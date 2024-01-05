use std::{net::SocketAddr, sync::Arc};

use colored::Colorize;
use imap_codec::imap_types::{
    bounded_static::ToBoundedStatic,
    command::{Command, CommandBody},
    core::Text,
    response::{Code, Status},
};
use imap_flow::{
    client::{ClientFlow, ClientFlowError, ClientFlowEvent, ClientFlowOptions},
    server::{ServerFlow, ServerFlowError, ServerFlowEvent, ServerFlowOptions},
    stream::AnyStream,
};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName},
    TlsAcceptor, TlsConnector,
};
use tracing::{error, info, trace};

use crate::{
    config::{Bind, Connect, Identity, Service},
    util::{self, ControlFlow, IdentityError},
};

const LITERAL_ACCEPT_TEXT: &str = "proxy: Literal accepted by proxy";
const LITERAL_REJECT_TEXT: &str = "proxy: Literal rejected by proxy";
const COMMAND_REJECTED_TEXT: &str = "proxy: Command rejected by server";

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Tls(#[from] rustls::Error),
}

pub trait State: Send + 'static {}

pub struct Proxy<S: State> {
    service: Service,
    state: S,
}

pub struct BoundState {
    listener: TcpListener,
}

impl State for BoundState {}

impl Proxy<BoundState> {
    pub async fn bind(service: Service) -> Result<Self, ProxyError> {
        // Accept arbitrary number of connections.
        let bind_addr_port = service.bind.addr_port();
        let listener = TcpListener::bind(&bind_addr_port).await?;
        info!(?bind_addr_port, "Bound to");

        Ok(Self {
            service,
            state: BoundState { listener },
        })
    }

    pub async fn accept_client(&self) -> Result<Proxy<ClientAcceptedState>, ProxyError> {
        let (client_to_proxy, client_addr) = self.state.listener.accept().await?;
        info!(?client_addr, "Accepted client");

        let client_to_proxy = match &self.service.bind {
            Bind::Tls { identity, .. } => {
                let config = {
                    let (certificate_chain, leaf_key) = match identity {
                        Identity::CertificateChainAndLeafKey {
                            certificate_chain_path,
                            leaf_key_path,
                        } => {
                            let certificate_chain =
                                util::load_certificate_chain_pem(certificate_chain_path)?;
                            let leaf_key = util::load_leaf_key_pem(leaf_key_path)?;

                            (certificate_chain, leaf_key)
                        }
                    };

                    rustls::ServerConfig::builder()
                        .with_safe_defaults()
                        .with_no_client_auth()
                        // Note: The name is misleading. We provide the full chain here.
                        .with_single_cert(certificate_chain, leaf_key)?
                };

                // TODO: The acceptor should really be part of the proxy initialization.
                //       However, for testing purposes, it's nice to create it on-the-fly.
                let acceptor = TlsAcceptor::from(Arc::new(config));

                AnyStream::new(acceptor.accept(client_to_proxy).await?)
            }
            Bind::Insecure { .. } => AnyStream::new(client_to_proxy),
        };

        Ok(Proxy {
            service: self.service.clone(),
            state: ClientAcceptedState {
                client_addr,
                client_to_proxy,
            },
        })
    }
}

pub struct ClientAcceptedState {
    client_addr: SocketAddr,
    client_to_proxy: AnyStream,
}

impl State for ClientAcceptedState {}

impl Proxy<ClientAcceptedState> {
    pub fn client_addr(&self) -> SocketAddr {
        self.state.client_addr
    }

    pub async fn connect_to_server(self) -> Result<Proxy<ConnectedState>, ProxyError> {
        let server_addr_port = self.service.connect.addr_port();
        info!(%server_addr_port, "Connecting to server");
        let stream_to_server = TcpStream::connect(&server_addr_port).await?;

        let proxy_to_server = match self.service.connect {
            Connect::Tls { ref host, .. } => {
                let config = {
                    let root_store = {
                        let mut root_store = RootCertStore::empty();

                        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(
                            |ta| {
                                OwnedTrustAnchor::from_subject_spki_name_constraints(
                                    ta.subject,
                                    ta.spki,
                                    ta.name_constraints,
                                )
                            },
                        ));

                        root_store
                    };

                    let mut config = ClientConfig::builder()
                        .with_safe_defaults()
                        .with_root_certificates(root_store)
                        .with_no_client_auth();

                    // See <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>
                    config.alpn_protocols = vec![b"imap".to_vec()];

                    config
                };

                let connector = TlsConnector::from(Arc::new(config));
                let dnsname = ServerName::try_from(host.as_str()).unwrap();

                info!(?server_addr_port, "Starting TLS with server");
                AnyStream::new(connector.connect(dnsname, stream_to_server).await.unwrap())
            }
            Connect::Insecure { .. } => AnyStream::new(stream_to_server),
        };

        info!(?server_addr_port, "Connected to server");

        Ok(Proxy {
            service: self.service,
            state: ConnectedState {
                client_to_proxy: self.state.client_to_proxy,
                proxy_to_server,
            },
        })
    }
}

pub struct ConnectedState {
    client_to_proxy: AnyStream,
    proxy_to_server: AnyStream,
}

impl State for ConnectedState {}

impl Proxy<ConnectedState> {
    pub async fn start_conversion(self) {
        let (mut proxy_to_server, mut greeting) = {
            // TODO: Read options from config
            let options = ClientFlowOptions { crlf_relaxed: true };

            let result = ClientFlow::receive_greeting(self.state.proxy_to_server, options).await;

            match result {
                Ok(value) => value,
                Err(error) => {
                    error!(?error, "Failed to receive greeting");
                    return;
                }
            }
        };
        trace!(greeting=%format!("{:?}", greeting).blue(), role = "s2p", "<--| Received greeting");

        util::filter_capabilities_in_greeting(&mut greeting);

        let (mut client_to_proxy, greeting) = {
            // TODO: Read options from config
            let options = ServerFlowOptions {
                literal_accept_text: Text::try_from(LITERAL_ACCEPT_TEXT).unwrap(),
                literal_reject_text: Text::try_from(LITERAL_REJECT_TEXT).unwrap(),
                ..Default::default()
            };

            let result =
                ServerFlow::send_greeting(self.state.client_to_proxy, options, greeting).await;

            match result {
                Ok(value) => value,
                Err(error) => {
                    error!(?error, "Failed to forward greeting");
                    return;
                }
            }
        };
        trace!(role = "p2c", ?greeting, "<--- Forwarded greeting");

        loop {
            let control_flow = tokio::select! {
                event = client_to_proxy.progress() => {
                    handle_client_event(event, &mut proxy_to_server)
                }
                event = proxy_to_server.progress() => {
                    handle_server_event(event, &mut client_to_proxy)
                }
            };

            if let ControlFlow::Abort = control_flow {
                break;
            }
        }
    }
}

fn handle_client_event(
    error: Result<ServerFlowEvent, ServerFlowError>,
    proxy_to_server: &mut ClientFlow,
) -> ControlFlow {
    let event = match error {
        Ok(event) => event,
        Err(
            ref error @ (ServerFlowError::ExpectedCrlfGotLf {
                ref discarded_bytes,
            }
            | ServerFlowError::MalformedMessage {
                ref discarded_bytes,
            }
            | ServerFlowError::LiteralTooLong {
                ref discarded_bytes,
            }),
        ) => {
            error!(role = "c2p", %error, ?discarded_bytes, "Discard client message");
            return ControlFlow::Continue;
        }
        Err(ServerFlowError::Stream(error)) => {
            error!(role = "c2p", %error, "Connection terminated");
            return ControlFlow::Abort;
        }
    };

    match event {
        ServerFlowEvent::ResponseSent {
            handle: _handle,
            response,
        } => {
            // TODO: log handle
            trace!(role = "p2c", ?response, "<--- Forwarded response");
        }
        ServerFlowEvent::CommandReceived { command } => {
            trace!(command=%format!("{:?}", command).red(), role = "c2p", "|--> Received command");
            let _handle = proxy_to_server.enqueue_command(command);
            // TODO: log handle
        }
        ServerFlowEvent::CommandAuthenticateReceived {
            command_authenticate,
        } => {
            let command = Command {
                tag: command_authenticate.tag,
                body: CommandBody::Authenticate {
                    mechanism: command_authenticate.mechanism,
                    initial_response: command_authenticate.initial_response,
                },
            };

            trace!(command=%format!("{:?}", command).red(), role = "c2p", "|--> Received command (authenticate)");
            let _handle = proxy_to_server.enqueue_command(command);
            // TODO: log handle
        }
        ServerFlowEvent::AuthenticateDataReceived { authenticate_data } => {
            trace!(authenticate_data=%format!("{:?}", authenticate_data).red(), role = "c2p", "|--> Received authenticate_data");
            // TODO: unwrap
            let _handle = proxy_to_server
                .authenticate_continue(authenticate_data)
                .unwrap();
            // TODO: log handle
        }
    }

    ControlFlow::Continue
}

fn handle_server_event(
    event: Result<ClientFlowEvent, ClientFlowError>,
    client_to_proxy: &mut ServerFlow,
) -> ControlFlow {
    let event = match event {
        Ok(event) => event,
        Err(
            ref error @ (ClientFlowError::ExpectedCrlfGotLf {
                ref discarded_bytes,
            }
            | ClientFlowError::MalformedMessage {
                ref discarded_bytes,
            }),
        ) => {
            error!(role = "c2p", %error, ?discarded_bytes, "Discard server message");
            return ControlFlow::Continue;
        }
        Err(ClientFlowError::Stream(error)) => {
            error!(role = "s2p", %error, "Connection terminated");
            return ControlFlow::Abort;
        }
    };

    match event {
        ClientFlowEvent::CommandSent {
            handle: _handle,
            command,
        } => {
            // TODO: log handle
            trace!(role = "p2s", ?command, "---> Forwarded command");
        }
        ClientFlowEvent::CommandRejected {
            handle: _handle,
            command,
            status,
        } => {
            // TODO: log handle
            trace!(role = "p2s", ?command, ?status, "---> Aborted command");
            let status = match status.code() {
                Some(Code::Alert) => {
                    // Keep the alert message because it MUST be displayed to the user
                    Status::bad(
                        Some(command.tag),
                        Some(Code::Alert),
                        status.text().to_static(),
                    )
                    .unwrap()
                }
                _ => {
                    // Use generic message because the original code and text might be misleading
                    Status::bad(Some(command.tag), None, COMMAND_REJECTED_TEXT).unwrap()
                }
            };
            let _handle = client_to_proxy.enqueue_status(status);
            // TODO: log handle
        }
        ClientFlowEvent::AuthenticateStarted { handle: _handle } => {
            // TODO: log handle
            trace!(role = "p2s", "---> Authentication started");
        }
        ClientFlowEvent::ContinuationAuthenticateReceived { continuation, .. } => {
            trace!(response=%format!("{:?}", continuation).blue(), role = "s2p", "<--| Received authentication continue");
            client_to_proxy.authenticate_continue(continuation).unwrap();
        }
        ClientFlowEvent::AuthenticateAccepted { status, .. } => {
            trace!(response=%format!("{:?}", status).blue(), role = "s2p", "<--| Received authentication accepted");
            // TODO: Fix unwrap
            client_to_proxy.authenticate_finish(status).unwrap();
        }
        ClientFlowEvent::AuthenticateRejected { status, .. } => {
            trace!(response=%format!("{:?}", status).blue(), role = "s2p", "<--| Received authentication rejected");
            // TODO: Fix unwrap
            client_to_proxy.authenticate_finish(status).unwrap();
        }
        ClientFlowEvent::DataReceived { mut data } => {
            trace!(data=%format!("{:?}", data).blue(), role = "s2p", "<--| Received data");
            util::filter_capabilities_in_data(&mut data);
            let _handle = client_to_proxy.enqueue_data(data);
            // TODO: log handle
        }
        ClientFlowEvent::StatusReceived { mut status } => {
            trace!(response=%format!("{:?}", status).blue(), role = "s2p", "<--| Received status");
            util::filter_capabilities_in_status(&mut status);
            let _handle = client_to_proxy.enqueue_status(status);
            // TODO: log handle
        }
        ClientFlowEvent::ContinuationReceived { mut continuation } => {
            trace!(response=%format!("{:?}", continuation).blue(), role = "s2p", "<--| Received continuation");
            util::filter_capabilities_in_continuation(&mut continuation);
            let _handle = client_to_proxy.enqueue_continuation(continuation);
            // TODO: log handle
        }
    }

    ControlFlow::Continue
}
