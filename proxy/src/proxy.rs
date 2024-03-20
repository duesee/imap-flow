use std::{net::SocketAddr, sync::Arc};

use colored::Colorize;
use imap_flow::{
    client::{ClientFlow, ClientFlowError, ClientFlowEvent, ClientFlowOptions},
    server::{ServerFlow, ServerFlowError, ServerFlowEvent, ServerFlowOptions},
    stream::AnyStream,
};
use imap_types::{
    bounded_static::ToBoundedStatic,
    command::{Command, CommandBody},
    core::Text,
    extensions::idle::IdleDone,
    response::{Code, Status},
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

                    let mut config = rustls::ServerConfig::builder()
                        .with_safe_defaults()
                        .with_no_client_auth()
                        // Note: The name is misleading. We provide the full chain here.
                        .with_single_cert(certificate_chain, leaf_key)?;

                    config.alpn_protocols = vec![b"imap".to_vec()];

                    config
                };

                // TODO(#146): The acceptor should really be part of the proxy initialization.
                //             However, for testing purposes, it's nice to create it on-the-fly.
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
    pub async fn start_conversation(self) {
        let (mut proxy_to_server, mut greeting) = {
            // TODO(#144): Read options from config
            let options = ClientFlowOptions::default();

            let result = ClientFlow::receive_greeting(self.state.proxy_to_server, options).await;

            match result {
                Ok(value) => value,
                Err(error) => {
                    error!(?error, "Failed to receive greeting");
                    return;
                }
            }
        };
        trace!(role = "s2p", greeting=%format!("{:?}", greeting).blue(), "<--|");

        util::filter_capabilities_in_greeting(&mut greeting);

        let (mut client_to_proxy, _) = {
            // TODO(#144): Read options from config
            let mut options = ServerFlowOptions::default();
            options.literal_accept_text = Text::try_from(LITERAL_ACCEPT_TEXT).unwrap();
            options.literal_reject_text = Text::try_from(LITERAL_REJECT_TEXT).unwrap();

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
        trace!(role = "p2c", "<--- greeting");

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
            }
            | ServerFlowError::CommandTooLong {
                ref discarded_bytes,
            }),
        ) => {
            error!(role = "c2p", %error, ?discarded_bytes, "Discard client message");
            return ControlFlow::Continue;
        }
        Err(ServerFlowError::StreamClosed) => {
            error!(role = "c2p", "Stream closed");
            return ControlFlow::Abort;
        }
        Err(ServerFlowError::Io(error)) => {
            error!(role = "c2p", %error, "IO error");
            return ControlFlow::Abort;
        }
    };

    match event {
        ServerFlowEvent::ResponseSent { handle, .. } => {
            trace!(role = "p2c", ?handle, "<---");
        }
        ServerFlowEvent::CommandReceived { command } => {
            trace!(role = "c2p", command=%format!("{:?}", command).red(), "|-->");

            let handle = proxy_to_server.enqueue_command(command);
            trace!(role = "p2s", ?handle, "enqueue_command");
        }
        ServerFlowEvent::CommandAuthenticateReceived {
            command_authenticate,
        } => {
            let command_authenticate: Command<'static> = command_authenticate.into();

            trace!(role = "c2p", command_authenticate=%format!("{:?}", command_authenticate).red(), "|-->");

            let handle = proxy_to_server.enqueue_command(command_authenticate);
            trace!(role = "p2s", ?handle, "enqueue_command");
        }
        ServerFlowEvent::AuthenticateDataReceived { authenticate_data } => {
            trace!(role = "c2p", authenticate_data=%format!("{:?}", authenticate_data).red(), "|-->");

            // TODO(#145): Fix unwrap
            let handle = proxy_to_server
                .set_authenticate_data(authenticate_data)
                .unwrap();
            trace!(role = "p2s", ?handle, "set_authenticate_data");
        }
        ServerFlowEvent::IdleCommandReceived { tag } => {
            let idle = Command {
                tag,
                body: CommandBody::Idle,
            };

            trace!(role = "c2p", idle=%format!("{:?}", idle).red(), "|-->");

            let handle = proxy_to_server.enqueue_command(idle);
            trace!(role = "p2s", ?handle, "enqueue_command");
        }
        ServerFlowEvent::IdleDoneReceived => {
            trace!(role = "c2p", done=%format!("{:?}", IdleDone).red(), "|-->");

            let handle = proxy_to_server.set_idle_done();
            trace!(role = "p2s", ?handle, "set_idle_done");
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
        Err(ClientFlowError::StreamClosed) => {
            error!(role = "s2p", "Stream closed");
            return ControlFlow::Abort;
        }
        Err(ClientFlowError::Io(error)) => {
            error!(role = "s2p", %error, "IO error");
            return ControlFlow::Abort;
        }
    };

    match event {
        ClientFlowEvent::CommandSent { handle, .. } => {
            trace!(role = "p2s", ?handle, "--->");
        }
        ClientFlowEvent::CommandRejected {
            handle,
            command,
            status,
        } => {
            trace!(role = "s2p", ?handle, status=%format!("{:?}", status).blue(), "<--|");

            let modified_status = match status.code() {
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
            let handle = client_to_proxy.enqueue_status(modified_status.clone());
            trace!(role = "p2c", ?handle, modified_status=%format!("{:?}", modified_status).yellow(), "enqueue_status");
        }
        ClientFlowEvent::AuthenticateStarted { handle } => {
            trace!(role = "p2s", ?handle, "--->");
        }
        ClientFlowEvent::AuthenticateContinuationRequestReceived {
            continuation_request,
            ..
        } => {
            trace!(role = "s2p", authenticate_continuation_request=%format!("{:?}", continuation_request).blue(), "<--|");

            let handle = client_to_proxy
                .authenticate_continue(continuation_request)
                .unwrap();
            trace!(role = "p2c", ?handle, "authenticate_continue");
        }
        ClientFlowEvent::AuthenticateStatusReceived { status, .. } => {
            trace!(role = "s2p", authenticate_status=%format!("{:?}", status).blue(), "<--|");

            // TODO(#145): Fix unwrap
            let handle = client_to_proxy.authenticate_finish(status).unwrap();
            trace!(role = "p2c", ?handle, "authenticate_finish");
        }
        ClientFlowEvent::DataReceived { mut data } => {
            trace!(role = "s2p", data=%format!("{:?}", data).blue(), "<--|");

            util::filter_capabilities_in_data(&mut data);

            let handle = client_to_proxy.enqueue_data(data);
            trace!(role = "p2c", ?handle, "enqueue_data");
        }
        ClientFlowEvent::StatusReceived { mut status } => {
            trace!(role = "s2p", status=%format!("{:?}", status).blue(), "<--|");

            util::filter_capabilities_in_status(&mut status);

            let handle = client_to_proxy.enqueue_status(status);
            trace!(role = "p2c", ?handle, "enqueue_status");
        }
        ClientFlowEvent::ContinuationRequestReceived {
            mut continuation_request,
        } => {
            trace!(role = "s2p", continuation_request=%format!("{:?}", continuation_request).blue(), "<--|");

            util::filter_capabilities_in_continuation(&mut continuation_request);

            let handle = client_to_proxy.enqueue_continuation_request(continuation_request);
            trace!(role = "p2c", ?handle, "enqueue_continuation_request");
        }
        ClientFlowEvent::IdleCommandSent { handle } => {
            trace!(role = "p2s", ?handle, "--->");
        }
        ClientFlowEvent::IdleAccepted {
            handle,
            continuation_request,
        } => {
            trace!(
                role = "s2p",
                ?handle,
                idle_accepted_continuation_request=%format!("{:?}", continuation_request).blue(),
                "<--|"
            );

            // TODO(#145): Fix unwrap
            let handle = client_to_proxy.idle_accept(continuation_request).unwrap();
            trace!(role = "p2c", ?handle, "idle_accept");
        }
        ClientFlowEvent::IdleRejected { handle, status } => {
            trace!(role = "s2p", ?handle, idle_rejected_status=%format!("{:?}", status).blue(), "<--|");

            // TODO(#145): Fix unwrap
            let handle = client_to_proxy.idle_reject(status).unwrap();
            trace!(role = "p2c", ?handle, "idle_reject");
        }
        ClientFlowEvent::IdleDoneSent { handle } => {
            trace!(role = "p2c", ?handle, "--->");
        }
    }

    ControlFlow::Continue
}
