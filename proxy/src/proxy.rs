use std::{net::SocketAddr, sync::Arc};

use colored::Colorize;
use imap_flow::{
    client::{ClientFlow, ClientFlowError, ClientFlowEvent, ClientFlowOptions},
    server::{ServerFlow, ServerFlowError, ServerFlowEvent, ServerFlowOptions},
    stream::Stream,
};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName},
    TlsConnector,
};
use tracing::{error, info, trace};

use crate::{
    config::Service,
    util::{self, ControlFlow},
};

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
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
        let bind_addr_port = format!("{}:{}", service.bind.host, service.bind.port);
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

        Ok(Proxy {
            service: self.service.clone(),
            state: ClientAcceptedState {
                client_addr,
                client_to_proxy: Stream::new(client_to_proxy),
            },
        })
    }
}

pub struct ClientAcceptedState {
    client_addr: SocketAddr,
    client_to_proxy: Stream,
}

impl State for ClientAcceptedState {}

impl Proxy<ClientAcceptedState> {
    pub fn client_addr(&self) -> SocketAddr {
        self.state.client_addr
    }

    pub async fn connect_to_server(self) -> Result<Proxy<ConnectedState>, ProxyError> {
        let server_addr = &self.service.connect.host;
        let server_port = &self.service.connect.port;
        let server_addr_port = format!("{server_addr}:{server_port}");

        info!(?server_addr_port, "Connecting to server");
        let proxy_to_server = match TcpStream::connect(&server_addr_port).await {
            Ok(stream_to_server) => {
                let mut root_cert_store = RootCertStore::empty();
                #[allow(deprecated)] // TODO: Fix deprecation warning
                root_cert_store.add_server_trust_anchors(
                    webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                        OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    }),
                );
                let config = ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_cert_store)
                    .with_no_client_auth();
                let connector = TlsConnector::from(Arc::new(config));
                let dnsname = ServerName::try_from(server_addr.as_str()).unwrap();

                info!(?server_addr_port, "Starting TLS with server");
                connector.connect(dnsname, stream_to_server).await.unwrap()
            }
            Err(err) => {
                error!(%err, "Failed to connect to server");
                return Err(err.into());
            }
        };
        info!(?server_addr_port, "Connected to server");

        Ok(Proxy {
            service: self.service,
            state: ConnectedState {
                client_to_proxy: self.state.client_to_proxy,
                proxy_to_server: Stream::new(proxy_to_server),
            },
        })
    }
}

pub struct ConnectedState {
    client_to_proxy: Stream,
    proxy_to_server: Stream,
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

        let mut client_to_proxy = {
            // TODO: Read options from config
            let options = ServerFlowOptions {
                crlf_relaxed: true,
                max_literal_size: u32::MAX,
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
        trace!(role = "p2c", "<--- Forwarded greeting");

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
            info!(role = "c2p", %error, ?discarded_bytes, "Discard client message");
            return ControlFlow::Continue;
        }
        Err(ServerFlowError::Io(error)) => {
            info!(role = "c2p", %error, "Connection terminated");
            return ControlFlow::Abort;
        }
    };

    match event {
        ServerFlowEvent::ResponseSent { handle: _handle } => {
            // TODO: log handle
            trace!(role = "p2c", "<--- Forwarded response");
        }
        ServerFlowEvent::CommandReceived { command } => {
            trace!(command=%format!("{:?}", command).red(), role = "c2p", "|--> Received command");
            let _handle = proxy_to_server.enqueue_command(command);
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
            info!(role = "c2p", %error, ?discarded_bytes, "Discard server message");
            return ControlFlow::Continue;
        }
        Err(ClientFlowError::Io(error)) => {
            info!(role = "s2p", %error, "Connection terminated");
            return ControlFlow::Abort;
        }
    };

    match event {
        ClientFlowEvent::CommandSent {
            tag,
            handle: _handle,
        } => {
            // TODO: log handle
            trace!(role = "p2s", ?tag, "---> Forwarded command");
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
    }

    ControlFlow::Continue
}
