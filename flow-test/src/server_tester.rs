use bstr::ByteSlice;
use imap_flow::{
    server::{ServerFlow, ServerFlowError, ServerFlowEvent, ServerFlowOptions},
    stream::AnyStream,
};
use imap_types::{bounded_static::ToBoundedStatic, response::Response};
use tokio::net::{TcpListener, TcpStream};
use tracing::trace;

use crate::codecs::Codecs;

/// A wrapper for `ServerFlow` suitable for testing.
pub struct ServerTester {
    codecs: Codecs,
    server_flow_options: ServerFlowOptions,
    connection_state: ConnectionState,
}

impl ServerTester {
    pub async fn new(
        codecs: Codecs,
        server_flow_options: ServerFlowOptions,
        server_listener: TcpListener,
    ) -> Self {
        let (stream, client_address) = server_listener.accept().await.unwrap();
        trace!(?client_address, "Server accepts connection");
        Self {
            codecs,
            server_flow_options,
            connection_state: ConnectionState::Connected { stream },
        }
    }

    pub async fn send_greeting(&mut self, bytes: &[u8]) {
        let enqueued_greeting = self.codecs.decode_greeting_normalized(bytes);
        match self.connection_state.take() {
            ConnectionState::Connected { stream } => {
                let stream = AnyStream::new(stream);
                let (server, greeting) = ServerFlow::send_greeting(
                    stream,
                    self.server_flow_options.clone(),
                    enqueued_greeting.to_static(),
                )
                .await
                .unwrap();
                assert_eq!(enqueued_greeting, greeting);
                self.connection_state = ConnectionState::Greeted { server };
            }
            ConnectionState::Greeted { .. } => {
                panic!("Server has already greeted");
            }
            ConnectionState::Disconnected => {
                panic!("Server is already disconnected");
            }
        }
    }

    pub async fn receive_command(&mut self, expected_bytes: &[u8]) {
        let expected_command = self.codecs.decode_command(expected_bytes);
        let server = self.connection_state.greeted();
        match server.progress().await.unwrap() {
            ServerFlowEvent::CommandReceived { command } => {
                assert_eq!(expected_command, command);
            }
            event => {
                panic!("Server emitted unexpected event: {event:?}");
            }
        }
    }

    pub async fn send_data(&mut self, bytes: &[u8]) {
        let enqueued_data = self.codecs.decode_data_normalized(bytes);
        let server = self.connection_state.greeted();
        let enqueued_handle = server.enqueue_data(enqueued_data.to_static());
        let event = server.progress().await.unwrap();
        match event {
            ServerFlowEvent::ResponseSent { handle, response } => {
                assert_eq!(enqueued_handle, handle);
                assert_eq!(Response::Data(enqueued_data), response);
            }
            event => {
                panic!("Server has unexpected event: {event:?}");
            }
        }
    }

    pub async fn send_status(&mut self, bytes: &[u8]) {
        let enqueued_status = self.codecs.decode_status_normalized(bytes);
        let server = self.connection_state.greeted();
        let enqueued_handle = server.enqueue_status(enqueued_status.to_static());
        let event = server.progress().await.unwrap();
        match event {
            ServerFlowEvent::ResponseSent { handle, response } => {
                assert_eq!(enqueued_handle, handle);
                assert_eq!(Response::Status(enqueued_status), response);
            }
            event => {
                panic!("Server has unexpected event: {event:?}");
            }
        }
    }

    pub async fn receive_error_because_expected_crlf_got_lf(&mut self, expected_bytes: &[u8]) {
        let server = self.connection_state.greeted();
        let error = server.progress().await.unwrap_err();
        match error {
            ServerFlowError::ExpectedCrlfGotLf { discarded_bytes } => {
                assert_eq!(
                    expected_bytes.as_bstr(),
                    discarded_bytes.declassify().as_bstr()
                );
            }
            error => {
                panic!("Server has unexpected error: {error:?}");
            }
        }
    }

    pub async fn receive_error_because_malformed_message(&mut self, expected_bytes: &[u8]) {
        let server = self.connection_state.greeted();
        let error = server.progress().await.unwrap_err();
        match error {
            ServerFlowError::MalformedMessage { discarded_bytes } => {
                assert_eq!(
                    expected_bytes.as_bstr(),
                    discarded_bytes.declassify().as_bstr()
                );
            }
            error => {
                panic!("Server has unexpected error: {error:?}");
            }
        }
    }

    pub async fn receive_error_because_literal_too_long(&mut self, expected_bytes: &[u8]) {
        let server = self.connection_state.greeted();
        let error = server.progress().await.unwrap_err();
        match error {
            ServerFlowError::LiteralTooLong { discarded_bytes } => {
                assert_eq!(
                    expected_bytes.as_bstr(),
                    discarded_bytes.declassify().as_bstr()
                );
            }
            error => {
                panic!("Server has unexpected error: {error:?}");
            }
        }
    }

    pub async fn receive_error_because_command_too_long(&mut self, expected_bytes: &[u8]) {
        let server = self.connection_state.greeted();
        let error = server.progress().await.unwrap_err();
        match error {
            ServerFlowError::CommandTooLong { discarded_bytes } => {
                assert_eq!(
                    expected_bytes.as_bstr(),
                    discarded_bytes.declassify().as_bstr()
                );
            }
            error => {
                panic!("Server has unexpected error: {error:?}");
            }
        }
    }

    /// Progresses internal responses without expecting any results.
    pub async fn progress_internal_responses<T>(&mut self) -> T {
        let server = self.connection_state.greeted();
        let result = server.progress().await;
        panic!("Server has unexpected result: {result:?}");
    }
}

/// The current state of the connection between server and client.
#[allow(clippy::large_enum_variant)]
enum ConnectionState {
    // The server has established a TCP connection to the client.
    Connected { stream: TcpStream },
    // The server has greeted the client.
    Greeted { server: ServerFlow },
    // The TCP connection between server and client was dropped.
    Disconnected,
}

impl ConnectionState {
    /// Assumes that the server has already greeted the client and returns the `ServerFlow`.
    fn greeted(&mut self) -> &mut ServerFlow {
        match self {
            ConnectionState::Connected { .. } => {
                panic!("Server has not greeted yet");
            }
            ConnectionState::Greeted { server } => server,
            ConnectionState::Disconnected => {
                panic!("Server is already disconnected");
            }
        }
    }

    fn take(&mut self) -> ConnectionState {
        std::mem::replace(self, ConnectionState::Disconnected)
    }
}
