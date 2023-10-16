use bytes::BytesMut;
use imap_codec::{
    decode::CommandDecodeError,
    imap_types::{
        command::Command,
        response::{CommandContinuationRequest, Data, Greeting, Response, Status},
    },
    CommandCodec, GreetingCodec, ResponseCodec,
};
use thiserror::Error;

use crate::{
    receive::{ReceiveEvent, ReceiveState},
    send::SendResponseState,
    stream::Stream,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ServerFlowOptions {
    pub crlf_relaxed: bool,
    pub max_literal_size: u32,
}

impl Default for ServerFlowOptions {
    fn default() -> Self {
        Self {
            // Lean towards usability
            crlf_relaxed: true,
            // 25 MiB is a common maximum email size (Oct. 2023)
            max_literal_size: 25 * 1024 * 1024,
        }
    }
}

pub struct ServerFlow {
    stream: Stream,
    max_literal_size: u32,

    next_response_handle: ServerFlowResponseHandle,
    send_response_state: SendResponseState<ResponseCodec, Option<ServerFlowResponseHandle>>,
    receive_command_state: ReceiveState<CommandCodec>,
}

impl ServerFlow {
    pub async fn send_greeting(
        mut stream: Stream,
        options: ServerFlowOptions,
        greeting: Greeting<'_>,
    ) -> Result<Self, ServerFlowError> {
        // Send greeting
        let write_buffer = BytesMut::new();
        let mut send_greeting_state =
            SendResponseState::new(GreetingCodec::default(), write_buffer);
        send_greeting_state.enqueue((), greeting);
        while let Some(()) = send_greeting_state.progress(&mut stream).await? {}

        // Successfully sent greeting, construct instance
        let write_buffer = send_greeting_state.finish();
        let send_response_state = SendResponseState::new(ResponseCodec::default(), write_buffer);
        let read_buffer = BytesMut::new();
        let receive_command_state =
            ReceiveState::new(CommandCodec::default(), options.crlf_relaxed, read_buffer);
        let server_flow = Self {
            stream,
            max_literal_size: options.max_literal_size,
            next_response_handle: ServerFlowResponseHandle(0),
            send_response_state,
            receive_command_state,
        };

        Ok(server_flow)
    }

    pub fn stream(&self) -> &Stream {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }

    pub fn enqueue_data(&mut self, data: Data<'_>) -> ServerFlowResponseHandle {
        let handle = self.next_response_handle();
        self.send_response_state
            .enqueue(Some(handle), Response::Data(data));
        handle
    }

    pub fn enqueue_status(&mut self, status: Status<'_>) -> ServerFlowResponseHandle {
        let handle = self.next_response_handle();
        self.send_response_state
            .enqueue(Some(handle), Response::Status(status));
        handle
    }

    fn next_response_handle(&mut self) -> ServerFlowResponseHandle {
        let handle = self.next_response_handle;
        self.next_response_handle = ServerFlowResponseHandle(handle.0 + 1);
        handle
    }

    pub async fn progress(&mut self) -> Result<ServerFlowEvent, ServerFlowError> {
        loop {
            if let Some(event) = self.progress_response().await? {
                return Ok(event);
            }

            if let Some(event) = self.progress_command().await? {
                return Ok(event);
            }
        }
    }

    async fn progress_response(&mut self) -> Result<Option<ServerFlowEvent>, ServerFlowError> {
        match self.send_response_state.progress(&mut self.stream).await? {
            Some(Some(handle)) => Ok(Some(ServerFlowEvent::ResponseSent { handle })),
            _ => Ok(None),
        }
    }

    async fn progress_command(&mut self) -> Result<Option<ServerFlowEvent>, ServerFlowError> {
        match self
            .receive_command_state
            .progress(&mut self.stream)
            .await?
        {
            ReceiveEvent::DecodingSuccess(command) => {
                self.receive_command_state.finish_message();
                Ok(Some(ServerFlowEvent::CommandReceived { command }))
            }
            ReceiveEvent::DecodingFailure(CommandDecodeError::LiteralFound {
                tag,
                length,
                mode: _mode,
            }) => {
                if length > self.max_literal_size {
                    let discarded_bytes = self.receive_command_state.discard_message();

                    // Inform the client that the literal was rejected.
                    // This should never fail because the text is not Base64.
                    let status = Status::no(Some(tag), None, "Computer says no").unwrap();
                    self.send_response_state
                        .enqueue(None, Response::Status(status));

                    Err(ServerFlowError::LiteralTooLong { discarded_bytes })
                } else {
                    self.receive_command_state.start_literal(length);

                    // Inform the client that the literal was accepted.
                    // This should never fail because the text is not Base64.
                    let cont = CommandContinuationRequest::basic(None, "Please, continue").unwrap();
                    self.send_response_state
                        .enqueue(None, Response::CommandContinuationRequest(cont));

                    Ok(None)
                }
            }
            ReceiveEvent::DecodingFailure(
                CommandDecodeError::Failed | CommandDecodeError::Incomplete,
            ) => {
                let discarded_bytes = self.receive_command_state.discard_message();
                Err(ServerFlowError::MalformedMessage { discarded_bytes })
            }
            ReceiveEvent::ExpectedCrlfGotLf => {
                let discarded_bytes = self.receive_command_state.discard_message();
                Err(ServerFlowError::ExpectedCrlfGotLf { discarded_bytes })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ServerFlowResponseHandle(u64);

#[derive(Debug)]
pub enum ServerFlowEvent {
    ResponseSent { handle: ServerFlowResponseHandle },
    CommandReceived { command: Command<'static> },
}

#[derive(Debug, Error)]
pub enum ServerFlowError {
    #[error(transparent)]
    Io(#[from] tokio::io::Error),
    #[error("Expected `\\r\\n`, got `\\n`")]
    ExpectedCrlfGotLf { discarded_bytes: Box<[u8]> },
    #[error("Received malformed message")]
    MalformedMessage { discarded_bytes: Box<[u8]> },
    #[error("Literal was rejected because it was too long")]
    LiteralTooLong { discarded_bytes: Box<[u8]> },
}
