use bounded_static::ToBoundedStatic;
use bytes::BytesMut;
use imap_codec::{
    decode::{GreetingDecodeError, ResponseDecodeError},
    imap_types::{
        command::Command,
        core::Tag,
        response::{Data, Greeting, Response, Status},
    },
    CommandCodec, GreetingCodec, ResponseCodec,
};
use thiserror::Error;

use crate::{
    receive::{ReceiveEvent, ReceiveState},
    send::SendCommandState,
    stream::Stream,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClientFlowOptions {
    pub crlf_relaxed: bool,
}

impl Default for ClientFlowOptions {
    fn default() -> Self {
        Self {
            // Lean towards usability
            crlf_relaxed: true,
        }
    }
}

pub struct ClientFlow {
    stream: Stream,

    next_command_handle: ClientFlowCommandHandle,
    send_command_state: SendCommandState<(Tag<'static>, ClientFlowCommandHandle)>,
    receive_response_state: ReceiveState<ResponseCodec>,
}

impl ClientFlow {
    pub async fn receive_greeting(
        mut stream: Stream,
        options: ClientFlowOptions,
    ) -> Result<(Self, Greeting<'static>), ClientFlowError> {
        // Receive greeting
        let read_buffer = BytesMut::new();
        let mut receive_greeting_state =
            ReceiveState::new(GreetingCodec::default(), options.crlf_relaxed, read_buffer);
        let greeting = match receive_greeting_state.progress(&mut stream).await? {
            ReceiveEvent::DecodingSuccess(greeting) => {
                receive_greeting_state.finish_message();
                greeting
            }
            ReceiveEvent::DecodingFailure(
                GreetingDecodeError::Failed | GreetingDecodeError::Incomplete,
            ) => {
                let discarded_bytes = receive_greeting_state.discard_message();
                return Err(ClientFlowError::MalformedMessage { discarded_bytes });
            }
            ReceiveEvent::ExpectedCrlfGotLf => {
                let discarded_bytes = receive_greeting_state.discard_message();
                return Err(ClientFlowError::ExpectedCrlfGotLf { discarded_bytes });
            }
        };

        // Successfully received greeting, create instance.
        let write_buffer = BytesMut::new();
        let send_command_state = SendCommandState::new(CommandCodec::default(), write_buffer);
        let read_buffer = receive_greeting_state.finish();
        let receive_response_state =
            ReceiveState::new(ResponseCodec::new(), options.crlf_relaxed, read_buffer);
        let client_flow = Self {
            stream,
            next_command_handle: ClientFlowCommandHandle(0),
            send_command_state,
            receive_response_state,
        };

        Ok((client_flow, greeting))
    }

    pub fn stream(&self) -> &Stream {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }

    pub fn enqueue_command(&mut self, command: Command<'_>) -> ClientFlowCommandHandle {
        let handle = self.next_command_handle;
        self.next_command_handle = ClientFlowCommandHandle(handle.0 + 1);
        let tag = command.tag.to_static();
        self.send_command_state.enqueue((tag, handle), command);
        handle
    }

    pub async fn progress(&mut self) -> Result<ClientFlowEvent, ClientFlowError> {
        loop {
            if let Some(event) = self.progress_command().await? {
                return Ok(event);
            }

            if let Some(event) = self.progress_response().await? {
                return Ok(event);
            }
        }
    }

    async fn progress_command(&mut self) -> Result<Option<ClientFlowEvent>, ClientFlowError> {
        match self.send_command_state.progress(&mut self.stream).await? {
            Some((tag, handle)) => Ok(Some(ClientFlowEvent::CommandSent { tag, handle })),
            None => Ok(None),
        }
    }

    async fn progress_response(&mut self) -> Result<Option<ClientFlowEvent>, ClientFlowError> {
        let event = loop {
            let response = match self
                .receive_response_state
                .progress(&mut self.stream)
                .await?
            {
                ReceiveEvent::DecodingSuccess(response) => {
                    self.receive_response_state.finish_message();
                    response
                }
                ReceiveEvent::DecodingFailure(ResponseDecodeError::LiteralFound { length }) => {
                    // The client must accept the literal in any case.
                    self.receive_response_state.start_literal(length);
                    continue;
                }
                ReceiveEvent::DecodingFailure(
                    ResponseDecodeError::Failed | ResponseDecodeError::Incomplete,
                ) => {
                    let discarded_bytes = self.receive_response_state.discard_message();
                    return Err(ClientFlowError::MalformedMessage { discarded_bytes });
                }
                ReceiveEvent::ExpectedCrlfGotLf => {
                    let discarded_bytes = self.receive_response_state.discard_message();
                    return Err(ClientFlowError::ExpectedCrlfGotLf { discarded_bytes });
                }
            };

            match response {
                Response::Status(status) => {
                    self.maybe_abort_command(&status);
                    break Some(ClientFlowEvent::StatusReceived { status });
                }
                Response::Data(data) => break Some(ClientFlowEvent::DataReceived { data }),
                Response::CommandContinuationRequest(_) => {
                    self.send_command_state.continue_command();
                    break None;
                }
            }
        };

        Ok(event)
    }

    fn maybe_abort_command(&mut self, status: &Status) {
        let Some((command_tag, _)) = self.send_command_state.command_in_progress() else {
            return;
        };

        match status {
            Status::Bad {
                tag: Some(status_tag),
                ..
            } if status_tag == command_tag => {
                self.send_command_state.abort_command();
            }
            _ => (),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ClientFlowCommandHandle(u64);

#[derive(Debug)]
pub enum ClientFlowEvent {
    CommandSent {
        tag: Tag<'static>,
        handle: ClientFlowCommandHandle,
    },
    DataReceived {
        data: Data<'static>,
    },
    StatusReceived {
        status: Status<'static>,
    },
}

#[derive(Debug, Error)]
pub enum ClientFlowError {
    #[error(transparent)]
    Io(#[from] tokio::io::Error),
    #[error("Expected `\\r\\n`, got `\\n`")]
    ExpectedCrlfGotLf { discarded_bytes: Box<[u8]> },
    #[error("Received malformed message")]
    MalformedMessage { discarded_bytes: Box<[u8]> },
}
