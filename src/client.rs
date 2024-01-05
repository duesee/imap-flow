use std::fmt::Debug;

use bytes::BytesMut;
use imap_codec::{
    decode::{GreetingDecodeError, ResponseDecodeError},
    imap_types::{
        auth::AuthenticateData,
        command::Command,
        response::{
            CommandContinuationRequest, Data, Greeting, Response, Status, StatusBody, StatusKind,
            Tagged,
        },
    },
    AuthenticateDataCodec, CommandCodec, GreetingCodec, ResponseCodec,
};
use thiserror::Error;

use crate::{
    handle::{Handle, HandleGenerator, HandleGeneratorGenerator, RawHandle},
    receive::{ReceiveEvent, ReceiveState},
    send::{SendCommandEvent, SendCommandKind, SendCommandState},
    stream::{AnyStream, StreamError},
    types::CommandAuthenticate,
};

static HANDLE_GENERATOR_GENERATOR: HandleGeneratorGenerator<ClientFlowCommandHandle> =
    HandleGeneratorGenerator::new();

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

#[derive(Debug)]
pub struct ClientFlow {
    stream: AnyStream,

    handle_generator: HandleGenerator<ClientFlowCommandHandle>,
    send_command_state: SendCommandState<ClientFlowCommandHandle>,
    receive_response_state: ReceiveState<ResponseCodec>,
}

impl ClientFlow {
    pub async fn receive_greeting(
        mut stream: AnyStream,
        options: ClientFlowOptions,
    ) -> Result<(Self, Greeting<'static>), ClientFlowError> {
        // Receive greeting.
        let mut receive_greeting_state = ReceiveState::new(
            GreetingCodec::default(),
            options.crlf_relaxed,
            BytesMut::new(),
        );

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

        // Create state to send commands ...
        let send_command_state = SendCommandState::new(
            CommandCodec::default(),
            AuthenticateDataCodec::default(),
            BytesMut::new(),
        );

        // ..., and state to receive responses.
        let receive_response_state = receive_greeting_state.change_codec(ResponseCodec::new());

        let client_flow = Self {
            stream,
            handle_generator: HANDLE_GENERATOR_GENERATOR.generate(),
            send_command_state,
            receive_response_state,
        };

        Ok((client_flow, greeting))
    }

    /// Enqueues the [`Command`] for being sent to the client.
    ///
    /// The [`Command`] is not sent immediately but during one of the next calls of
    /// [`ClientFlow::progress`]. All [`Command`]s are sent in the same order they have been
    /// enqueued.
    pub fn enqueue_command(&mut self, command: Command<'static>) -> ClientFlowCommandHandle {
        let handle = self.handle_generator.generate();
        self.send_command_state.enqueue(handle, command);
        handle
    }

    pub async fn progress(&mut self) -> Result<ClientFlowEvent, ClientFlowError> {
        // The client must do two things:
        // - Sending commands to the server.
        // - Receiving responses from the server.
        //
        // There are two ways to accomplish that:
        // - Doing both in parallel.
        // - Doing both consecutively.
        //
        // Doing both in parallel is more complicated because both operations share the same
        // state and the borrow checker prevents the naive approach. We would need to introduce
        // interior mutability.
        //
        // Doing both consecutively is easier. But in which order? Receiving responses will block
        // indefinitely because we never know when the server is sending the next response.
        // Sending commands will be completed in the foreseeable future because for practical
        // purposes we can assume that the number of commands is finite and the stream will be
        // able to transfer all bytes soon.
        //
        // Therefore we prefer the second approach and begin with sending the commands.
        loop {
            if let Some(event) = self.progress_send().await? {
                return Ok(event);
            }

            if let Some(event) = self.progress_receive().await? {
                return Ok(event);
            }
        }
    }

    async fn progress_send(&mut self) -> Result<Option<ClientFlowEvent>, ClientFlowError> {
        match self.send_command_state.progress(&mut self.stream).await? {
            Some(SendCommandEvent::CommandSent {
                key: handle,
                command,
            }) => Ok(Some(ClientFlowEvent::CommandSent { handle, command })),
            Some(SendCommandEvent::CommandAuthenticateStarted { key: handle }) => {
                Ok(Some(ClientFlowEvent::AuthenticateStarted { handle }))
            }
            None => Ok(None),
        }
    }

    async fn progress_receive(&mut self) -> Result<Option<ClientFlowEvent>, ClientFlowError> {
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
                    let event = if let Some(finish_result) = self.maybe_finish_command(&status) {
                        match finish_result {
                            FinishCommandResult::LiteralRejected { handle, command } => {
                                ClientFlowEvent::CommandRejected {
                                    handle,
                                    command,
                                    status,
                                }
                            }
                            FinishCommandResult::AuthenticationAccepted {
                                handle,
                                command_authenticate,
                            } => ClientFlowEvent::AuthenticateAccepted {
                                handle,
                                command_authenticate,
                                status,
                            },
                            FinishCommandResult::AuthenticationRejected {
                                handle,
                                command_authenticate,
                            } => ClientFlowEvent::AuthenticateRejected {
                                handle,
                                command_authenticate,
                                status,
                            },
                        }
                    } else {
                        ClientFlowEvent::StatusReceived { status }
                    };

                    break Some(event);
                }
                Response::Data(data) => break Some(ClientFlowEvent::DataReceived { data }),
                Response::CommandContinuationRequest(continuation) => {
                    if self.send_command_state.continue_literal() {
                        // We received a continuation that was necessary for sending a command.
                        // So we abort receiving responses for now and continue with sending commands.
                        break None;
                    } else if let Some(&handle) = self.send_command_state.continue_authenticate() {
                        break Some(ClientFlowEvent::ContinuationAuthenticateReceived {
                            handle,
                            continuation,
                        });
                    } else {
                        break Some(ClientFlowEvent::ContinuationReceived { continuation });
                    }
                }
            }
        };

        Ok(event)
    }

    fn maybe_finish_command(&mut self, status: &Status) -> Option<FinishCommandResult> {
        let command_kind = self.send_command_state.command_in_progress()?;

        match command_kind {
            SendCommandKind::Regular { command } => {
                let removed_command = match status {
                    Status::Tagged(Tagged {
                        tag,
                        body: StatusBody { kind, .. },
                        ..
                    }) if *kind == StatusKind::Bad && tag == &command.tag => {
                        self.send_command_state.remove_command_in_progress()
                    }
                    _ => None,
                };

                if let Some((handle, SendCommandKind::Regular { command })) = removed_command {
                    Some(FinishCommandResult::LiteralRejected { handle, command })
                } else {
                    None
                }
            }
            SendCommandKind::Authenticate {
                command_authenticate,
                ..
            } => {
                let removed_command = match status {
                    Status::Tagged(Tagged {
                        tag,
                        body: StatusBody { kind, .. },
                        ..
                    }) if tag == &command_authenticate.tag => self
                        .send_command_state
                        .remove_command_in_progress()
                        .zip(Some(kind.clone())),
                    _ => None,
                };

                if let Some((
                    (
                        handle,
                        SendCommandKind::Authenticate {
                            command_authenticate,
                            ..
                        },
                    ),
                    status_kind,
                )) = removed_command
                {
                    match status_kind {
                        StatusKind::Ok => Some(FinishCommandResult::AuthenticationAccepted {
                            handle,
                            command_authenticate,
                        }),
                        StatusKind::No | StatusKind::Bad => {
                            Some(FinishCommandResult::AuthenticationRejected {
                                handle,
                                command_authenticate,
                            })
                        }
                    }
                } else {
                    None
                }
            }
        }
    }

    pub fn authenticate_continue(
        &mut self,
        authenticate_data: AuthenticateData,
    ) -> Result<ClientFlowCommandHandle, AuthenticateData> {
        self.send_command_state
            .continue_authenticate_with_data(authenticate_data)
            .copied()
    }
}

enum FinishCommandResult {
    LiteralRejected {
        handle: ClientFlowCommandHandle,
        command: Command<'static>,
    },
    AuthenticationAccepted {
        handle: ClientFlowCommandHandle,
        command_authenticate: CommandAuthenticate,
    },
    AuthenticationRejected {
        handle: ClientFlowCommandHandle,
        command_authenticate: CommandAuthenticate,
    },
}

/// A handle for an enqueued [`Command`].
///
/// This handle can be used to track the sending progress. After a [`Command`] was enqueued via
/// [`ClientFlow::enqueue_command`] it is in the process of being sent until
/// [`ClientFlow::progress`] returns a [`ClientFlowEvent::CommandSent`] or
/// [`ClientFlowEvent::CommandRejected`] with the corresponding handle.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct ClientFlowCommandHandle(RawHandle);

impl Handle for ClientFlowCommandHandle {
    fn from_raw(handle: RawHandle) -> Self {
        Self(handle)
    }
}

// Implement a short debug representation that hides the underlying raw handle
impl Debug for ClientFlowCommandHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ClientFlowCommandHandle")
            .field(&self.0.generator_id())
            .field(&self.0.handle_id())
            .finish()
    }
}

#[derive(Debug)]
pub enum ClientFlowEvent {
    /// Enqueued [`Command`] successfully sent.
    CommandSent {
        /// Handle to the enqueued [`Command`].
        handle: ClientFlowCommandHandle,
        /// Formerly enqueued [`Command`].
        command: Command<'static>,
    },
    /// Enqueued [`Command`] rejected.
    ///
    /// Note: Emitted when the server rejected a command literal with `BAD`.
    CommandRejected {
        /// Handle to the enqueued [`Command`].
        handle: ClientFlowCommandHandle,
        /// Formerly enqueued [`Command`].
        command: Command<'static>,
        /// [`Status`] sent by the server in order to reject the [`Command`].
        ///
        /// Note: [`ClientFlow`] already handled this [`Status`] but it might still have
        /// useful information that could be logged or displayed to the user
        /// (e.g. [`Code::Alert`](imap_codec::imap_types::response::Code::Alert)).
        status: Status<'static>,
    },
    AuthenticateStarted {
        handle: ClientFlowCommandHandle,
    },
    /// Server is requesting (more) authentication data.
    ContinuationAuthenticateReceived {
        /// Handle to the enqueued [`Command`].
        handle: ClientFlowCommandHandle,
        continuation: CommandContinuationRequest<'static>,
    },
    AuthenticateAccepted {
        handle: ClientFlowCommandHandle,
        command_authenticate: CommandAuthenticate,
        status: Status<'static>,
    },
    AuthenticateRejected {
        handle: ClientFlowCommandHandle,
        command_authenticate: CommandAuthenticate,
        status: Status<'static>,
    },
    /// Server [`Data`] received.
    DataReceived {
        data: Data<'static>,
    },
    /// Server [`Status`] received.
    StatusReceived {
        status: Status<'static>,
    },
    /// Server [`CommandContinuationRequest`] response received.
    ///
    /// Note: The received continuation was not part of [`ClientFlow`] handling.
    ContinuationReceived {
        continuation: CommandContinuationRequest<'static>,
    },
}

#[derive(Debug, Error)]
pub enum ClientFlowError {
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error("Expected `\\r\\n`, got `\\n`")]
    ExpectedCrlfGotLf { discarded_bytes: Box<[u8]> },
    #[error("Received malformed message")]
    MalformedMessage { discarded_bytes: Box<[u8]> },
}
