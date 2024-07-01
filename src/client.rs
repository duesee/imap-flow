use std::fmt::{Debug, Formatter};

use imap_codec::{
    AuthenticateDataCodec, CommandCodec, GreetingCodec, IdleDoneCodec, ResponseCodec,
};
use imap_types::{
    auth::AuthenticateData,
    command::Command,
    response::{CommandContinuationRequest, Data, Greeting, Response, Status},
    secret::Secret,
};
use thiserror::Error;

use crate::{
    client_send::{ClientSendEvent, ClientSendState, ClientSendTermination},
    handle::{Handle, HandleGenerator, HandleGeneratorGenerator, RawHandle},
    receive::{ReceiveError, ReceiveEvent, ReceiveState},
    types::CommandAuthenticate,
    Interrupt, State,
};

static HANDLE_GENERATOR_GENERATOR: HandleGeneratorGenerator<CommandHandle> =
    HandleGeneratorGenerator::new();

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Options {
    pub crlf_relaxed: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for Options {
    fn default() -> Self {
        Self {
            // Lean towards conformity
            crlf_relaxed: false,
        }
    }
}

pub struct Client {
    handle_generator: HandleGenerator<CommandHandle>,
    send_state: ClientSendState,
    receive_state: ReceiveState,
    next_expected_message: NextExpectedMessage,
}

impl Client {
    pub fn new(options: Options) -> Self {
        let send_state = ClientSendState::new(
            CommandCodec::default(),
            AuthenticateDataCodec::default(),
            IdleDoneCodec::default(),
        );

        let receive_state = ReceiveState::new(options.crlf_relaxed, None);
        let next_expected_message = NextExpectedMessage::Greeting(GreetingCodec::default());

        Self {
            handle_generator: HANDLE_GENERATOR_GENERATOR.generate(),
            send_state,
            receive_state,
            next_expected_message,
        }
    }

    /// Enqueues the [`Command`] for being sent to the client.
    ///
    /// The [`Command`] is not sent immediately but during one of the next calls of
    /// [`Client::next`]. All [`Command`]s are sent in the same order they have been
    /// enqueued.
    pub fn enqueue_command(&mut self, command: Command<'static>) -> CommandHandle {
        let handle = self.handle_generator.generate();
        self.send_state.enqueue_command(handle, command);
        handle
    }

    fn progress_send(&mut self) -> Result<Option<Event>, Interrupt<Error>> {
        // Abort if we didn't received the greeting yet
        if let NextExpectedMessage::Greeting(_) = &self.next_expected_message {
            return Ok(None);
        }

        match self.send_state.next() {
            Ok(Some(ClientSendEvent::Command { handle, command })) => {
                Ok(Some(Event::CommandSent { handle, command }))
            }
            Ok(Some(ClientSendEvent::Authenticate { handle })) => {
                Ok(Some(Event::AuthenticateStarted { handle }))
            }
            Ok(Some(ClientSendEvent::Idle { handle })) => {
                Ok(Some(Event::IdleCommandSent { handle }))
            }
            Ok(Some(ClientSendEvent::IdleDone { handle })) => {
                Ok(Some(Event::IdleDoneSent { handle }))
            }
            Ok(None) => Ok(None),
            Err(Interrupt::Io(io)) => Err(Interrupt::Io(io)),
            Err(Interrupt::Error(_)) => unreachable!(),
        }
    }

    fn progress_receive(&mut self) -> Result<Option<Event>, Interrupt<Error>> {
        let event = loop {
            match &self.next_expected_message {
                NextExpectedMessage::Greeting(codec) => {
                    match self.receive_state.next::<GreetingCodec>(codec) {
                        Ok(ReceiveEvent::DecodingSuccess(greeting)) => {
                            self.next_expected_message =
                                NextExpectedMessage::Response(ResponseCodec::default());
                            break Some(Event::GreetingReceived { greeting });
                        }
                        Ok(ReceiveEvent::LiteralAnnouncement { .. }) => {
                            // Unexpected literal, let's continue and see what happen
                            continue;
                        }
                        Err(interrupt) => return Err(handle_receive_interrupt(interrupt)),
                    }
                }
                NextExpectedMessage::Response(codec) => {
                    let response = match self.receive_state.next::<ResponseCodec>(codec) {
                        Ok(ReceiveEvent::DecodingSuccess(response)) => response,
                        Ok(ReceiveEvent::LiteralAnnouncement { .. }) => {
                            // The client must accept the literal in any case.
                            continue;
                        }
                        Err(interrupt) => return Err(handle_receive_interrupt(interrupt)),
                    };

                    match response {
                        Response::Status(status) => {
                            let event = if let Some(finish_result) =
                                self.send_state.maybe_terminate(&status)
                            {
                                match finish_result {
                                    ClientSendTermination::LiteralRejected { handle, command } => {
                                        Event::CommandRejected {
                                            handle,
                                            command,
                                            status,
                                        }
                                    }
                                    ClientSendTermination::AuthenticateAccepted {
                                        handle,
                                        command_authenticate,
                                    }
                                    | ClientSendTermination::AuthenticateRejected {
                                        handle,
                                        command_authenticate,
                                    } => Event::AuthenticateStatusReceived {
                                        handle,
                                        command_authenticate,
                                        status,
                                    },
                                    ClientSendTermination::IdleRejected { handle } => {
                                        Event::IdleRejected { handle, status }
                                    }
                                }
                            } else {
                                Event::StatusReceived { status }
                            };

                            break Some(event);
                        }
                        Response::Data(data) => break Some(Event::DataReceived { data }),
                        Response::CommandContinuationRequest(continuation_request) => {
                            if self.send_state.literal_continue() {
                                // We received a continuation request that was necessary for
                                // sending a command. So we abort receiving responses for now
                                // and continue with sending commands.
                                break None;
                            } else if let Some(handle) = self.send_state.authenticate_continue() {
                                break Some(Event::AuthenticateContinuationRequestReceived {
                                    handle,
                                    continuation_request,
                                });
                            } else if let Some(handle) = self.send_state.idle_continue() {
                                break Some(Event::IdleAccepted {
                                    handle,
                                    continuation_request,
                                });
                            } else {
                                break Some(Event::ContinuationRequestReceived {
                                    continuation_request,
                                });
                            }
                        }
                    }
                }
            }
        };

        Ok(event)
    }

    pub fn set_authenticate_data(
        &mut self,
        authenticate_data: AuthenticateData<'static>,
    ) -> Result<CommandHandle, AuthenticateData<'static>> {
        self.send_state.set_authenticate_data(authenticate_data)
    }

    pub fn set_idle_done(&mut self) -> Option<CommandHandle> {
        self.send_state.set_idle_done()
    }
}

impl Debug for Client {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("handle_generator", &self.handle_generator)
            .finish_non_exhaustive()
    }
}

impl State for Client {
    type Event = Event;
    type Error = Error;

    fn enqueue_input(&mut self, bytes: &[u8]) {
        self.receive_state.enqueue_input(bytes);
    }

    fn next(&mut self) -> Result<Self::Event, Interrupt<Self::Error>> {
        loop {
            if let Some(event) = self.progress_send()? {
                return Ok(event);
            }

            if let Some(event) = self.progress_receive()? {
                return Ok(event);
            }
        }
    }
}

fn handle_receive_interrupt(interrupt: Interrupt<ReceiveError>) -> Interrupt<Error> {
    match interrupt {
        Interrupt::Io(io) => Interrupt::Io(io),
        Interrupt::Error(ReceiveError::DecodingFailure { discarded_bytes }) => {
            Interrupt::Error(Error::MalformedMessage { discarded_bytes })
        }
        Interrupt::Error(ReceiveError::ExpectedCrlfGotLf { discarded_bytes }) => {
            Interrupt::Error(Error::ExpectedCrlfGotLf { discarded_bytes })
        }
        Interrupt::Error(ReceiveError::MessageIsPoisoned { .. }) => {
            // Unreachable because we don't poison messages
            unreachable!()
        }
        Interrupt::Error(ReceiveError::MessageTooLong { .. }) => {
            // Unreachable because message limit is not set
            unreachable!()
        }
    }
}

/// Handle for enqueued [`Command`].
///
/// This handle can be used to track the sending progress. After a [`Command`] was enqueued via
/// [`Client::enqueue_command`] it is in the process of being sent until [`Client::next`] returns
/// a [`Event::CommandSent`] or [`Event::CommandRejected`] with the corresponding handle.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct CommandHandle(RawHandle);

/// Debug representation hiding the raw handle.
impl Debug for CommandHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CommandHandle")
            .field(&self.0.generator_id())
            .field(&self.0.handle_id())
            .finish()
    }
}

impl Handle for CommandHandle {
    fn from_raw(handle: RawHandle) -> Self {
        Self(handle)
    }
}

#[derive(Debug)]
pub enum Event {
    /// [`Greeting`] received.
    GreetingReceived { greeting: Greeting<'static> },
    /// [`Command`] sent completely.
    CommandSent {
        /// Handle to the enqueued [`Command`].
        handle: CommandHandle,
        /// Formerly enqueued [`Command`].
        command: Command<'static>,
    },
    /// [`Command`] rejected due to literal.
    CommandRejected {
        /// Handle to enqueued [`Command`].
        handle: CommandHandle,
        /// Formerly enqueued [`Command`].
        command: Command<'static>,
        /// [`Status`] sent by the server to reject the [`Command`].
        ///
        /// Note: [`Client`] already handled this [`Status`] but it might still have
        /// useful information that could be logged or displayed to the user
        /// (e.g. [`Code::Alert`](imap_types::response::Code::Alert)).
        status: Status<'static>,
    },
    /// AUTHENTICATE sent.
    AuthenticateStarted { handle: CommandHandle },
    /// Server requests (more) authentication data.
    ///
    /// The client MUST call [`Client::set_authenticate_data`] next.
    ///
    /// Note: The client can also progress the authentication by sending [`AuthenticateData::Cancel`].
    /// However, it's up to the server to abort the authentication flow by sending a tagged status response.
    AuthenticateContinuationRequestReceived {
        /// Handle to the enqueued [`Command`].
        handle: CommandHandle,
        continuation_request: CommandContinuationRequest<'static>,
    },
    /// [`Status`] received to authenticate command.
    AuthenticateStatusReceived {
        handle: CommandHandle,
        command_authenticate: CommandAuthenticate,
        status: Status<'static>,
    },
    /// IDLE sent.
    IdleCommandSent { handle: CommandHandle },
    /// IDLE accepted by server. Entering IDLE state.
    IdleAccepted {
        handle: CommandHandle,
        continuation_request: CommandContinuationRequest<'static>,
    },
    /// IDLE rejected by server.
    IdleRejected {
        handle: CommandHandle,
        status: Status<'static>,
    },
    /// DONE sent. Exiting IDLE state.
    IdleDoneSent { handle: CommandHandle },
    /// Server [`Data`] received.
    DataReceived { data: Data<'static> },
    /// Server [`Status`] received.
    StatusReceived { status: Status<'static> },
    /// Server [`CommandContinuationRequest`] response received.
    ///
    /// Note: The received continuation request was not part of [`Client`] handling.
    ContinuationRequestReceived {
        continuation_request: CommandContinuationRequest<'static>,
    },
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Expected `\\r\\n`, got `\\n`")]
    ExpectedCrlfGotLf { discarded_bytes: Secret<Box<[u8]>> },
    #[error("Received malformed message")]
    MalformedMessage { discarded_bytes: Secret<Box<[u8]>> },
}

#[derive(Clone, Debug)]
pub enum NextExpectedMessage {
    Greeting(GreetingCodec),
    Response(ResponseCodec),
}
