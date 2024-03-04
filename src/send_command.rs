use std::collections::VecDeque;

use imap_codec::{
    encode::{Encoder, Fragment},
    AuthenticateDataCodec, CommandCodec, IdleDoneCodec,
};
use imap_types::{
    auth::AuthenticateData,
    command::{Command, CommandBody},
    core::{LiteralMode, Tag},
    extensions::idle::IdleDone,
    response::{Status, StatusBody, StatusKind, Tagged},
};
use tracing::warn;

use crate::{
    client::ClientFlowCommandHandle,
    stream::{AnyStream, WriteBuffer, WriteError},
    types::CommandAuthenticate,
};

pub struct SendCommandState {
    command_codec: CommandCodec,
    authenticate_data_codec: AuthenticateDataCodec,
    idle_done_codec: IdleDoneCodec,
    /// FIFO queue for commands that should be sent next.
    queued_commands: VecDeque<QueuedCommand>,
    /// The command that is currently being sent.
    current_command: Option<CurrentCommand>,
    /// Used for writing the current command to the stream.
    /// Note that this buffer can be non-empty even if `current_command` is `None`
    /// because commands can be aborted (see `maybe_terminate`) but partially sent
    /// fragment must never be aborted.
    write_buffer: WriteBuffer,
}

impl SendCommandState {
    pub fn new(
        command_codec: CommandCodec,
        authenticate_data_codec: AuthenticateDataCodec,
        idle_done_codec: IdleDoneCodec,
        write_buffer: WriteBuffer,
    ) -> Self {
        Self {
            command_codec,
            authenticate_data_codec,
            idle_done_codec,
            queued_commands: VecDeque::new(),
            current_command: None,
            write_buffer,
        }
    }

    pub fn enqueue(&mut self, handle: ClientFlowCommandHandle, command: Command<'static>) {
        self.queued_commands
            .push_back(QueuedCommand { handle, command });
    }

    /// Terminates the current command depending on the received status.
    pub fn maybe_remove(&mut self, status: &Status) -> Option<SendCommandTermination> {
        // TODO: Do we want more checks on the state? Was idle already accepted? Does the command even has a literal? etc.
        // If we reach one of the return statements, the current command will be removed
        let current_command = self.current_command.take()?;
        self.current_command = Some(match current_command {
            CurrentCommand::Command(state) => {
                // Check if status matches the current command
                if let Status::Tagged(Tagged {
                    tag,
                    body: StatusBody { kind, .. },
                    ..
                }) = status
                {
                    if *kind == StatusKind::Bad && tag == &state.command.tag {
                        // Terminate command because literal was rejected
                        return Some(SendCommandTermination::LiteralRejected {
                            handle: state.handle,
                            command: state.command,
                        });
                    }
                }

                CurrentCommand::Command(state)
            }
            CurrentCommand::Authenticate(state) => {
                // Check if status matches the current authenticate command
                if let Status::Tagged(Tagged {
                    tag,
                    body: StatusBody { kind, .. },
                    ..
                }) = status
                {
                    if tag == &state.command_authenticate.tag {
                        match kind {
                            StatusKind::Ok => {
                                // Terminate authenticate command because it was accepted
                                return Some(SendCommandTermination::AuthenticateAccepted {
                                    handle: state.handle,
                                    command_authenticate: state.command_authenticate,
                                });
                            }
                            StatusKind::No | StatusKind::Bad => {
                                // Terminate authenticate command because it was rejected
                                return Some(SendCommandTermination::AuthenticateRejected {
                                    handle: state.handle,
                                    command_authenticate: state.command_authenticate,
                                });
                            }
                        };
                    }
                }

                CurrentCommand::Authenticate(state)
            }
            CurrentCommand::Idle(state) => {
                // Check if status matches the current idle command
                if let Status::Tagged(Tagged {
                    tag,
                    body: StatusBody { kind, .. },
                    ..
                }) = status
                {
                    if tag == &state.tag {
                        if matches!(kind, StatusKind::Ok | StatusKind::Bad) {
                            warn!(got=?status, "Expected command continuation request response or NO command completion result");
                            warn!("Interpreting as IDLE rejected");
                        }

                        // Terminate idle command because it was rejected
                        return Some(SendCommandTermination::IdleRejected {
                            handle: state.handle,
                        });
                    }
                }

                CurrentCommand::Idle(state)
            }
        });

        None
    }

    /// Handles the received continuation request for a literal.
    pub fn literal_continue(&mut self) -> bool {
        // Check whether in correct state
        let Some(current_command) = self.current_command.take() else {
            return false;
        };
        let CurrentCommand::Command(state) = current_command else {
            self.current_command = Some(current_command);
            return false;
        };
        let CommandActivity::WaitingForLiteralAccepted { limbo_literal } = state.activity else {
            self.current_command = Some(CurrentCommand::Command(state));
            return false;
        };

        // Change state
        self.current_command = Some(CurrentCommand::Command(CommandState {
            activity: CommandActivity::PushingFragments {
                accepted_literal: Some(limbo_literal),
            },
            ..state
        }));

        true
    }

    /// Handles the received continuation request for an authenticate data.
    pub fn authenticate_continue(&mut self) -> Option<ClientFlowCommandHandle> {
        // Check whether in correct state
        let Some(current_command) = self.current_command.take() else {
            return None;
        };
        let CurrentCommand::Authenticate(state) = current_command else {
            self.current_command = Some(current_command);
            return None;
        };
        let AuthenticateActivity::WaitingForAuthenticateResponse = state.activity else {
            self.current_command = Some(CurrentCommand::Authenticate(state));
            return None;
        };

        // Change state
        self.current_command = Some(CurrentCommand::Authenticate(AuthenticateState {
            activity: AuthenticateActivity::WaitingForAuthenticateDataSet,
            ..state
        }));

        Some(state.handle)
    }

    /// Takes the requested authenticate data and sends it to the server.
    pub fn set_authenticate_data(
        &mut self,
        authenticate_data: AuthenticateData<'static>,
    ) -> Result<ClientFlowCommandHandle, AuthenticateData> {
        // Check whether in correct state
        let Some(current_command) = self.current_command.take() else {
            return Err(authenticate_data);
        };
        let CurrentCommand::Authenticate(state) = current_command else {
            self.current_command = Some(current_command);
            return Err(authenticate_data);
        };
        let AuthenticateActivity::WaitingForAuthenticateDataSet = state.activity else {
            self.current_command = Some(CurrentCommand::Authenticate(state));
            return Err(authenticate_data);
        };

        // Encode authenticate data
        let mut fragments = self.authenticate_data_codec.encode(&authenticate_data);
        // Authenticate data is a single line by definition
        let Some(Fragment::Line {
            data: authenticate_data,
        }) = fragments.next()
        else {
            unreachable!()
        };
        assert!(fragments.next().is_none());

        // Change state
        self.current_command = Some(CurrentCommand::Authenticate(AuthenticateState {
            activity: AuthenticateActivity::PushingAuthenticateData { authenticate_data },
            ..state
        }));

        Ok(state.handle)
    }

    /// Handles the received continuation request for the idle done.
    pub fn idle_continue(&mut self) -> Option<ClientFlowCommandHandle> {
        // Check whether in correct state
        let Some(current_command) = self.current_command.take() else {
            return None;
        };
        let CurrentCommand::Idle(state) = current_command else {
            self.current_command = Some(current_command);
            return None;
        };
        let IdleActivity::WaitingForIdleResponse = state.activity else {
            self.current_command = Some(CurrentCommand::Idle(state));
            return None;
        };

        // Change state
        self.current_command = Some(CurrentCommand::Idle(IdleState {
            activity: IdleActivity::WaitingForIdleDoneSet,
            ..state
        }));

        Some(state.handle)
    }

    /// Sends the requested idle done to the server.
    pub fn set_idle_done(&mut self) -> Option<ClientFlowCommandHandle> {
        // Check whether in correct state
        let Some(current_command) = self.current_command.take() else {
            return None;
        };
        let CurrentCommand::Idle(state) = current_command else {
            self.current_command = Some(current_command);
            return None;
        };
        let IdleActivity::WaitingForIdleDoneSet = state.activity else {
            self.current_command = Some(CurrentCommand::Idle(state));
            return None;
        };

        // Encode idle done
        let mut fragments = self.idle_done_codec.encode(&IdleDone);
        // Idle done is a single line by defintion
        let Some(Fragment::Line {
            data: idle_done, ..
        }) = fragments.next()
        else {
            unreachable!()
        };
        assert!(fragments.next().is_none());

        // Change state
        let handle = state.handle;
        self.current_command = Some(CurrentCommand::Idle(IdleState {
            activity: IdleActivity::PushingIdleDone { idle_done },
            ..state
        }));

        Some(handle)
    }

    pub async fn progress(
        &mut self,
        stream: &mut AnyStream,
    ) -> Result<Option<SendCommandEvent>, WriteError> {
        let current_command = match self.current_command.take() {
            Some(current_command) => {
                // We are currently sending a command but the sending process was aborted for one
                // of these reasons:
                // - The future was cancelled
                // - The server must send a continuation request or a status
                // - The client flow user must provide more data
                // Continue the sending process.
                current_command
            }
            None => {
                let Some(queued_command) = self.queued_commands.pop_front() else {
                    // There is currently no command that needs to be sent
                    return Ok(None);
                };

                queued_command.start(&self.command_codec)
            }
        };

        // Push as many bytes of the command as possible to the buffer
        let current_command = current_command.push_to_buffer(&mut self.write_buffer);

        // Store the current command to ensure cancellation safety
        self.current_command = Some(current_command);

        // Send all bytes of current command
        stream.write_all(&mut self.write_buffer).await?;

        // Restore the current command, can't fail because we set it to `Some` above
        let current_command = self.current_command.take().unwrap();

        // Inform the state of the current command that all bytes were sent
        match current_command.finish_sending() {
            FinishSendingResult::Uncompleted {
                state: current_command,
                event,
            } => {
                // Command is not finished yet
                self.current_command = Some(current_command);
                Ok(event)
            }
            FinishSendingResult::Completed { event } => {
                // Command was sent completely
                Ok(Some(event))
            }
        }
    }
}

/// Queued (and not sent yet) command.
struct QueuedCommand {
    handle: ClientFlowCommandHandle,
    command: Command<'static>,
}

impl QueuedCommand {
    /// Start the sending process for this command.
    fn start(self, codec: &CommandCodec) -> CurrentCommand {
        let handle = self.handle;
        let command = self.command;
        let mut fragments = codec.encode(&command);
        let tag = command.tag;

        match command.body {
            CommandBody::Authenticate {
                mechanism,
                initial_response,
            } => {
                // The authenticate command is a single line by definition
                let Some(Fragment::Line { data: authenticate }) = fragments.next() else {
                    unreachable!()
                };
                assert!(fragments.next().is_none());

                CurrentCommand::Authenticate(AuthenticateState {
                    handle,
                    command_authenticate: CommandAuthenticate {
                        tag,
                        mechanism,
                        initial_response,
                    },
                    activity: AuthenticateActivity::PushingAuthenticate { authenticate },
                })
            }
            CommandBody::Idle => {
                // The idle command is a single line by definition
                let Some(Fragment::Line { data: idle }) = fragments.next() else {
                    unreachable!()
                };
                assert!(fragments.next().is_none());

                CurrentCommand::Idle(IdleState {
                    handle,
                    tag,
                    activity: IdleActivity::PushingIdle { idle },
                })
            }
            body => CurrentCommand::Command(CommandState {
                handle,
                command: Command { tag, body },
                fragments: fragments.collect(),
                activity: CommandActivity::PushingFragments {
                    accepted_literal: None,
                },
            }),
        }
    }
}

/// Currently being sent command.
enum CurrentCommand {
    /// Sending state of regular command.
    Command(CommandState),
    /// Sending state of authenticate command.
    Authenticate(AuthenticateState),
    /// Sending state of idle command.
    Idle(IdleState),
}

impl CurrentCommand {
    /// Pushes as many bytes as possible from the command to the buffer.
    fn push_to_buffer(self, write_buffer: &mut WriteBuffer) -> Self {
        match self {
            Self::Command(state) => Self::Command(state.push_to_buffer(write_buffer)),
            Self::Authenticate(state) => Self::Authenticate(state.push_to_buffer(write_buffer)),
            Self::Idle(state) => Self::Idle(state.push_to_buffer(write_buffer)),
        }
    }

    /// Updates the state after all bytes were sent.
    fn finish_sending(self) -> FinishSendingResult<Self> {
        match self {
            Self::Command(state) => state.finish_sending().map_state(Self::Command),
            Self::Authenticate(state) => state.finish_sending().map_state(Self::Authenticate),
            Self::Idle(state) => state.finish_sending().map_state(Self::Idle),
        }
    }
}

/// Updated command state after sending all bytes, see `finish_sending`.
enum FinishSendingResult<S> {
    /// Command not finished yet.
    Uncompleted {
        /// Updated command state.
        state: S,
        /// Event that needs to be returned by `progress`.
        event: Option<SendCommandEvent>,
    },
    /// Command sent completely.
    Completed {
        /// Event that needs to be returned by `progress`.
        event: SendCommandEvent,
    },
}

impl<S> FinishSendingResult<S> {
    fn map_state<T>(self, f: impl Fn(S) -> T) -> FinishSendingResult<T> {
        match self {
            FinishSendingResult::Uncompleted { state, event } => FinishSendingResult::Uncompleted {
                state: f(state),
                event,
            },
            FinishSendingResult::Completed { event } => FinishSendingResult::Completed { event },
        }
    }
}

struct CommandState {
    handle: ClientFlowCommandHandle,
    command: Command<'static>,
    /// The outstanding command fragments that needs to be sent.
    fragments: VecDeque<Fragment>,
    activity: CommandActivity,
}

impl CommandState {
    fn push_to_buffer(self, write_buffer: &mut WriteBuffer) -> Self {
        let mut fragments = self.fragments;
        let activity = match self.activity {
            CommandActivity::PushingFragments { accepted_literal } => {
                // First push the accepted literal if available
                if let Some(data) = accepted_literal {
                    write_buffer.bytes.extend(data);
                }

                // Push as many fragments as possible
                let limbo_literal = loop {
                    match fragments.pop_front() {
                        Some(
                            Fragment::Line { data }
                            | Fragment::Literal {
                                data,
                                mode: LiteralMode::NonSync,
                            },
                        ) => {
                            write_buffer.bytes.extend(data);
                        }
                        Some(Fragment::Literal {
                            data,
                            mode: LiteralMode::Sync,
                        }) => {
                            // Stop pushing fragments because a literal needs to be accepted
                            // by the server
                            break Some(data);
                        }
                        None => break None,
                    };
                };

                // Done with pushing
                CommandActivity::WaitingForFragmentsSent { limbo_literal }
            }
            activity => activity,
        };

        Self {
            fragments,
            activity,
            ..self
        }
    }

    fn finish_sending(self) -> FinishSendingResult<Self> {
        match self.activity {
            CommandActivity::WaitingForFragmentsSent { limbo_literal } => match limbo_literal {
                Some(limbo_literal) => FinishSendingResult::Uncompleted {
                    state: Self {
                        activity: CommandActivity::WaitingForLiteralAccepted { limbo_literal },
                        ..self
                    },
                    event: None,
                },
                None => FinishSendingResult::Completed {
                    event: SendCommandEvent::Command {
                        handle: self.handle,
                        command: self.command,
                    },
                },
            },
            activity => FinishSendingResult::Uncompleted {
                state: Self { activity, ..self },
                event: None,
            },
        }
    }
}

enum CommandActivity {
    /// Pushing fragments to the write buffer.
    PushingFragments {
        /// A literal that was accepted by the server and needs to be sent before the fragments.
        accepted_literal: Option<Vec<u8>>,
    },
    /// Waiting until the pushed fragments are sent.
    WaitingForFragmentsSent {
        /// A literal that needs to be accepted by the server after the pushed fragments are sent.
        limbo_literal: Option<Vec<u8>>,
    },
    /// Waiting until the server accepts the literal via continuation request or rejects it
    /// via status.
    WaitingForLiteralAccepted {
        /// Literal that needs to be accepted by the server.
        limbo_literal: Vec<u8>,
    },
}

struct AuthenticateState {
    handle: ClientFlowCommandHandle,
    command_authenticate: CommandAuthenticate,
    activity: AuthenticateActivity,
}

impl AuthenticateState {
    fn push_to_buffer(self, write_buffer: &mut WriteBuffer) -> Self {
        let activity = match self.activity {
            AuthenticateActivity::PushingAuthenticate { authenticate } => {
                write_buffer.bytes.extend(authenticate);
                AuthenticateActivity::WaitingForAuthenticateSent
            }
            AuthenticateActivity::PushingAuthenticateData { authenticate_data } => {
                write_buffer.bytes.extend(authenticate_data);
                AuthenticateActivity::WaitingForAuthenticateDataSent
            }
            activity => activity,
        };

        Self { activity, ..self }
    }

    fn finish_sending(self) -> FinishSendingResult<Self> {
        match self.activity {
            AuthenticateActivity::WaitingForAuthenticateSent => FinishSendingResult::Uncompleted {
                state: Self {
                    activity: AuthenticateActivity::WaitingForAuthenticateResponse,
                    ..self
                },
                event: Some(SendCommandEvent::CommandAuthenticate {
                    handle: self.handle,
                }),
            },
            AuthenticateActivity::WaitingForAuthenticateDataSent => {
                FinishSendingResult::Uncompleted {
                    state: Self {
                        activity: AuthenticateActivity::WaitingForAuthenticateResponse,
                        ..self
                    },
                    event: None,
                }
            }
            activity => FinishSendingResult::Uncompleted {
                state: Self { activity, ..self },
                event: None,
            },
        }
    }
}

enum AuthenticateActivity {
    /// Pushing the authenticate command to the write buffer.
    PushingAuthenticate { authenticate: Vec<u8> },
    /// Waiting until the pushed authenticate command is sent.
    WaitingForAuthenticateSent,
    /// Waiting until the server requests more authenticate data via continuation request or
    /// accepts/rejects the authenticate command via status.
    WaitingForAuthenticateResponse,
    /// Waiting until the client flow user provides the authenticate data.
    ///
    /// Specifically, [`ClientFlow::set_authenticate_data`].
    WaitingForAuthenticateDataSet,
    /// Pushing the authenticate data to the write buffer.
    PushingAuthenticateData { authenticate_data: Vec<u8> },
    /// Waiting until the pushed authenticate data is sent.
    WaitingForAuthenticateDataSent,
}

struct IdleState {
    handle: ClientFlowCommandHandle,
    tag: Tag<'static>,
    activity: IdleActivity,
}

impl IdleState {
    fn push_to_buffer(self, write_buffer: &mut WriteBuffer) -> Self {
        let activity = match self.activity {
            IdleActivity::PushingIdle { idle } => {
                write_buffer.bytes.extend(idle);
                IdleActivity::WaitingForIdleSent
            }
            IdleActivity::PushingIdleDone { idle_done } => {
                write_buffer.bytes.extend(idle_done);
                IdleActivity::WaitingForIdleDoneSent
            }
            activity => activity,
        };

        Self { activity, ..self }
    }

    fn finish_sending(self) -> FinishSendingResult<Self> {
        match self.activity {
            IdleActivity::WaitingForIdleSent => FinishSendingResult::Uncompleted {
                state: Self {
                    activity: IdleActivity::WaitingForIdleResponse,
                    ..self
                },
                event: Some(SendCommandEvent::CommandIdle {
                    handle: self.handle,
                }),
            },
            IdleActivity::WaitingForIdleDoneSent => FinishSendingResult::Completed {
                event: SendCommandEvent::IdleDone {
                    handle: self.handle,
                },
            },
            activity => FinishSendingResult::Uncompleted {
                state: Self { activity, ..self },
                event: None,
            },
        }
    }
}

enum IdleActivity {
    /// Pushing the idle command to the write buffer.
    PushingIdle { idle: Vec<u8> },
    /// Waiting until the pushed idle command is sent.
    WaitingForIdleSent,
    /// Waiting until the server accepts the idle command via continuation request or rejects it
    /// via status.
    WaitingForIdleResponse,
    /// Waiting until the client flow user triggers idle done.
    ///
    /// Specifically, [`ClientFlow::set_idle_done`].
    WaitingForIdleDoneSet,
    /// Pushing the idle done to the write buffer.
    PushingIdleDone { idle_done: Vec<u8> },
    /// Waiting until the pushed idle done is sent.
    WaitingForIdleDoneSent,
}

/// Command was sent.
pub enum SendCommandEvent {
    Command {
        handle: ClientFlowCommandHandle,
        command: Command<'static>,
    },
    CommandAuthenticate {
        handle: ClientFlowCommandHandle,
    },
    CommandIdle {
        handle: ClientFlowCommandHandle,
    },
    IdleDone {
        handle: ClientFlowCommandHandle,
    },
}

/// Command was terminated via `maybe_terminate`.
pub enum SendCommandTermination {
    /// Command was terminated because its literal was rejected by the server.
    LiteralRejected {
        handle: ClientFlowCommandHandle,
        command: Command<'static>,
    },
    /// Authenticate command was accepted.
    AuthenticateAccepted {
        handle: ClientFlowCommandHandle,
        command_authenticate: CommandAuthenticate,
    },
    /// Authenticate command was rejected.
    AuthenticateRejected {
        handle: ClientFlowCommandHandle,
        command_authenticate: CommandAuthenticate,
    },
    /// Idle command was rejected.
    IdleRejected { handle: ClientFlowCommandHandle },
}
