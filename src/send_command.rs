use std::{collections::VecDeque, fmt::Debug};

use bytes::BytesMut;
use imap_codec::{
    encode::{Encoder, Fragment},
    AuthenticateDataCodec, CommandCodec, IdleDoneCodec,
};
use imap_types::{
    auth::AuthenticateData,
    command::{Command, CommandBody},
    core::{LiteralMode, Tag},
    extensions::idle::IdleDone,
};

use crate::{
    stream::{AnyStream, StreamError},
    types::CommandAuthenticate,
};

#[derive(Debug)]
pub struct SendCommandState<K: Copy> {
    command_codec: CommandCodec,
    authenticate_data_codec: AuthenticateDataCodec,
    idle_done_codec: IdleDoneCodec,
    // The commands that should be send.
    send_queue: VecDeque<SendCommandQueueEntry<K>>,
    // State of the command that is currently being sent.
    send_progress: Option<SendCommandProgress<K>>,
    // Used for writing the current command to the stream.
    // Should be empty if `send_progress` is `None`.
    write_buffer: BytesMut,
}

impl<K: Copy> SendCommandState<K> {
    pub fn new(
        command_codec: CommandCodec,
        authenticate_data_codec: AuthenticateDataCodec,
        idle_done_codec: IdleDoneCodec,
        write_buffer: BytesMut,
    ) -> Self {
        Self {
            command_codec,
            authenticate_data_codec,
            idle_done_codec,
            send_queue: VecDeque::new(),
            send_progress: None,
            write_buffer,
        }
    }

    pub fn enqueue(&mut self, key: K, command: Command<'static>) {
        let fragments = self.command_codec.encode(&command).collect();
        let kind = match command.body {
            CommandBody::Authenticate {
                mechanism,
                initial_response,
            } => SendCommandKind::Authenticate {
                command_authenticate: CommandAuthenticate {
                    tag: command.tag,
                    mechanism,
                    initial_response,
                },
                started: false,
            },
            CommandBody::Idle => SendCommandKind::Idle {
                tag: command.tag,
                started: false,
            },
            body => SendCommandKind::Regular {
                command: Command {
                    tag: command.tag,
                    body,
                },
            },
        };
        self.send_queue.push_back(SendCommandQueueEntry {
            key,
            kind,
            fragments,
        });
    }

    pub fn command_in_progress(&self) -> Option<&SendCommandKind> {
        self.send_progress.as_ref().map(|x| &x.kind)
    }

    pub fn remove_command_in_progress(&mut self) -> Option<(K, SendCommandKind)> {
        self.write_buffer.clear();
        self.send_progress
            .take()
            .map(|progress| (progress.key, progress.kind))
    }

    pub fn continue_literal(&mut self) -> bool {
        let Some(write_progress) = self.send_progress.as_mut() else {
            return false;
        };
        let Some(literal_progress) = write_progress.blocked_reason.as_mut() else {
            return false;
        };
        let SendCommandBlockedReason::WaitForLiteralAck {
            received_continue, ..
        } = literal_progress
        else {
            return false;
        };
        if *received_continue {
            return false;
        }

        *received_continue = true;

        true
    }

    pub fn continue_authenticate(&mut self) -> Option<&K> {
        let write_progress = self.send_progress.as_mut()?;
        let literal_progress = write_progress.blocked_reason.as_mut()?;
        let SendCommandBlockedReason::WaitForAuthenticateData {
            received_continue, ..
        } = literal_progress
        else {
            return None;
        };
        if *received_continue {
            return None;
        }

        *received_continue = true;

        Some(&write_progress.key)
    }

    pub fn continue_authenticate_with_data(
        &mut self,
        authenticate_data: AuthenticateData,
    ) -> Result<&K, AuthenticateData> {
        let Some(write_progress) = self.send_progress.as_mut() else {
            return Err(authenticate_data);
        };
        let Some(literal_progress) = write_progress.blocked_reason.as_mut() else {
            return Err(authenticate_data);
        };
        let SendCommandBlockedReason::WaitForAuthenticateData {
            received_continue,
            authenticate_data: current_authenticate_data,
        } = literal_progress
        else {
            return Err(authenticate_data);
        };
        if !*received_continue {
            return Err(authenticate_data);
        }
        if current_authenticate_data.is_some() {
            return Err(authenticate_data);
        }

        *current_authenticate_data = Some(authenticate_data);

        Ok(&write_progress.key)
    }

    pub fn continue_idle(&mut self) -> Option<&K> {
        let write_progress = self.send_progress.as_mut()?;
        let literal_progress = write_progress.blocked_reason.as_mut()?;
        let SendCommandBlockedReason::Idle {
            received_continue, ..
        } = literal_progress
        else {
            return None;
        };
        if *received_continue {
            return None;
        }

        *received_continue = true;

        Some(&write_progress.key)
    }

    pub fn idle_done(&mut self) -> Option<&K> {
        let Some(write_progress) = self.send_progress.as_mut() else {
            return None;
        };
        let Some(literal_progress) = write_progress.blocked_reason.as_mut() else {
            return None;
        };
        let SendCommandBlockedReason::Idle {
            received_continue,
            idle_done: current_idle_done,
        } = literal_progress
        else {
            return None;
        };
        if !*received_continue {
            return None;
        }
        if current_idle_done.is_some() {
            return None;
        }

        *current_idle_done = Some(IdleDone);

        Some(&write_progress.key)
    }

    pub async fn progress(
        &mut self,
        stream: &mut AnyStream,
    ) -> Result<Option<SendCommandEvent<K>>, StreamError> {
        let progress = match self.send_progress.take() {
            Some(progress) => {
                // We are currently sending a command to the server. This sending process was
                // previously aborted for one of two reasons: Either we needed to wait for a
                // `Continue` from the server or the `Future` was dropped while sending.
                progress
            }
            None => {
                let Some(entry) = self.send_queue.pop_front() else {
                    // There is currently no command that need to be sent
                    return Ok(None);
                };

                // Start sending the next command
                SendCommandProgress {
                    key: entry.key,
                    kind: entry.kind,
                    blocked_reason: None,
                    next_fragments: entry.fragments,
                }
            }
        };
        let progress = self.send_progress.insert(progress);

        // Handle the outstanding literal first if there is one
        if let Some(suspended_reason) = progress.blocked_reason.take() {
            match suspended_reason {
                SendCommandBlockedReason::WaitForLiteralAck {
                    data,
                    received_continue,
                } => {
                    if received_continue {
                        // We received a `Continue` from the server, we can send the literal now
                        self.write_buffer.extend(data);
                    } else {
                        // Delay this literal because we still wait for the `Continue` from the server
                        progress.blocked_reason =
                            Some(SendCommandBlockedReason::WaitForLiteralAck {
                                data,
                                received_continue,
                            });

                        // Make sure that the line before the literal is sent completely to the server
                        stream.write_all(&mut self.write_buffer).await?;

                        return Ok(None);
                    }
                }
                SendCommandBlockedReason::WaitForAuthenticateData {
                    received_continue,
                    authenticate_data,
                } => {
                    match authenticate_data {
                        Some(authenticate_data) => {
                            // The data can only be set after receiving a continue from server
                            assert!(received_continue);

                            // We received a `Continue` from the server and the auth data from the
                            // client-flow user. We can send the auth data now.
                            progress
                                .next_fragments
                                .extend(self.authenticate_data_codec.encode(&authenticate_data))
                        }
                        None => {
                            // Delay this because we still wait for the client flow user to call
                            // `authenticate_continue`.
                            progress.blocked_reason =
                                Some(SendCommandBlockedReason::WaitForAuthenticateData {
                                    received_continue,
                                    authenticate_data,
                                });

                            return Ok(None);
                        }
                    }
                }
                SendCommandBlockedReason::Idle {
                    received_continue,
                    idle_done,
                } => {
                    match idle_done {
                        Some(done) => {
                            // The `IdleDone` can only be set after receiving a `Continue`
                            // from server
                            assert!(received_continue);

                            // We received a `Continue` from the server and the `IdleDone`
                            // from the client-flow user. We can send the `IdleDone` now.
                            progress
                                .next_fragments
                                .extend(self.idle_done_codec.encode(&done))
                        }
                        None => {
                            // Delay this because we still wait for the client flow user to call
                            // `idle_done`.
                            progress.blocked_reason = Some(SendCommandBlockedReason::Idle {
                                received_continue,
                                idle_done,
                            });

                            return Ok(None);
                        }
                    }
                }
            }
        }

        // Handle the outstanding lines or literals
        let need_continue = loop {
            if let Some(fragment) = progress.next_fragments.pop_front() {
                match fragment {
                    Fragment::Line { data } => self.write_buffer.extend(data),
                    Fragment::Literal { data, mode } => match mode {
                        LiteralMode::Sync => {
                            // We need to wait for a command continuation request response from the server
                            progress.blocked_reason =
                                Some(SendCommandBlockedReason::WaitForLiteralAck {
                                    data,
                                    received_continue: false,
                                });
                            break true;
                        }
                        LiteralMode::NonSync => self.write_buffer.extend(data),
                    },
                }
            } else {
                break false;
            }
        };

        // Send the bytes of the command to the server
        stream.write_all(&mut self.write_buffer).await?;

        if need_continue {
            Ok(None)
        } else {
            let Some(progress) = self.send_progress.take() else {
                return Ok(None);
            };

            match progress.kind {
                SendCommandKind::Regular { command } => {
                    // Command was sent completely
                    Ok(Some(SendCommandEvent::CommandSent {
                        key: progress.key,
                        command,
                    }))
                }
                SendCommandKind::Authenticate {
                    command_authenticate,
                    started: was_started,
                } => {
                    // Authenticate is only treated as completed after receiving a "OK" from server
                    let progress = self.send_progress.insert(SendCommandProgress {
                        kind: SendCommandKind::Authenticate {
                            command_authenticate,
                            started: true,
                        },
                        blocked_reason: Some(SendCommandBlockedReason::WaitForAuthenticateData {
                            received_continue: false,
                            authenticate_data: None,
                        }),
                        ..progress
                    });

                    if was_started {
                        // Command was already sent before
                        Ok(None)
                    } else {
                        // Command was sent just now
                        Ok(Some(SendCommandEvent::CommandAuthenticateStarted {
                            key: progress.key,
                        }))
                    }
                }
                SendCommandKind::Idle {
                    tag,
                    started: was_started,
                } => {
                    if was_started {
                        Ok(Some(SendCommandEvent::IdleTerminated { key: progress.key }))
                    } else {
                        let progress = self.send_progress.insert(SendCommandProgress {
                            kind: SendCommandKind::Idle { tag, started: true },
                            blocked_reason: Some(SendCommandBlockedReason::Idle {
                                received_continue: false,
                                idle_done: None,
                            }),
                            ..progress
                        });

                        Ok(Some(SendCommandEvent::IdleStarted { key: progress.key }))
                    }
                }
            }
        }
    }
}

pub enum SendCommandEvent<K> {
    CommandSent { key: K, command: Command<'static> },
    CommandAuthenticateStarted { key: K },
    IdleStarted { key: K },
    IdleTerminated { key: K },
}

// TODO(#105)
#[derive(Debug)]
pub enum SendCommandKind {
    Regular {
        command: Command<'static>,
    },
    Authenticate {
        command_authenticate: CommandAuthenticate,
        started: bool,
    },
    Idle {
        tag: Tag<'static>,
        started: bool,
    },
}

#[derive(Debug)]
struct SendCommandQueueEntry<K> {
    key: K,
    kind: SendCommandKind,
    fragments: VecDeque<Fragment>,
}

#[derive(Debug)]
struct SendCommandProgress<K> {
    key: K,
    kind: SendCommandKind,
    // If defined we need to wait for something before we can send `next_fragments`.
    blocked_reason: Option<SendCommandBlockedReason>,
    // The fragments that need to be sent.
    next_fragments: VecDeque<Fragment>,
}

#[derive(Debug)]
enum SendCommandBlockedReason {
    WaitForLiteralAck {
        // The bytes of the literal.
        data: Vec<u8>,
        // Was the literal already acknowledged by a `Continue` from the server?
        received_continue: bool,
    },
    // TODO(#105)
    WaitForAuthenticateData {
        // Was the authenticate data already requested by the server?
        received_continue: bool,
        // The authenticate data provided by the client flow user.
        // Should only be set when requested by the server.
        authenticate_data: Option<AuthenticateData>,
    },
    Idle {
        // Has the server already sent a `Continue`?
        received_continue: bool,
        // The `IdleDone` provided by the client flow user.
        // Should only be set after a `Continue` was received from the server.
        idle_done: Option<IdleDone>,
    },
}