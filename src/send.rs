use std::collections::VecDeque;

use bytes::BytesMut;
use imap_codec::{
    encode::{Encoder, Fragment},
    imap_types::command::Command,
    CommandCodec,
};
use tokio::io::AsyncWriteExt;

use crate::stream::Stream;

pub struct SendCommandState<K> {
    codec: CommandCodec,
    // The commands that should be send.
    send_queue: VecDeque<SendCommandQueueEntry<K>>,
    // State of the command that is currently being sent.
    send_progress: Option<SendCommandProgress<K>>,
    // Used for writing the current command to the stream.
    // Should be empty if `send_progress` is `None`.
    write_buffer: BytesMut,
}

impl<K> SendCommandState<K> {
    pub fn new(codec: CommandCodec, write_buffer: BytesMut) -> Self {
        Self {
            codec,
            send_queue: VecDeque::new(),
            send_progress: None,
            write_buffer,
        }
    }

    pub fn enqueue(&mut self, key: K, command: Command<'_>) {
        let fragments = self.codec.encode(&command).collect();
        let entry = SendCommandQueueEntry { key, fragments };
        self.send_queue.push_back(entry);
    }

    pub fn command_in_progress(&self) -> Option<&K> {
        self.send_progress.as_ref().map(|x| &x.key)
    }

    pub fn abort_command(&mut self) {
        self.send_progress = None;
        self.write_buffer.clear();
    }

    pub fn continue_command(&mut self) {
        // TODO: Should we handle unexpected continues?
        let Some(write_progress) = self.send_progress.as_mut() else {
            return;
        };
        let Some(literal_progress) = write_progress.next_literal.as_mut() else {
            return;
        };
        if literal_progress.received_continue {
            return;
        }

        literal_progress.received_continue = true;
    }

    pub async fn progress(&mut self, stream: &mut Stream) -> Result<Option<K>, tokio::io::Error> {
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
                    next_literal: None,
                    next_fragments: entry.fragments,
                }
            }
        };
        let progress = self.send_progress.insert(progress);

        // Handle the outstanding literal first if there is one
        if let Some(literal_progress) = progress.next_literal.take() {
            if literal_progress.received_continue {
                // We received a `Continue` from the server, we can send the literal now
                self.write_buffer.extend(literal_progress.data);
            } else {
                // Delay this literal because we still wait for the `Continue` from the server
                progress.next_literal = Some(literal_progress);

                // Make sure that the line before the literal is sent completely to the server
                stream
                    .write_mut()
                    .write_all_buf(&mut self.write_buffer)
                    .await?;

                return Ok(None);
            }
        }

        // Handle the outstanding lines or literals
        let need_continue = loop {
            if let Some(fragment) = progress.next_fragments.pop_front() {
                match fragment {
                    Fragment::Line { data } => {
                        self.write_buffer.extend(data);
                    }
                    Fragment::Literal { data, mode: _mode } => {
                        // TODO: Handle `LITERAL{+,-}`.
                        // Delay this literal because we need to wait for a `Continue` from
                        // the server
                        progress.next_literal = Some(SendCommandLiteralProgress {
                            data,
                            received_continue: false,
                        });
                        break true;
                    }
                }
            } else {
                break false;
            }
        };

        // Send the bytes of the command to the server
        stream
            .write_mut()
            .write_all_buf(&mut self.write_buffer)
            .await?;

        if need_continue {
            Ok(None)
        } else {
            // Command was sent completely
            Ok(self.send_progress.take().map(|progress| progress.key))
        }
    }
}

struct SendCommandQueueEntry<K> {
    key: K,
    fragments: VecDeque<Fragment>,
}

struct SendCommandProgress<K> {
    key: K,
    // If defined this literal need to be sent before `next_fragments`.
    next_literal: Option<SendCommandLiteralProgress>,
    // The fragments that need to be sent.
    next_fragments: VecDeque<Fragment>,
}

struct SendCommandLiteralProgress {
    // The bytes of the literal.
    data: Vec<u8>,
    // Was the literal already acknowledged by a `Continue` from the server?
    received_continue: bool,
}

pub struct SendResponseState<C: Encoder, K> {
    codec: C,
    // The responses that should be sent.
    send_queue: VecDeque<SendResponseQueueEntry<K>>,
    // Key of the response that is currently being sent.
    send_in_progress_key: Option<K>,
    // Used for writing the current response to the stream.
    // Should be empty if `send_in_progress_key` is `None`.
    write_buffer: BytesMut,
}

impl<C: Encoder, K> SendResponseState<C, K> {
    pub fn new(codec: C, write_buffer: BytesMut) -> Self {
        Self {
            codec,
            send_queue: VecDeque::new(),
            send_in_progress_key: None,
            write_buffer,
        }
    }

    pub fn enqueue(&mut self, key: K, response: C::Message<'_>) {
        let fragments = self.codec.encode(&response).collect();
        let entry = SendResponseQueueEntry { key, fragments };
        self.send_queue.push_back(entry);
    }

    pub fn finish(mut self) -> BytesMut {
        self.write_buffer.clear();
        self.write_buffer
    }

    pub async fn progress(&mut self, stream: &mut Stream) -> Result<Option<K>, tokio::io::Error> {
        let send_in_progress_key = match self.send_in_progress_key.take() {
            Some(key) => {
                // We are currently sending a response. This sending process was
                // previously aborted because the `Future` was dropped while sending.
                key
            }
            None => {
                let Some(entry) = self.send_queue.pop_front() else {
                    // There is currently no response that need to be sent
                    return Ok(None);
                };

                // Push the response to the write buffer
                for fragment in entry.fragments {
                    let data = match fragment {
                        Fragment::Line { data } => data,
                        // TODO: Handle `LITERAL{+,-}`.
                        Fragment::Literal { data, mode: _mode } => data,
                    };
                    self.write_buffer.extend(data);
                }

                entry.key
            }
        };
        self.send_in_progress_key = Some(send_in_progress_key);

        // Send all bytes of current response
        stream
            .write_mut()
            .write_all_buf(&mut self.write_buffer)
            .await?;

        // response was sent completely
        Ok(self.send_in_progress_key.take())
    }
}

struct SendResponseQueueEntry<K> {
    key: K,
    fragments: Vec<Fragment>,
}
