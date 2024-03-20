use bounded_static::IntoBoundedStatic;
use bytes::Buf;
use imap_codec::decode::Decoder;

use crate::stream::{AnyStream, ReadBuffer, ReadError};

pub struct ReceiveState<C> {
    codec: C,
    crlf_relaxed: bool,
    next_fragment: NextFragment,
    // How many bytes in the parse buffer do we already have checked?
    // This is important if we need multiple attempts to read from the underlying
    // stream before the message is completely received.
    seen_bytes: usize,
    // Used for reading the current message from the stream.
    // Its length should always be equal to or greater than `seen_bytes`.
    read_buffer: ReadBuffer,
}

impl<C> ReceiveState<C> {
    pub fn new(codec: C, crlf_relaxed: bool, read_buffer: ReadBuffer) -> Self {
        Self {
            codec,
            crlf_relaxed,
            next_fragment: NextFragment::start_new_line(),
            seen_bytes: 0,
            read_buffer,
        }
    }

    pub fn start_literal(&mut self, length: u32) {
        self.next_fragment = NextFragment::Literal { length };
        self.read_buffer.bytes.reserve(length as usize);
    }

    pub fn finish_message(&mut self) {
        self.read_buffer.bytes.advance(self.seen_bytes);
        self.seen_bytes = 0;
        self.next_fragment = NextFragment::start_new_line();
    }

    pub fn discard_message(&mut self) -> Box<[u8]> {
        let discarded_bytes = self.read_buffer.bytes[..self.seen_bytes].into();
        self.finish_message();
        discarded_bytes
    }

    pub fn discard_all_bytes(&mut self) -> Box<[u8]> {
        self.seen_bytes = self.read_buffer.bytes.len();
        self.discard_message()
    }

    pub async fn progress(&mut self, stream: &mut AnyStream) -> Result<ReceiveEvent<C>, ReadError>
    where
        C: Decoder,
        for<'a> C::Message<'a>: IntoBoundedStatic<Static = C::Message<'static>>,
        for<'a> C::Error<'a>: IntoBoundedStatic<Static = C::Error<'static>>,
    {
        loop {
            match self.next_fragment {
                NextFragment::Line { seen_bytes_in_line } => {
                    if let Some(event) = self.progress_line(stream, seen_bytes_in_line).await? {
                        return Ok(event);
                    }
                }
                NextFragment::Literal { length } => {
                    self.progress_literal(stream, length).await?;
                }
            };
        }
    }

    async fn progress_line(
        &mut self,
        stream: &mut AnyStream,
        seen_bytes_in_line: usize,
    ) -> Result<Option<ReceiveEvent<C>>, ReadError>
    where
        C: Decoder,
        for<'a> C::Message<'a>: IntoBoundedStatic<Static = C::Message<'static>>,
        for<'a> C::Error<'a>: IntoBoundedStatic<Static = C::Error<'static>>,
    {
        let Some(crlf_result) = find_crlf(
            &self.read_buffer.bytes[self.seen_bytes..],
            seen_bytes_in_line,
            self.crlf_relaxed,
        ) else {
            // No full line received yet, more data needed.

            // Mark the bytes of the partial line as seen.
            let seen_bytes_in_line = self.read_buffer.bytes.len() - self.seen_bytes;
            self.next_fragment = NextFragment::Line { seen_bytes_in_line };

            // Read more data.
            stream.read(&mut self.read_buffer).await?;

            return Ok(None);
        };

        // Mark the all bytes of the current line as seen.
        self.seen_bytes += crlf_result.lf_position + 1;
        self.next_fragment = NextFragment::start_new_line();

        if crlf_result.expected_crlf_got_lf {
            return Ok(Some(ReceiveEvent::ExpectedCrlfGotLf));
        }

        // Try to parse the whole message from the start (including the new line).
        // TODO(#129): If the message is really long and we need multiple attempts to receive it,
        //             then this is O(n^2). IMO this can be only fixed by using a generator-like
        //             decoder.
        match self
            .codec
            .decode(&self.read_buffer.bytes[..self.seen_bytes])
        {
            Ok((remaining, message)) => {
                assert!(remaining.is_empty());
                Ok(Some(ReceiveEvent::DecodingSuccess(message.into_static())))
            }
            Err(error) => Ok(Some(ReceiveEvent::DecodingFailure(error.into_static()))),
        }
    }

    async fn progress_literal(
        &mut self,
        stream: &mut AnyStream,
        literal_length: u32,
    ) -> Result<(), ReadError> {
        let unseen_bytes = self.read_buffer.bytes.len() - self.seen_bytes;

        if unseen_bytes < literal_length as usize {
            // We did not receive enough bytes for the literal yet.
            stream.read(&mut self.read_buffer).await?;
        } else {
            // We received enough bytes for the literal.
            // Now we can continue reading the next line.
            self.next_fragment = NextFragment::start_new_line();
            self.seen_bytes += literal_length as usize;
        }

        Ok(())
    }

    pub fn change_codec<D>(self, codec: D) -> ReceiveState<D> {
        ReceiveState::new(codec, self.crlf_relaxed, self.read_buffer)
    }
}

pub enum ReceiveEvent<C: Decoder> {
    DecodingSuccess(C::Message<'static>),
    DecodingFailure(C::Error<'static>),
    ExpectedCrlfGotLf,
}

/// The next fragment that will be read...
#[derive(Clone, Copy, Debug)]
enum NextFragment {
    // ... is a line.
    //
    // Note: A message always starts (and ends) with a line.
    Line {
        // How many bytes in the current line do we already have checked?
        // This is important if we need multiple attempts to read from the underlying
        // stream before the line is completely received.
        seen_bytes_in_line: usize,
    },
    // ... is a literal with the given length.
    Literal {
        length: u32,
    },
}

impl NextFragment {
    fn start_new_line() -> Self {
        Self::Line {
            seen_bytes_in_line: 0,
        }
    }
}

/// A line ending for the current line was found.
struct FindCrlfResult {
    // The position of the `\n` symbol
    lf_position: usize,
    // Is the line ending `\n` even though we expected `\r\n`?
    expected_crlf_got_lf: bool,
}

/// Finds the line ending (`\n` or `\r\n`) for the current line.
///
/// Parameters:
/// - `buf`: The buffer that contains the current line starting at index 0.
/// - `start`: At this index the search for `\n` will start. Note that the `\r` might be located
//     before this index.
/// - `crlf_relaxed`: Whether the accepted line ending is `\n` or `\r\n`.
fn find_crlf(buf: &[u8], start: usize, crlf_relaxed: bool) -> Option<FindCrlfResult> {
    let lf_position = start + buf[start..].iter().position(|item| *item == b'\n')?;
    let expected_crlf_got_lf = !crlf_relaxed && buf[lf_position.saturating_sub(1)] != b'\r';
    Some(FindCrlfResult {
        lf_position,
        expected_crlf_got_lf,
    })
}
