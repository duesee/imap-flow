use bounded_static::IntoBoundedStatic;
use bytes::{Buf, BytesMut};
use imap_codec::decode::Decoder;

use crate::stream::{AnyStream, StreamError};

#[derive(Debug)]
pub struct ReceiveState<C: Decoder> {
    codec: C,
    crlf_relaxed: bool,
    next_fragment: NextFragment,
    // How many bytes in the parse buffer do we already have checked?
    // This is important if we need multiple attempts to read from the underlying
    // stream before the message is completely received.
    seen_bytes: usize,
    // Used for reading the current message from the stream.
    // Its length should always be equal to or greater than `seen_bytes`.
    read_buffer: BytesMut,
}

impl<C: Decoder> ReceiveState<C> {
    pub fn new(codec: C, crlf_relaxed: bool, read_buffer: BytesMut) -> Self {
        Self {
            codec,
            crlf_relaxed,
            next_fragment: NextFragment::default(),
            seen_bytes: 0,
            read_buffer,
        }
    }

    pub fn start_literal(&mut self, length: u32) {
        self.next_fragment = NextFragment::Literal { length };
        self.read_buffer.reserve(length as usize);
    }

    pub fn finish_message(&mut self) {
        self.read_buffer.advance(self.seen_bytes);
        self.seen_bytes = 0;
        self.next_fragment = NextFragment::default();
    }

    pub fn discard_message(&mut self) -> Box<[u8]> {
        let discarded_bytes = self.read_buffer[..self.seen_bytes].into();
        self.finish_message();
        discarded_bytes
    }

    pub async fn progress(&mut self, stream: &mut AnyStream) -> Result<ReceiveEvent<C>, StreamError>
    where
        for<'a> C::Message<'a>: IntoBoundedStatic<Static = C::Message<'static>>,
        for<'a> C::Error<'a>: IntoBoundedStatic<Static = C::Error<'static>>,
    {
        loop {
            match self.next_fragment {
                NextFragment::Line => {
                    if let Some(event) = self.progress_line(stream).await? {
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
    ) -> Result<Option<ReceiveEvent<C>>, StreamError>
    where
        for<'a> C::Message<'a>: IntoBoundedStatic<Static = C::Message<'static>>,
        for<'a> C::Error<'a>: IntoBoundedStatic<Static = C::Error<'static>>,
    {
        // TODO: If the line is really long and we need multiple attempts to receive it, then this is O(n^2).
        //       This could be fixed by setting seen bytes in the None case
        let crlf_result = match find_crlf(&self.read_buffer[self.seen_bytes..], self.crlf_relaxed) {
            Some(crlf_result) => crlf_result,
            None => {
                // No full line received yet, more data needed.
                stream.read(&mut self.read_buffer).await?;
                return Ok(None);
            }
        };

        // Mark the all bytes of the current line as seen.
        self.seen_bytes += crlf_result.lf_position + 1;

        if crlf_result.expected_crlf_got_lf {
            return Ok(Some(ReceiveEvent::ExpectedCrlfGotLf));
        }

        // Try to parse the whole message from the start (including the new line).
        // TODO: If the message is really long and we need multiple attempts to receive it, then this is O(n^2)
        //       IMO this can be only fixed by using a generator-like decoder
        match self.codec.decode(&self.read_buffer[..self.seen_bytes]) {
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
    ) -> Result<(), StreamError> {
        let unseen_bytes = self.read_buffer.len() - self.seen_bytes;

        if unseen_bytes < literal_length as usize {
            // We did not receive enough bytes for the literal yet.
            stream.read(&mut self.read_buffer).await?;
        } else {
            // We received enough bytes for the literal.
            // Now we can continue reading the next line.
            self.next_fragment = NextFragment::Line;
            self.seen_bytes += literal_length as usize;
        }

        Ok(())
    }

    pub fn change_codec<D: Decoder>(self, codec: D) -> ReceiveState<D> {
        ReceiveState::new(codec, self.crlf_relaxed, self.read_buffer)
    }
}

pub enum ReceiveEvent<C: Decoder> {
    DecodingSuccess(C::Message<'static>),
    DecodingFailure(C::Error<'static>),
    ExpectedCrlfGotLf,
}

// The next fragment that will be read...
#[derive(Clone, Copy, Debug, Default)]
enum NextFragment {
    // ... is a line.
    //
    // Note: A message always starts (and ends) with a line.
    #[default]
    Line,
    // ... is a literal with the given length.
    Literal {
        length: u32,
    },
}

// A line ending for the current line was found.
struct FindCrlfResult {
    // The position of the `\n` symbol
    lf_position: usize,
    // Is the line ending `\n` even though we expected `\r\n`?
    expected_crlf_got_lf: bool,
}

// Finds the line ending for the current line.
// Depending on `crlf_relaxed` the accepted line ending is `\n` (true) or `\r\n` (false).
fn find_crlf(buf: &[u8], crlf_relaxed: bool) -> Option<FindCrlfResult> {
    let lf_position = buf.iter().position(|item| *item == b'\n')?;
    let expected_crlf_got_lf = !crlf_relaxed && buf[lf_position.saturating_sub(1)] != b'\r';
    Some(FindCrlfResult {
        lf_position,
        expected_crlf_got_lf,
    })
}
