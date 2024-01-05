use std::borrow::Cow;

use imap_codec::imap_types::{auth::AuthMechanism, core::Tag, secret::Secret};

#[derive(Debug)]
pub struct CommandAuthenticate {
    pub tag: Tag<'static>,
    pub mechanism: AuthMechanism<'static>,
    pub initial_response: Option<Secret<Cow<'static, [u8]>>>,
}
