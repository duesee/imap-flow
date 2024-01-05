//! Collection of common IMAP tasks.
//!
//! The tasks here correspond to the invocation (and processing) of a single command.

use std::borrow::Cow;

use imap_codec::imap_types::{
    auth::{AuthMechanism, AuthenticateData},
    command::CommandBody,
    core::NonEmptyVec,
    response::{Bye, Capability, CommandContinuationRequest, Data, StatusBody, StatusKind},
    secret::Secret,
};

use crate::Task;

#[derive(Default)]
pub struct CapabilityTask {
    /// We use this as scratch space.
    capabilities: Option<NonEmptyVec<Capability<'static>>>,
}

impl Task for CapabilityTask {
    type Output = Result<NonEmptyVec<Capability<'static>>, &'static str>;

    fn command_body(&self) -> CommandBody<'static> {
        CommandBody::Capability
    }

    fn process_data(&mut self, data: Data<'static>) -> Option<Data<'static>> {
        match data {
            Data::Capability(capabilities) => {
                self.capabilities = Some(capabilities);
                None
            }
            unknown => Some(unknown),
        }
    }

    fn process_tagged(self, status_body: StatusBody<'static>) -> Self::Output {
        match status_body.kind {
            StatusKind::Ok => match self.capabilities {
                Some(capabilities) => Ok(capabilities),
                None => Err("missing REQUIRED untagged CAPABILITY"),
            },
            StatusKind::No => Err("unexpected NO result"),
            StatusKind::Bad => Err("command unknown or arguments invalid"),
        }
    }
}

#[derive(Default)]
pub struct LogoutTask {
    got_bye: bool,
}

impl Task for LogoutTask {
    type Output = Result<(), &'static str>;

    fn command_body(&self) -> CommandBody<'static> {
        CommandBody::Logout
    }

    fn process_bye(&mut self, _: Bye<'static>) -> Option<Bye<'static>> {
        self.got_bye = true;
        None
    }

    fn process_tagged(self, status_body: StatusBody<'static>) -> Self::Output {
        match status_body.kind {
            StatusKind::Ok => match self.got_bye {
                true => Ok(()),
                false => Err("missing REQUIRED untagged BYE"),
            },
            StatusKind::No => Err("unexpected NO result"),
            StatusKind::Bad => Err("command unknown or arguments invalid"),
        }
    }
}

pub struct AuthenticatePlainTask {
    line: Option<Vec<u8>>,
    ir: bool,
}

impl AuthenticatePlainTask {
    pub fn new(username: &str, password: &str, ir: bool) -> Self {
        Self {
            line: Some(format!("\x00{}\x00{}", username, password).into_bytes()),
            ir,
        }
    }
}

impl Task for AuthenticatePlainTask {
    type Output = Result<(), ()>;

    fn command_body(&self) -> CommandBody<'static> {
        CommandBody::Authenticate {
            mechanism: AuthMechanism::Plain,
            initial_response: if self.ir {
                // TODO: command_body must only be called once... hm...
                Some(Secret::new(Cow::Owned(self.line.clone().unwrap())))
            } else {
                None
            },
        }
    }

    fn process_continuation_authenticate(
        &mut self,
        _: CommandContinuationRequest<'static>,
    ) -> Result<AuthenticateData, CommandContinuationRequest<'static>> {
        if self.ir {
            Ok(AuthenticateData::Cancel)
        } else if let Some(line) = self.line.take() {
            Ok(AuthenticateData::Continue(Secret::new(line)))
        } else {
            Ok(AuthenticateData::Cancel)
        }
    }

    fn process_tagged(self, _: StatusBody<'static>) -> Self::Output {
        Ok(())
    }
}
