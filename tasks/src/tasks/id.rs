use imap_types::{
    command::CommandBody,
    core::{IString, NString},
    response::{Data, StatusBody, StatusKind},
};

use crate::{SchedulerError, Task};

pub type IdTaskOutput = Option<Vec<(IString<'static>, NString<'static>)>>;

#[derive(Clone, Debug)]
pub struct IdTask {
    parameters: Option<Vec<(IString<'static>, NString<'static>)>>,
    output: IdTaskOutput,
}

impl IdTask {
    #[cfg_attr(debug_assertions, tracing::instrument)]
    pub fn new(parameters: Vec<(IString<'static>, NString<'static>)>) -> Self {
        Self {
            parameters: Some(parameters),
            output: None,
        }
    }
}

impl Task for IdTask {
    type Output = Result<IdTaskOutput, SchedulerError>;

    #[cfg_attr(debug_assertions, tracing::instrument(skip(self)))]
    fn command_body(&self) -> CommandBody<'static> {
        CommandBody::Id {
            parameters: self.parameters.clone(),
        }
    }

    #[cfg_attr(debug_assertions, tracing::instrument(skip(self)))]
    fn process_data(&mut self, data: Data<'static>) -> Option<Data<'static>> {
        if let Data::Id { parameters } = data {
            self.output = parameters;
            None
        } else {
            Some(data)
        }
    }

    #[cfg_attr(debug_assertions, tracing::instrument(skip(self)))]
    fn process_tagged(self, status_body: StatusBody<'static>) -> Self::Output {
        match status_body.kind {
            StatusKind::Ok => Ok(self.output),
            StatusKind::No => Err(SchedulerError::No(status_body)),
            StatusKind::Bad => Err(SchedulerError::Bad(status_body)),
        }
    }
}