use std::{fs::File, io::BufReader, path::Path};

use imap_codec::imap_types::{
    auth::AuthMechanism,
    core::NonEmptyVec,
    response::{
        Bye, Capability, Code, CommandContinuationRequest, CommandContinuationRequestBasic, Data,
        Greeting, Status, StatusBody, Tagged,
    },
};
use rustls::{Certificate, PrivateKey};
use thiserror::Error;
use tracing::warn;

pub enum ControlFlow {
    Continue,
    Abort,
}

// Remove unsupported capabilities in a greetings `Code::Capability`.
pub fn filter_capabilities_in_greeting(greeting: &mut Greeting) {
    if let Some(Code::Capability(capabilities)) = &mut greeting.code {
        let filtered = filter_capabilities(capabilities.clone());

        if *capabilities != filtered {
            warn!(
                before=?capabilities,
                after=?filtered.clone(),
                "Filtered capabilities in greeting",
            );
            *capabilities = filtered;
        }
    }
}

// Remove unsupported capabilities in a `Data::Capability`.
pub fn filter_capabilities_in_data(data: &mut Data) {
    if let Data::Capability(capabilities) = data {
        let filtered = filter_capabilities(capabilities.clone());

        if *capabilities != filtered {
            warn!(
                before=?capabilities,
                after=?filtered,
                "Filtered capabilities in data",
            );
            *capabilities = filtered;
        }
    }
}

// Remove unsupported capabilities in a status' `Code::Capability`.
pub fn filter_capabilities_in_status(status: &mut Status) {
    if let Status::Tagged(Tagged {
        body:
            StatusBody {
                code: Some(Code::Capability(capabilities)),
                ..
            },
        ..
    })
    | Status::Untagged(StatusBody {
        code: Some(Code::Capability(capabilities)),
        ..
    })
    | Status::Bye(Bye {
        code: Some(Code::Capability(capabilities)),
        ..
    }) = status
    {
        let filtered = filter_capabilities(capabilities.clone());

        if *capabilities != filtered {
            warn!(
                before=?capabilities,
                after=?filtered,
                "Filtered capabilities in status",
            );
            *capabilities = filtered;
        }
    }
}

// Remove unsupported capabilities in command continuation request response.
pub fn filter_capabilities_in_continuation(continuation: &mut CommandContinuationRequest) {
    if let CommandContinuationRequest::Basic(basic) = continuation {
        if let Some(Code::Capability(capabilities)) = basic.code() {
            let capabilities = filter_capabilities(capabilities.clone());

            *basic = CommandContinuationRequestBasic::new(
                Some(Code::Capability(capabilities)),
                basic.text().clone(),
            )
            .unwrap();
        }
    }
}

// Remove unsupported capabilities in a capability list.
fn filter_capabilities(capabilities: NonEmptyVec<Capability>) -> NonEmptyVec<Capability> {
    let filtered: Vec<_> = capabilities
        .into_iter()
        .filter(|capability| match capability {
            Capability::Imap4Rev1 => true,
            Capability::Auth(auth_mechanism) if is_auth_mechanism_proxyable(auth_mechanism) => true,
            Capability::SaslIr => true,
            Capability::Quota | Capability::QuotaRes(_) | Capability::QuotaSet => true,
            Capability::Move => true,
            _ => false,
        })
        .collect();

    NonEmptyVec::try_from(filtered).unwrap_or(NonEmptyVec::from(Capability::Imap4Rev1))
}

fn is_auth_mechanism_proxyable(auth_mechanism: &AuthMechanism) -> bool {
    match auth_mechanism {
        // Can be proxied, terminated, or upgraded
        AuthMechanism::Plain | AuthMechanism::Login | AuthMechanism::XOAuth2 => true,
        // Can be proxied
        AuthMechanism::ScramSha1 | AuthMechanism::ScramSha256 => true,
        // Cannot be proxied (due to session binding)
        AuthMechanism::ScramSha1Plus | AuthMechanism::ScramSha256Plus => false,
        // Unknown
        _ => false,
    }
}

// -------------------------------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Error processing \"{path}\"")]
    Io {
        #[source]
        source: std::io::Error,
        path: String,
    },
    #[error("Expected 1 key in \"{path}\", found {found}")]
    UnexpectedKeyCount { path: String, found: usize },
}

pub fn load_certificate_chain_pem<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<Certificate>, IdentityError> {
    let display_path = path.as_ref().display().to_string();

    let mut reader = BufReader::new(File::open(path).map_err(|error| IdentityError::Io {
        source: error,
        path: display_path.clone(),
    })?);

    rustls_pemfile::certs(&mut reader)
        .map(|res| {
            res.map(|der| Certificate(der.to_vec()))
                .map_err(|source| IdentityError::Io {
                    source,
                    path: display_path.clone(),
                })
        })
        .collect()
}

pub fn load_leaf_key_pem<P: AsRef<Path>>(path: P) -> Result<PrivateKey, IdentityError> {
    let display_path = path.as_ref().display().to_string();

    let mut reader = BufReader::new(File::open(&path).map_err(|source| IdentityError::Io {
        source,
        path: display_path.clone(),
    })?);

    let mut keys = vec![];

    for key in rustls_pemfile::pkcs8_private_keys(&mut reader) {
        let key = key.map_err(|source| IdentityError::Io {
            source,
            path: display_path.clone(),
        })?;
        keys.push(PrivateKey(key.secret_pkcs8_der().to_vec()));
    }

    match keys.len() {
        1 => Ok(keys.remove(0)),
        found => Err(IdentityError::UnexpectedKeyCount {
            path: display_path,
            found,
        }),
    }
}
