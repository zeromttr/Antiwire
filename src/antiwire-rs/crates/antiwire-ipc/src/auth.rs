//! IPC token resolution and request authorization.

use std::path::Path;

use data_encoding::HEXUPPER;
use subtle::ConstantTimeEq;
use tonic::{Request, Status};
use zeroize::Zeroizing;

use crate::error::IpcError;

/// Metadata key for the shared IPC token (gRPC lowercases keys).
pub(crate) use antiwire_proto::TOKEN_HEADER;

/// Daemon side: generate a fresh token and publish it at `path` for the
/// client group.
///
/// A new token on every start means a token copied while it was readable by more
/// accounts, before the file was restricted, stops working. The client re-reads the
/// file when it changes, so a rotation costs it at most one failed request.
pub(crate) fn publish_new_token(path: &Path) -> Result<Zeroizing<String>, IpcError> {
    use crate::atomic_file::{write_token, TokenAccess};

    let token = generate_token()?;
    match write_token(path, token.as_bytes())? {
        TokenAccess::ClientGroup | TokenAccess::DeveloperProfile => {}
        TokenAccess::AdminsOnly => tracing::error!(
            group = antiwire_proto::IPC_CLIENT_GROUP,
            path = %path.display(),
            "the IPC client group does not exist, so only administrators can use the \
             daemon; reinstall Antiwire or create the group and add your account to it"
        ),
    }
    Ok(token)
}

/// Validates the `x-antiwire-token` metadata entry on an incoming request.
#[allow(clippy::result_large_err)] // `tonic::Status` is the gRPC auth error type.
pub(crate) fn authorize_request(
    metadata: &tonic::metadata::MetadataMap,
    expected: &str,
) -> Result<(), Status> {
    let provided = metadata
        .get(TOKEN_HEADER)
        .and_then(|value| value.to_str().ok());

    match provided {
        Some(token) if token.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1 => Ok(()),
        _ => Err(Status::unauthenticated("Missing or invalid IPC token.")),
    }
}

/// Tower interceptor that rejects calls without the shared IPC token.
#[derive(Clone)]
pub(crate) struct AuthInterceptor {
    expected: Zeroizing<String>,
}

impl AuthInterceptor {
    #[cfg(test)]
    pub(crate) fn new(token: impl Into<String>) -> Self {
        Self {
            expected: Zeroizing::new(token.into()),
        }
    }

    pub(crate) fn from_zeroizing(token: Zeroizing<String>) -> Self {
        Self { expected: token }
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        authorize_request(request.metadata(), &self.expected)?;
        Ok(request)
    }
}

fn generate_token() -> Result<Zeroizing<String>, IpcError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|error| IpcError::Random(error.to_string()))?;
    Ok(Zeroizing::new(HEXUPPER.encode(bytes.as_ref())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tonic::metadata::MetadataMap;

    fn valid_token(token: &str) -> bool {
        token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    #[test]
    fn authorize_accepts_matching_token() {
        let mut metadata = MetadataMap::new();
        metadata.insert(TOKEN_HEADER, "secret-token".parse().unwrap());

        authorize_request(&metadata, "secret-token").expect("token should be accepted");
    }

    #[test]
    fn authorize_rejects_missing_token() {
        let metadata = MetadataMap::new();
        let err = authorize_request(&metadata, "secret-token").expect_err("missing token");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn authorize_rejects_wrong_token() {
        let mut metadata = MetadataMap::new();
        metadata.insert(TOKEN_HEADER, "wrong".parse().unwrap());

        let err = authorize_request(&metadata, "secret-token").expect_err("wrong token");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    /// Every start publishes a fresh token, so one copied earlier stops working.
    #[test]
    fn each_start_publishes_a_new_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let token_path = dir.path().join("ipc.token");

        let first = publish_new_token(&token_path).expect("first token");
        let second = publish_new_token(&token_path).expect("second token");
        assert_ne!(first, second);
        assert!(valid_token(&second));
        assert_eq!(
            fs::read_to_string(token_path).unwrap().trim(),
            second.as_str()
        );
    }
}
