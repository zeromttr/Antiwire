//! Async client for the [TypeSafe AI](https://typesafe.ai) API.
//!
//! This crate follows the `TypeSafe` Python SDK: the same request validation, wire
//! format, error messages, and retry policy. It is async-only and does not talk
//! to the Antiwire daemon. From synchronous code, drive it with
//! [`tokio::runtime::Runtime::block_on`].
//!
//! ```no_run
//! use antiwire_aibackend::{JsonContent, Noul, Questions, TypeSafeClient};
//!
//! # async fn example() -> antiwire_aibackend::Result<()> {
//! let client = TypeSafeClient::builder().api_key("key").build()?;
//! let questions = Questions::new().ask(
//!     "billing",
//!     Noul::new().instructions(JsonContent::text("Is this about billing?")),
//! );
//! let response = client
//!     .system_one(&JsonContent::text("I was charged twice."), &questions)
//!     .await?;
//! let _ = response;
//! # Ok(())
//! # }
//! ```

mod client;
mod config;
mod error;
mod questions;
mod response;
mod retry;
mod transport;

pub use client::{CallOverrides, ClientBuilder, Models, TypeSafeClient};
pub use config::{
    resolved_base_url, API_KEY_ENV, BASE_URL_ENV, DEFAULT_BASE_URL, DEFAULT_MODEL,
    DEFAULT_MODEL_ENV, DEFAULT_TIMEOUT,
};
pub use error::{ApiError, ApiErrorKind, Error, ErrorBody};
pub use questions::{Choice, JsonContent, Noul, NoulCriteria, Question, Questions, Score};
pub use response::{
    Answer, ChoiceAnswer, ListModelsResponse, ModelMetadata, NoulAnswer, ScoreAnswer,
    SystemOneResponse, Usage,
};
pub use retry::RetryPolicy;

/// A [`TypeSafeClient`](crate::TypeSafeClient) result.
pub type Result<T> = std::result::Result<T, Error>;
