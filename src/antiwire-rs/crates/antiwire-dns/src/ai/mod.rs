//! Shared AI decision coordination for proactive and retroactive modes.
//!
//! Both DNS modes use this one service: saved-decision lookup, classification
//! of unknown domains, score-to-decision evaluation against current settings,
//! persistence, in-flight deduplication, and bounded background work.

pub(crate) mod classifier;
pub(crate) mod coordinator;
pub(crate) mod decision;

pub(crate) use classifier::AiBackendClassifier;
#[cfg(test)]
pub(crate) use classifier::Classifier;
pub(crate) use coordinator::{AiCoordinator, PostResponseWork};
pub(crate) use decision::{canonical_ai_key, AiPolicySnapshot};
