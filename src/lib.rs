//! whn-core — World-Humne-Network protocol core (spec draft v0.1).
//!
//! Language-neutral spec lives in `docs/protocol.md`. This crate is the
//! reference implementation of:
//! - identity (Ed25519 keypairs),
//! - Capability / Need cards (canonical JSON, blake3 ids),
//! - signing and verification.
//! - deterministic local candidate matching and signed attestation ranking.

pub mod attestation;
pub mod card;
pub mod crypto;
pub mod error;
pub mod matcher;
pub mod ranking;

/// Protocol spec version implemented by this crate.
pub const SPEC_VERSION: &str = "whn/0.1";
