//! Error definitions

use anchor_lang::prelude::*;

#[error_code]
pub enum StakeError {
    #[msg("Account already initialized")]
    AlreadyInitialized,
    #[msg("Invalid deposit amount")]
    InvalidAmount,
    #[msg("Unauthorized")]
    Unauthorized,
}
