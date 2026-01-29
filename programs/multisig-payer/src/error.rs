//! Error definitions

use anchor_lang::prelude::*;

#[error_code]
pub enum DaoError {
    #[msg("Unauthorized - not the DAO authority")]
    Unauthorized,
    #[msg("DAO already initialized")]
    AlreadyInitialized,
    #[msg("Proposal title too long")]
    TitleTooLong,
    #[msg("Proposal already executed")]
    AlreadyExecuted,
}
