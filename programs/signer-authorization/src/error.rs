use anchor_lang::prelude::*;

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized: caller is not the vault authority")]
    UnauthorizedAuthority,
}
