use anchor_lang::prelude::*;

// ---------------------------------------------------------------------------
// Vault State
// ---------------------------------------------------------------------------
// Stores lamports with an authority who can withdraw.
// ---------------------------------------------------------------------------

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub bump: u8,
}
