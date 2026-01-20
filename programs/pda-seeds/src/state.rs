//! State definitions for PDA Seeds program

use anchor_lang::prelude::*;

/// User account with weak seeds (vulnerable version)
#[account]
#[derive(InitSpace)]
pub struct WeakUserAccount {
    pub owner: Pubkey,
    pub data: u64,
    pub bump: u8,
}

/// User account with strong seeds (secure version)
#[account]
#[derive(InitSpace)]
pub struct StrongUserAccount {
    pub owner: Pubkey,
    pub nonce: u64, // Random nonce makes PDA unpredictable
    pub data: u64,
    pub bump: u8,
}
