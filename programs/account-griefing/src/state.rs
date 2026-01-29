//! State definitions for staking accounts

use anchor_lang::prelude::*;

/// Stake account storing user's staked amount
#[account]
#[derive(InitSpace)]
pub struct StakeAccount {
    /// Owner of the stake
    pub owner: Pubkey,
    /// Amount staked
    pub amount: u64,
    /// Bump seed for PDA derivation
    pub bump: u8,
    /// Whether this account is initialized
    pub is_initialized: bool,
}

/// Stake account with nonce for secure PDA derivation
#[account]
#[derive(InitSpace)]
pub struct SecureStakeAccount {
    /// Owner of the stake
    pub owner: Pubkey,
    /// Amount staked
    pub amount: u64,
    /// Nonce used in PDA derivation
    pub nonce: u64,
    /// Bump seed for PDA derivation
    pub bump: u8,
    /// Whether this account is initialized
    pub is_initialized: bool,
}
