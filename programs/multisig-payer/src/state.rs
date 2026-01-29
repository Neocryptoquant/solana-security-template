//! State definitions for DAO governance

use anchor_lang::prelude::*;

/// Maximum title length for proposals
pub const MAX_TITLE_LEN: usize = 64;

/// DAO configuration with multisig authority
#[account]
#[derive(InitSpace)]
pub struct DaoConfig {
    /// The multisig PDA that controls this DAO
    pub authority: Pubkey,
    /// Number of proposals created
    pub proposal_count: u64,
    /// Bump seed for the config PDA
    pub bump: u8,
    /// Whether the DAO is initialized
    pub is_initialized: bool,
}

/// Multisig treasury PDA
#[account]
#[derive(InitSpace)]
pub struct MultisigTreasury {
    /// The DAO this treasury belongs to
    pub dao: Pubkey,
    /// Bump seed for the treasury PDA  
    pub bump: u8,
}

/// A governance proposal
#[account]
#[derive(InitSpace)]
pub struct Proposal {
    /// Unique proposal ID
    pub id: u64,
    /// Proposal title
    #[max_len(64)]
    pub title: String,
    /// Creator of the proposal
    pub creator: Pubkey,
    /// Number of yes votes
    pub yes_votes: u64,
    /// Number of no votes
    pub no_votes: u64,
    /// Whether the proposal is executed
    pub executed: bool,
    /// Bump seed
    pub bump: u8,
}
