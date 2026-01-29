//! Multisig as Payer Vulnerability - Anchor Program
//!
//! Demonstrates why PDA authorities cannot act as payers for account
//! creation. PDAs cannot sign system program transfer instructions.
//!
//! VULNERABILITY: Using a multisig PDA as the payer in `init` constraint.
//! RESULT: Transaction always fails with "unauthorized signer" error.
//!
//! Source: J4X_Security (2026)

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod error;
pub mod secure;
pub mod state;
pub mod vulnerable;

use secure::*;
use vulnerable::*;

declare_id!("Fvat4mBGBnCbz7eGpTYUUJq2gQ4bwevt5AYhAVibmjC2");

#[program]
pub mod multisig_payer {
    use super::*;

    /// Initialize the DAO config with a multisig PDA as authority
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.initialize(&ctx.bumps)
    }

    /// VULNERABLE: Create proposal with multisig PDA as payer
    /// This will ALWAYS fail because PDAs cannot sign system transfers
    pub fn vulnerable_create_proposal(
        ctx: Context<VulnerableCreateProposal>,
        proposal_id: u64,
        title: String,
    ) -> Result<()> {
        ctx.accounts.create_proposal(&ctx.bumps, proposal_id, title)
    }

    /// SECURE: Create proposal with separate rent payer
    /// Multisig still controls permissions, but a signer pays rent
    pub fn secure_create_proposal(
        ctx: Context<SecureCreateProposal>,
        proposal_id: u64,
        title: String,
    ) -> Result<()> {
        ctx.accounts.create_proposal(&ctx.bumps, proposal_id, title)
    }

    /// Vote on a proposal
    pub fn vote(ctx: Context<Vote>, approve: bool) -> Result<()> {
        ctx.accounts.vote(approve)
    }
}
