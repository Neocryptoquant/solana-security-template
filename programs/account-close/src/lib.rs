//! Account Close Vulnerability - Anchor Program
//!
//! Demonstrates the "Account Revival" vulnerability after closure.
//!
//! VULNERABILITY: After closing an account, an attacker can "revive" it
//! by sending lamports to it within the same transaction. The program
//! may then re-read the stale data or allow re-initialization.

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod error;
pub mod secure;
pub mod state;
pub mod vulnerable;

use secure::*;
use vulnerable::*;

declare_id!("Cnji8fAoqzDyJaR1D2MXyk2hgyixZBoSf5UmN6SegpFf");

#[program]
pub mod account_close {
    use super::*;

    /// Initialize a user data account
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.initialize(&ctx.bumps)
    }

    /// VULNERABLE: Close account without zeroing data
    /// Vulnerable to revival attack
    pub fn vulnerable_close(ctx: Context<VulnerableClose>) -> Result<()> {
        ctx.accounts.close()
    }

    /// SECURE: Close account properly with data zeroing
    pub fn secure_close(ctx: Context<SecureClose>) -> Result<()> {
        ctx.accounts.close()
    }

    /// Use account data (to demonstrate revival exploit)
    pub fn use_data(ctx: Context<UseData>) -> Result<u64> {
        Ok(ctx.accounts.user_account.balance)
    }
}
