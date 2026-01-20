//! PDA Seeds Vulnerability - Anchor Program
//!
//! Demonstrates weak PDA seed construction that allows attackers to
//! create predictable or colliding accounts.
//!
//! VULNERABILITY: Using easily guessable or insufficient seeds for PDAs.
//! ATTACK: Attacker pre-computes PDA with known seeds, front-runs creation.

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod error;
pub mod secure;
pub mod state;
pub mod vulnerable;

use secure::*;
use vulnerable::*;

declare_id!("Cd9nrvpnf83Yfn2B3rV8sFP3TcAY3MTsZtyXgHWwdQ1k");

#[program]
pub mod pda_seeds {
    use super::*;

    /// VULNERABLE: Create a user account with weak seeds (only user pubkey)
    /// Predictable PDA - anyone can compute it
    pub fn vulnerable_create_user(ctx: Context<VulnerableCreateUser>) -> Result<()> {
        ctx.accounts.create_user(&ctx.bumps)
    }

    /// VULNERABLE: Update user data - vulnerable to seed collision
    pub fn vulnerable_update(ctx: Context<VulnerableUpdate>, data: u64) -> Result<()> {
        ctx.accounts.update(data)
    }

    /// SECURE: Create user with strong seeds (includes random nonce)
    pub fn secure_create_user(ctx: Context<SecureCreateUser>, nonce: u64) -> Result<()> {
        ctx.accounts.create_user(&ctx.bumps, nonce)
    }

    /// SECURE: Update with verified PDA derivation
    pub fn secure_update(ctx: Context<SecureUpdate>, data: u64) -> Result<()> {
        ctx.accounts.update(data)
    }
}
