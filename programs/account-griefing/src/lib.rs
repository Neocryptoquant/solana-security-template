//! Account Creation Griefing Vulnerability - Anchor Program
//!
//! Demonstrates how attackers can DOS seed-based account creation by
//! pre-funding the target PDA with lamports.
//!
//! VULNERABILITY: create_account() reverts if target address has any lamports.
//! ATTACK: Attacker computes deterministic PDA, sends minimal lamports to block creation.
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

declare_id!("GWRZSqQP37DEg6R7hEmBHVBDyWJNVwRAPtDduwGhtQqp");

#[program]
pub mod account_griefing {
    use super::*;

    /// VULNERABLE: Create stake account with predictable, deterministic seeds.
    /// Attacker can pre-fund PDA to block account creation permanently.
    pub fn vulnerable_create_stake(ctx: Context<VulnerableCreateStake>) -> Result<()> {
        ctx.accounts.create_stake(&ctx.bumps)
    }

    /// VULNERABLE: Deposit to stake account
    pub fn vulnerable_deposit(ctx: Context<VulnerableDeposit>, amount: u64) -> Result<()> {
        ctx.accounts.deposit(amount)
    }

    /// SECURE: Create stake account with random nonce in seeds.
    /// Attacker cannot predict the address without knowing the nonce.
    pub fn secure_create_stake(ctx: Context<SecureCreateStake>, nonce: u64) -> Result<()> {
        ctx.accounts.create_stake(&ctx.bumps, nonce)
    }

    /// SECURE: Deposit to stake account with nonce-based PDA
    pub fn secure_deposit(ctx: Context<SecureDeposit>, amount: u64) -> Result<()> {
        ctx.accounts.deposit(amount)
    }
}
