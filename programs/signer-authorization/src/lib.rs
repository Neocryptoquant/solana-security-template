#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod error;
pub mod initialize;
pub mod secure;
pub mod state;
pub mod vulnerable;

use initialize::*;
use secure::*;
use vulnerable::*;

declare_id!("EXnhqXwkDbL63d2UPbERQ4BQSubRyLHwCJLiKhhW7zba");

#[program]
pub mod signer_authorization {
    use super::*;

    /// Initialize a new vault for the signer.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.initialize(&ctx.bumps)
    }

    /// Deposit lamports into the vault.
    pub fn deposit(ctx: Context<Initialize>, amount: u64) -> Result<()> {
        ctx.accounts.deposit(amount)
    }

    /// VULNERABLE: Withdraw without proper signer validation.
    /// Demonstrates the vulnerability - anyone can drain funds.
    pub fn vulnerable_withdraw(ctx: Context<VulnerableWithdraw>, amount: u64) -> Result<()> {
        ctx.accounts.withdraw(amount)
    }

    /// SECURE: Withdraw with proper signer validation.
    /// Only the vault authority can withdraw funds.
    pub fn secure_withdraw(ctx: Context<SecureWithdraw>, amount: u64) -> Result<()> {
        ctx.accounts.withdraw(amount)
    }
}
