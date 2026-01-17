#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod error;
pub mod initialize;
pub mod insecure;
pub mod secure;
pub mod state;

use initialize::*;
use insecure::*;
use secure::*;

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

    /// INSECURE: Withdraw without proper signer validation.
    /// Demonstrates the vulnerability - anyone can drain funds.
    pub fn insecure_withdraw(ctx: Context<InsecureWithdraw>, amount: u64) -> Result<()> {
        ctx.accounts.withdraw(amount)
    }

    /// SECURE: Withdraw with proper signer validation.
    /// Only the vault authority can withdraw funds.
    pub fn secure_withdraw(ctx: Context<SecureWithdraw>, amount: u64) -> Result<()> {
        ctx.accounts.withdraw(amount)
    }
}
