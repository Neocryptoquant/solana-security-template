//! VULNERABLE: Weak PDA Seeds
//!
//! VULNERABILITY:
//! 1. Seeds only include user pubkey - easily predictable
//! 2. No hardcoded bump constraint - vulnerable to bump seed canonicalization
//!
//! ATTACK: Attacker can compute the same PDA and front-run account creation

use crate::state::WeakUserAccount;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct VulnerableCreateUser<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    // ---------------------------------------------------------------------------
    // VULNERABILITY: Seeds only use user pubkey
    // Anyone can compute this PDA for any user
    // No protection against front-running or collision
    // ---------------------------------------------------------------------------
    #[account(
        init,
        payer = user,
        space = 8 + WeakUserAccount::INIT_SPACE,
        seeds = [user.key().as_ref()],  // WEAK: only user pubkey
        bump
    )]
    pub user_account: Account<'info, WeakUserAccount>,

    pub system_program: Program<'info, System>,
}

impl<'info> VulnerableCreateUser<'info> {
    pub fn create_user(&mut self, bumps: &VulnerableCreateUserBumps) -> Result<()> {
        self.user_account.owner = self.user.key();
        self.user_account.data = 0;
        self.user_account.bump = bumps.user_account;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct VulnerableUpdate<'info> {
    pub user: Signer<'info>,

    // ---------------------------------------------------------------------------
    // VULNERABILITY: Not verifying bump is canonical
    // Attacker could potentially use non-canonical bump in some scenarios
    // ---------------------------------------------------------------------------
    #[account(
        mut,
        seeds = [user.key().as_ref()],
        bump  // Should use: bump = user_account.bump
    )]
    pub user_account: Account<'info, WeakUserAccount>,
}

impl<'info> VulnerableUpdate<'info> {
    pub fn update(&mut self, data: u64) -> Result<()> {
        self.user_account.data = data;
        Ok(())
    }
}
