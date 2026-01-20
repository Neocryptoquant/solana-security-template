//! VULNERABLE: Account Close Without Proper Cleanup
//!
//! VULNERABILITY:
//! 1. Account data is not zeroed before closing
//! 2. Account can be "revived" if someone sends lamports to it
//! 3. Stale data remains readable after revival
//!
//! ATTACK:
//! 1. Close account (lamports transferred, but data intact)
//! 2. In same tx, send lamports back to the account address
//! 3. Account is "alive" again with old data

use crate::state::UserAccount;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        init,
        payer = owner,
        space = 8 + UserAccount::INIT_SPACE,
        seeds = [b"user", owner.key().as_ref()],
        bump
    )]
    pub user_account: Account<'info, UserAccount>,

    pub system_program: Program<'info, System>,
}

impl<'info> Initialize<'info> {
    pub fn initialize(&mut self, bumps: &InitializeBumps) -> Result<()> {
        self.user_account.owner = self.owner.key();
        self.user_account.balance = 100; // Initial balance
        self.user_account.is_initialized = true;
        self.user_account.bump = bumps.user_account;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct VulnerableClose<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    // ---------------------------------------------------------------------------
    // VULNERABILITY: Using close without zeroing data
    // The 'close' constraint transfers lamports but doesn't zero data
    // Account can be revived by sending lamports back to same address
    // ---------------------------------------------------------------------------
    #[account(
        mut,
        seeds = [b"user", owner.key().as_ref()],
        bump = user_account.bump,
        close = owner  // VULNERABLE: data not zeroed
    )]
    pub user_account: Account<'info, UserAccount>,
}

impl<'info> VulnerableClose<'info> {
    pub fn close(&mut self) -> Result<()> {
        // Just closing - no data cleanup
        // After this, if account receives lamports it's "alive" again
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UseData<'info> {
    pub owner: Signer<'info>,

    #[account(
        seeds = [b"user", owner.key().as_ref()],
        bump = user_account.bump,
    )]
    pub user_account: Account<'info, UserAccount>,
}
