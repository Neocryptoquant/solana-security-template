use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};

use crate::error::VaultError;
use crate::state::Vault;

// ---------------------------------------------------------------------------
// SECURE: Proper Signer Authorization
// ---------------------------------------------------------------------------
// FIX: Use Signer<'info> type and constraint validation.
// Transaction fails if authority hasn't signed.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct SecureWithdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
        constraint = vault.authority == authority.key() @ VaultError::UnauthorizedAuthority
    )]
    pub vault: Account<'info, Vault>,

    /// Signer type enforces that this account must sign the transaction.
    pub authority: Signer<'info>,

    #[account(mut)]
    pub destination: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

impl<'info> SecureWithdraw<'info> {
    pub fn withdraw(&mut self, amount: u64) -> Result<()> {
        let seeds = &[b"vault", self.authority.key.as_ref(), &[self.vault.bump]];
        let signer_seeds = &[&seeds[..]];

        transfer(
            CpiContext::new_with_signer(
                self.system_program.to_account_info(),
                Transfer {
                    from: self.vault.to_account_info(),
                    to: self.destination.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
        )
    }
}
