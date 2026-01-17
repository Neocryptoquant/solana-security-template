use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};

use crate::state::Vault;

// ---------------------------------------------------------------------------
// VULNERABILITY: Missing Signer Authorization
// ---------------------------------------------------------------------------
// The authority account is not validated as a Signer. Anyone can pass any
// pubkey and drain funds without signing the transaction.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct InsecureWithdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,

    /// CHECK: VULNERABLE - Not validated as signer.
    /// Attacker can pass vault.authority without signing.
    pub authority: AccountInfo<'info>,

    #[account(mut)]
    pub destination: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

impl<'info> InsecureWithdraw<'info> {
    pub fn withdraw(&mut self, amount: u64) -> Result<()> {
        // No signature verification - anyone can drain!
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
