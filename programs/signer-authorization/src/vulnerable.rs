use anchor_lang::prelude::*;

use crate::state::Vault;

// ---------------------------------------------------------------------------
// VULNERABILITY: Missing Signer Authorization
// ---------------------------------------------------------------------------
// The authority account uses UncheckedAccount (not Signer). Anyone can pass
// the vault.authority pubkey without signing, allowing unauthorized withdrawals.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct VulnerableWithdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,

    /// CHECK: VULNERABLE - Not validated as signer.
    /// Attacker can pass vault.authority without signing.
    pub authority: UncheckedAccount<'info>,

    #[account(mut)]
    /// CHECK: Destination for lamports
    pub destination: UncheckedAccount<'info>,
}

impl<'info> VulnerableWithdraw<'info> {
    /// Withdraw lamports from vault.
    /// DANGER: No signature verification - anyone can drain!
    pub fn withdraw(&mut self, amount: u64) -> Result<()> {
        // Modern pattern: use Lamports trait for direct transfers
        // This is vulnerable because we don't verify authority signed
        self.vault.sub_lamports(amount)?;
        self.destination.add_lamports(amount)?;

        Ok(())
    }
}
