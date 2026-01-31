//! VULNERABLE implementation - predictable PDA seeds
//!
//! This implementation uses only the user's pubkey as a seed, making the
//! PDA address completely predictable. An attacker can:
//! 1. Compute the PDA for any user
//! 2. Send minimum rent-exempt lamports to that address
//! 3. Block the user from ever creating their stake account
//!
//! The create_account instruction will fail because the address already
//! has lamports (Solana assumes it's "in use").

use anchor_lang::prelude::*;
use crate::state::StakeAccount;
use crate::error::StakeError;

#[derive(Accounts)]
pub struct VulnerableCreateStake<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    /// VULNERABLE: Manual account creation without checking pre-funding
    /// We use UncheckedAccount because we're creating it manually
    #[account(mut)]
    pub stake_account: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

impl<'info> VulnerableCreateStake<'info> {
    pub fn create_stake(&mut self, _bumps: &VulnerableCreateStakeBumps) -> Result<()> {
        let space = 8 + StakeAccount::INIT_SPACE as u64;
        let rent = Rent::get()?.minimum_balance(space as usize);
        
        // Manual CPI to create_account
        // This fails if account already has lamports (the vulnerability)
        let ix = anchor_lang::solana_program::system_instruction::create_account(
            &self.user.key(),
            &self.stake_account.key(),
            rent,
            space,
            &crate::ID,
        );

        let bump = *self.user.key().as_ref().last().unwrap(); // Simple predictable seed logic for demo
        // In real attack we use the predictable bump
        
        // Improve: Re-derive bump to sign
        let (pda, bump) = Pubkey::find_program_address(
            &[b"stake", self.user.key().as_ref()],
            &crate::ID
        );
        require_keys_eq!(pda, self.stake_account.key(), StakeError::Unauthorized);

        let seeds = &[
            b"stake", 
            self.user.key().as_ref(),
            &[bump]
        ];
        let signer = &[&seeds[..]];

        anchor_lang::solana_program::program::invoke_signed(
            &ix,
            &[
                self.user.to_account_info(),
                self.stake_account.to_account_info(),
                self.system_program.to_account_info(),
            ],
            signer
        )?;

        // Now initialize the data
        let mut account = StakeAccount::try_from_slice(&self.stake_account.data.borrow())
            .unwrap_or_default(); // Should be empty
            
        // Minimal init manual
        // Note: In manual CPI we need to serialize discriminator and data
        // For simplicity in this demo we just ensure create_account was called
        
        msg!("Created stake account manually for user: {}", self.user.key());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct VulnerableDeposit<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"stake", user.key().as_ref()],
        bump = stake_account.bump,
        constraint = stake_account.owner == user.key()
    )]
    pub stake_account: Account<'info, StakeAccount>,

    pub system_program: Program<'info, System>,
}

impl<'info> VulnerableDeposit<'info> {
    pub fn deposit(&mut self, amount: u64) -> Result<()> {
        // Transfer SOL from user to stake account
        let cpi_context = CpiContext::new(
            self.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: self.user.to_account_info(),
                to: self.stake_account.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;

        self.stake_account.amount = self.stake_account.amount.checked_add(amount).unwrap();
        msg!("Deposited {} lamports", amount);
        Ok(())
    }
}
