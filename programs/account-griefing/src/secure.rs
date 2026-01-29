//! SECURE implementation - unpredictable PDA seeds with nonce
//!
//! This implementation includes a random nonce in the PDA seeds, making
//! the address unpredictable to attackers. They cannot fund the PDA in
//! advance because they don't know which nonce the user will choose.

use anchor_lang::prelude::*;
use crate::state::SecureStakeAccount;
use crate::error::StakeError;

#[derive(Accounts)]
#[instruction(nonce: u64)]
pub struct SecureCreateStake<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    /// SECURE: Nonce makes PDA unpredictable
    /// Attacker cannot compute address without knowing the nonce
    #[account(
        init,
        payer = user,
        space = 8 + SecureStakeAccount::INIT_SPACE,
        seeds = [b"stake", user.key().as_ref(), &nonce.to_le_bytes()],
        bump
    )]
    pub stake_account: Account<'info, SecureStakeAccount>,

    pub system_program: Program<'info, System>,
}

impl<'info> SecureCreateStake<'info> {
    pub fn create_stake(&mut self, bumps: &SecureCreateStakeBumps, nonce: u64) -> Result<()> {
        self.stake_account.owner = self.user.key();
        self.stake_account.amount = 0;
        self.stake_account.nonce = nonce;
        self.stake_account.bump = bumps.stake_account;
        self.stake_account.is_initialized = true;
        
        msg!("Created secure stake account with nonce: {}", nonce);
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(amount: u64)]
pub struct SecureDeposit<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"stake", user.key().as_ref(), &stake_account.nonce.to_le_bytes()],
        bump = stake_account.bump,
        constraint = stake_account.owner == user.key() @ StakeError::Unauthorized
    )]
    pub stake_account: Account<'info, SecureStakeAccount>,

    pub system_program: Program<'info, System>,
}

impl<'info> SecureDeposit<'info> {
    pub fn deposit(&mut self, amount: u64) -> Result<()> {
        require!(amount > 0, StakeError::InvalidAmount);

        let cpi_context = CpiContext::new(
            self.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: self.user.to_account_info(),
                to: self.stake_account.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;

        self.stake_account.amount = self.stake_account
            .amount
            .checked_add(amount)
            .ok_or(StakeError::InvalidAmount)?;
            
        msg!("Deposited {} lamports", amount);
        Ok(())
    }
}
