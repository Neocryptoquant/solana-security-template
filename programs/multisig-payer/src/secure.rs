//! SECURE implementation - separate rent payer
//!
//! This implementation correctly separates the concepts of:
//! 1. AUTHORITY - The multisig PDA that controls permissions
//! 2. RENT PAYER - A regular signer that pays for account creation
//!
//! The rent payer has NO authority over the DAO - they simply fund
//! account creation. The multisig retains full control over governance.

use anchor_lang::prelude::*;
use crate::state::{DaoConfig, MultisigTreasury, Proposal, MAX_TITLE_LEN};
use crate::error::DaoError;

/// SECURE: Separate rent payer from authority
#[derive(Accounts)]
#[instruction(proposal_id: u64)]
pub struct SecureCreateProposal<'info> {
    /// SECURE: Regular signer pays rent (no authority role)
    #[account(mut)]
    pub rent_payer: Signer<'info>,

    /// The creator of the proposal
    pub creator: Signer<'info>,

    /// The multisig treasury - validates authority, does NOT pay
    #[account(
        seeds = [b"treasury", config.key().as_ref()],
        bump = treasury.bump
    )]
    pub treasury: Account<'info, MultisigTreasury>,

    #[account(
        seeds = [b"dao_config"],
        bump = config.bump,
        constraint = config.authority == treasury.key() @ DaoError::Unauthorized
    )]
    pub config: Account<'info, DaoConfig>,

    /// SECURE: payer = rent_payer (a regular Signer, not a PDA)
    #[account(
        init,
        payer = rent_payer,  // Regular signer pays rent
        space = 8 + Proposal::INIT_SPACE,
        seeds = [b"proposal", config.key().as_ref(), &proposal_id.to_le_bytes()],
        bump
    )]
    pub proposal: Account<'info, Proposal>,

    pub system_program: Program<'info, System>,
}

impl<'info> SecureCreateProposal<'info> {
    pub fn create_proposal(
        &mut self,
        bumps: &SecureCreateProposalBumps,
        proposal_id: u64,
        title: String,
    ) -> Result<()> {
        require!(title.len() <= MAX_TITLE_LEN, DaoError::TitleTooLong);

        self.proposal.id = proposal_id;
        self.proposal.title = title;
        self.proposal.creator = self.creator.key();
        self.proposal.yes_votes = 0;
        self.proposal.no_votes = 0;
        self.proposal.executed = false;
        self.proposal.bump = bumps.proposal;

        msg!("Proposal {} created by {}", proposal_id, self.creator.key());
        msg!("Rent paid by {}", self.rent_payer.key());
        msg!("Authority validation: treasury PDA");
        Ok(())
    }
}
