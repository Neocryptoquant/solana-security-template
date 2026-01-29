//! VULNERABLE implementation - PDA as payer
//!
//! This implementation attempts to use a multisig PDA as the payer for
//! account creation. This WILL ALWAYS FAIL because:
//!
//! 1. Anchor's `init` constraint generates a CPI to system_program::create_account
//! 2. create_account requires the funding account to sign a transfer
//! 3. PDAs cannot sign system program operations - only the program that
//!    derived them can sign, and only for CPIs to that same program
//!
//! Error: "Cross-program invocation with unauthorized signer or writable account"

use anchor_lang::prelude::*;
use crate::state::{DaoConfig, MultisigTreasury, Proposal, MAX_TITLE_LEN};
use crate::error::DaoError;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

    #[account(
        init,
        payer = creator,
        space = 8 + DaoConfig::INIT_SPACE,
        seeds = [b"dao_config"],
        bump
    )]
    pub config: Account<'info, DaoConfig>,

    /// The multisig treasury PDA that will "own" funds
    #[account(
        init,
        payer = creator,
        space = 8 + MultisigTreasury::INIT_SPACE,
        seeds = [b"treasury", config.key().as_ref()],
        bump
    )]
    pub treasury: Account<'info, MultisigTreasury>,

    pub system_program: Program<'info, System>,
}

impl<'info> Initialize<'info> {
    pub fn initialize(&mut self, bumps: &InitializeBumps) -> Result<()> {
        self.config.authority = self.treasury.key();
        self.config.proposal_count = 0;
        self.config.bump = bumps.config;
        self.config.is_initialized = true;

        self.treasury.dao = self.config.key();
        self.treasury.bump = bumps.treasury;

        msg!("DAO initialized with treasury authority: {}", self.treasury.key());
        Ok(())
    }
}

/// VULNERABLE: This instruction will ALWAYS fail!
/// The treasury PDA cannot sign the system transfer needed for init
#[derive(Accounts)]
#[instruction(proposal_id: u64)]
pub struct VulnerableCreateProposal<'info> {
    /// The multisig treasury PDA - CANNOT be a payer!
    #[account(
        mut,
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

    /// VULNERABLE: payer = treasury (a PDA!)
    /// This will fail with "unauthorized signer" error
    #[account(
        init,
        payer = treasury,  // BUG: PDA cannot sign system transfers!
        space = 8 + Proposal::INIT_SPACE,
        seeds = [b"proposal", config.key().as_ref(), &proposal_id.to_le_bytes()],
        bump
    )]
    pub proposal: Account<'info, Proposal>,

    /// The user creating the proposal (but treasury pays - broken!)
    pub creator: Signer<'info>,

    pub system_program: Program<'info, System>,
}

impl<'info> VulnerableCreateProposal<'info> {
    pub fn create_proposal(
        &mut self,
        bumps: &VulnerableCreateProposalBumps,
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

        msg!("Proposal {} created", proposal_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Vote<'info> {
    #[account(mut)]
    pub voter: Signer<'info>,

    #[account(mut)]
    pub proposal: Account<'info, Proposal>,
}

impl<'info> Vote<'info> {
    pub fn vote(&mut self, approve: bool) -> Result<()> {
        require!(!self.proposal.executed, DaoError::AlreadyExecuted);
        
        if approve {
            self.proposal.yes_votes += 1;
        } else {
            self.proposal.no_votes += 1;
        }
        
        msg!("Vote recorded: {}", if approve { "YES" } else { "NO" });
        Ok(())
    }
}
