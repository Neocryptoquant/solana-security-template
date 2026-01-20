//! Refund instructions - VULNERABLE vs SECURE
//!
//! VULNERABILITY: In vulnerable_refund, we don't verify that the destination
//! for the refunded tokens matches the original maker. An attacker can:
//! 1. Find an active escrow
//! 2. Call vulnerable_refund with THEIR address as destination
//! 3. Steal the escrowed tokens

use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    ProgramResult,
};

use crate::state::Escrow;

/// VULNERABLE: Refund without validating the recipient
pub fn process_vulnerable_refund(accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let [
        _caller,          // Anyone can call!
        escrow_account,
        vault,
        destination,     // Where tokens go - NOT VALIDATED!
        token_program,
        ..
    ] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify escrow is owned by program
    if escrow_account.owner() != &crate::ID {
        return Err(ProgramError::IllegalOwner);
    }

    let escrow = Escrow::from_account_info(escrow_account)?;

    // ---------------------------------------------------------------------------
    // VULNERABILITY: We don't check that destination == escrow.maker
    // Anyone can pass any destination and steal the tokens!
    // ---------------------------------------------------------------------------

    let amount = escrow.amount_to_give();

    // Create PDA signer for vault
    let bump_bytes = [escrow.bump];
    let seeds = [
        Seed::from(b"escrow"),
        Seed::from(&escrow.maker),
        Seed::from(&bump_bytes),
    ];
    let signer = Signer::from(&seeds);

    // Transfer tokens to (unvalidated!) destination
    pinocchio_token::instructions::Transfer {
        from: vault,
        to: destination,
        authority: escrow_account, // Escrow PDA is authority
        amount,
    }
    .invoke_signed(&[signer])?;

    // Mark escrow as inactive
    let escrow = Escrow::from_account_info(escrow_account)?;
    let ptr = escrow as *mut Escrow;
    unsafe {
        (*ptr).is_active = 0;
    }

    Ok(())
}

/// SECURE: Refund with proper maker validation
pub fn process_secure_refund(accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let [caller, escrow_account, vault, destination, token_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify escrow is owned by program
    if escrow_account.owner() != &crate::ID {
        return Err(ProgramError::IllegalOwner);
    }

    let escrow = Escrow::from_account_info(escrow_account)?;

    // ---------------------------------------------------------------------------
    // FIX 1: Verify caller is the original maker
    // Only the maker can request a refund
    // ---------------------------------------------------------------------------
    if caller.key() != &escrow.maker() {
        return Err(ProgramError::InvalidAccountData);
    }

    // ---------------------------------------------------------------------------
    // FIX 2: Verify destination matches the maker
    // Tokens can only go back to the original maker
    // ---------------------------------------------------------------------------
    if destination.key() != caller.key() {
        // Destination must be maker's token account
        // (In production, also verify ATA derivation)
        return Err(ProgramError::InvalidAccountData);
    }

    // ---------------------------------------------------------------------------
    // FIX 3: Caller must sign
    // ---------------------------------------------------------------------------
    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let amount = escrow.amount_to_give();

    let bump_bytes = [escrow.bump];
    let seeds = [
        Seed::from(b"escrow"),
        Seed::from(&escrow.maker),
        Seed::from(&bump_bytes),
    ];
    let signer = Signer::from(&seeds);

    pinocchio_token::instructions::Transfer {
        from: vault,
        to: destination,
        authority: escrow_account,
        amount,
    }
    .invoke_signed(&[signer])?;

    // Mark escrow as inactive
    let escrow = Escrow::from_account_info(escrow_account)?;
    let ptr = escrow as *mut Escrow;
    unsafe {
        (*ptr).is_active = 0;
    }

    Ok(())
}
