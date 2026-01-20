//! VULNERABLE: Missing Discriminator Check
//!
//! VULNERABILITY:
//! The program expects a "User" account but doesn't check the discriminator.
//! An attacker can pass an "Admin" account (same layout) and:
//! - Read admin data as if it were user data
//! - Potentially escalate privileges
//!
//! ATTACK:
//! 1. Create an Admin account with attacker as the pubkey
//! 2. Call vulnerable action with Admin account instead of User
//! 3. Program reads Admin.permissions as User.balance
//! 4. Attacker gets unauthorized access

#![allow(unused)]

use pinocchio::{
    error::{ProgramError, ProgramResult},
    AccountView, Address,
};

/// VULNERABLE: Read user data without type verification
pub fn process_action(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let user_account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;

    let caller = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Verify owner
    if unsafe { user_account.owner() } != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // ---------------------------------------------------------------------------
    // VULNERABILITY: No discriminator check!
    // We assume this is a User account, but it could be an Admin account
    // Both have the same layout: [discriminator(1), pubkey(32), u64(8)]
    // ---------------------------------------------------------------------------

    let data = user_account.try_borrow()?;
    if data.len() < 41 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Skip discriminator (byte 0), read pubkey (bytes 1-33)
    let stored_user = &data[1..33];

    // Read "balance" (but could be Admin.permissions!)
    let balance = u64::from_le_bytes(
        data[33..41]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?,
    );

    // Check if caller matches stored user
    if caller.address().as_ref() != stored_user {
        return Err(ProgramError::InvalidAccountData);
    }

    // VULNERABLE: Using "balance" which could actually be "permissions"
    // This could lead to privilege escalation

    Ok(())
}
