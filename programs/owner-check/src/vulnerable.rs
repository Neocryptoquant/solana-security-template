//! VULNERABLE: Missing Owner Check
//!
//! VULNERABILITY:
//! - We read the "admin" pubkey from a config account
//! - We DON'T check that config_account.owner == program_id
//! - Attacker can pass ANY account with malicious data

#![allow(unused)]

use pinocchio::{
    error::{ProgramError, ProgramResult},
    AccountView, Address,
};

/// VULNERABLE: Read admin from config without owner verification
pub fn process_read_config(
    _program_id: &Address, // NOTE: We ignore program_id - the bug!
    accounts: &[AccountView],
) -> ProgramResult {
    let config_account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;

    let caller = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;

    // ---------------------------------------------------------------------------
    // VULNERABILITY: No owner check!
    // We should verify: config_account.owner() == program_id
    // Without this, attacker can pass any account with fake data
    // ---------------------------------------------------------------------------

    // Read admin pubkey from config data (first 32 bytes)
    let config_data = config_account.try_borrow()?;
    if config_data.len() < 32 {
        return Err(ProgramError::InvalidAccountData);
    }

    let stored_admin = &config_data[..32];

    // Check if caller is the admin (compare addresses)
    if caller.address().as_ref() != stored_admin {
        return Err(ProgramError::InvalidAccountData);
    }

    // VULNERABLE: Admin action executed from unverified account
    // In a real program, this would do something privileged...

    Ok(())
}
