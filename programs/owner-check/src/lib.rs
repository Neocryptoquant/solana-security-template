//! Owner Check - Pinocchio Program
//!
//! Demonstrates the "Missing Owner Check" vulnerability.

#![no_std]

use pinocchio::{
    entrypoint,
    error::{ProgramError, ProgramResult},
    nostd_panic_handler, AccountView, Address,
};

mod secure;
mod vulnerable;

entrypoint!(process_instruction);
nostd_panic_handler!();

/// Main entry point
pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data
        .first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match instruction {
        0 => vulnerable::process_read_config(program_id, accounts),
        1 => secure::process_read_config(program_id, accounts),
        2 => initialize_config(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize a config account
fn initialize_config(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let config_account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Must be owned by this program
    // SAFETY: owner() returns a reference to the account's owner
    if unsafe { config_account.owner() } != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    if data.len() < 33 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let admin_pubkey = &data[1..33];

    // Write admin to config data
    // SAFETY: we're the only one modifying this account
    unsafe {
        let config_data = config_account.borrow_unchecked();
        if config_data.len() >= 32 {
            // Get mutable slice and write
            core::ptr::copy_nonoverlapping(
                admin_pubkey.as_ptr(),
                config_data.as_ptr() as *mut u8,
                32,
            );
        }
    }

    Ok(())
}
