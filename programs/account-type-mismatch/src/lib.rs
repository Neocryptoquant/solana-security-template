//! Type Cosplay - Pinocchio Program
//!
//! Demonstrates the "Type Cosplay" or "Missing Discriminator" vulnerability.
//!
//! VULNERABILITY: When accounts don't have a discriminator (type identifier),
//! an attacker can pass an account of type A where type B is expected.
//! If both have the same serialized layout, the program reads garbage data.

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

/// Account type discriminators
pub const USER_DISCRIMINATOR: u8 = 1;
pub const ADMIN_DISCRIMINATOR: u8 = 2;

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
        // 0 = Vulnerable: Read user without discriminator check
        0 => vulnerable::process_action(program_id, accounts),
        // 1 = Secure: Read user WITH discriminator verification
        1 => secure::process_action(program_id, accounts),
        // 2 = Initialize user account
        2 => init_user(program_id, accounts, instruction_data),
        // 3 = Initialize admin account
        3 => init_admin(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize user account (discriminator = 1)
fn init_user(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;

    if unsafe { account.owner() } != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // User layout: [discriminator(1), pubkey(32), balance(8)]
    unsafe {
        let acc_data = account.borrow_unchecked();
        if acc_data.len() < 41 {
            return Err(ProgramError::InvalidAccountData);
        }
        let ptr = acc_data.as_ptr() as *mut u8;
        *ptr = USER_DISCRIMINATOR; // Set discriminator

        if data.len() >= 33 {
            core::ptr::copy_nonoverlapping(data[1..33].as_ptr(), ptr.add(1), 32);
        }
    }
    Ok(())
}

/// Initialize admin account (discriminator = 2)
fn init_admin(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;

    if unsafe { account.owner() } != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Admin layout: [discriminator(1), pubkey(32), permissions(8)]
    // Note: Same layout as User! Only discriminator differs
    unsafe {
        let acc_data = account.borrow_unchecked();
        if acc_data.len() < 41 {
            return Err(ProgramError::InvalidAccountData);
        }
        let ptr = acc_data.as_ptr() as *mut u8;
        *ptr = ADMIN_DISCRIMINATOR; // Set discriminator

        if data.len() >= 33 {
            core::ptr::copy_nonoverlapping(data[1..33].as_ptr(), ptr.add(1), 32);
        }
    }
    Ok(())
}
