//! P-Escrow: Pinocchio Escrow with Vulnerability Demonstration
//!
//! Demonstrates the "Missing Refund Validation" vulnerability in token escrows.
//!
//! VULNERABILITY: When a taker cancels/refunds, the escrow doesn't verify
//! that the correct maker is receiving the tokens back. An attacker can
//! redirect refunds to themselves.

use pinocchio::{account_info::AccountInfo, entrypoint, pubkey::Pubkey, ProgramResult};

pub mod instructions;
pub mod state;

#[cfg(test)]
mod tests;

entrypoint!(process_instruction);

/// Program ID (will be replaced by keypair at deploy time)
#[allow(clippy::useless_transmute)]
pub static ID: Pubkey = unsafe {
    core::mem::transmute::<[u8; 32], Pubkey>([
        0x50, 0x45, 0x73, 0x63, 0x72, 0x30, 0x77, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
        0x31, 0x31,
    ])
};

/// Instruction discriminators
#[repr(u8)]
pub enum EscrowInstruction {
    Make = 0,
    Take = 1,
    VulnerableRefund = 2,
    SecureRefund = 3,
}

impl TryFrom<&u8> for EscrowInstruction {
    type Error = pinocchio::program_error::ProgramError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Make),
            1 => Ok(Self::Take),
            2 => Ok(Self::VulnerableRefund),
            3 => Ok(Self::SecureRefund),
            _ => Err(pinocchio::program_error::ProgramError::InvalidInstructionData),
        }
    }
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Verify program ID
    if program_id != &ID {
        return Err(pinocchio::program_error::ProgramError::IncorrectProgramId);
    }

    let (discriminator, data) = instruction_data
        .split_first()
        .ok_or(pinocchio::program_error::ProgramError::InvalidInstructionData)?;

    match EscrowInstruction::try_from(discriminator)? {
        EscrowInstruction::Make => instructions::process_make(accounts, data),
        EscrowInstruction::Take => instructions::process_take(accounts, data),
        EscrowInstruction::VulnerableRefund => {
            instructions::process_vulnerable_refund(accounts, data)
        }
        EscrowInstruction::SecureRefund => instructions::process_secure_refund(accounts, data),
    }
}
