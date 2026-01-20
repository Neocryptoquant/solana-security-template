//! Escrow instructions

pub mod make;
pub mod refund;

pub use make::process_make;
pub use refund::{process_secure_refund, process_vulnerable_refund};

use pinocchio::{account_info::AccountInfo, ProgramResult};

/// Process take instruction (stub for now)
pub fn process_take(_accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    // TODO: Implement take logic
    Ok(())
}
