use anchor_lang::prelude::*;

use crate::state::Pool;

// ---------------------------------------------------------------------------
// VULNERABILITY: Unchecked Arithmetic
// ---------------------------------------------------------------------------
// Uses raw u64 multiplication and division. Large inputs cause:
// 1. Overflow: amount_in * reserve_y wraps around
// 2. Precision loss: integer division truncates to zero for small values
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct VulnerableSwap<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"pool", pool.authority.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, Pool>,
}

impl<'info> VulnerableSwap<'info> {
    /// Swap X for Y using vulnerable arithmetic.
    /// DANGER: No overflow protection, no precision handling.
    pub fn swap_x_for_y(&mut self, amount_in: u64, _min_out: u64) -> Result<u64> {
        let reserve_x = self.pool.reserve_x;
        let reserve_y = self.pool.reserve_y;

        // VULNERABLE: Raw multiplication can overflow
        // If amount_in = u64::MAX / 2 and reserve_y = 3, this overflows
        let numerator = amount_in * reserve_y;

        // VULNERABLE: Division by (reserve_x + amount_in) can lose precision
        // Small amounts result in 0 output
        let amount_out = numerator / (reserve_x + amount_in);

        // No slippage check against min_out!

        // Update reserves
        self.pool.reserve_x = reserve_x + amount_in;
        self.pool.reserve_y = reserve_y - amount_out;

        Ok(amount_out)
    }
}
