//! Fuzz test for the Arithmetic Overflow vulnerability
//!
//! This fuzz test generates random u64 values for `amount_in` to test
//! both the vulnerable and secure swap implementations.
//!
//! The vulnerable version wraps on overflow; the secure version returns
//! an error when overflow would occur.

/// Fuzz data - the inputs we're randomizing
#[derive(Debug, Clone)]
pub struct SwapFuzzData {
    /// Random amount to swap (this is what we're fuzzing!)
    pub amount_in: u64,
    /// Minimum output amount (slippage protection)
    pub min_out: u64,
    /// Initial reserve X
    pub initial_reserve_x: u64,
    /// Initial reserve Y
    pub initial_reserve_y: u64,
}

impl SwapFuzzData {
    /// Generate random fuzz data
    pub fn random() -> Self {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        
        let s = RandomState::new();
        let mut h = s.build_hasher();
        h.write_u64(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64);
        
        Self {
            amount_in: h.finish(),
            min_out: 0,
            initial_reserve_x: h.finish().wrapping_add(1), // Avoid zero
            initial_reserve_y: h.finish().wrapping_add(1), // Avoid zero
        }
    }
}

/// Vulnerable swap implementation (mirrors the on-chain vulnerable code)
///
/// This function uses raw arithmetic that can overflow.
fn vulnerable_swap(
    amount_in: u64,
    reserve_x: u64,
    reserve_y: u64,
) -> Option<(u64, u64, u64)> {
    // VULNERABLE: Raw multiplication can overflow in release mode
    // In debug mode this would panic, but release mode wraps silently!
    let numerator = amount_in.wrapping_mul(reserve_y);
    
    // This can also overflow
    let denominator = reserve_x.wrapping_add(amount_in);
    
    if denominator == 0 {
        return None;
    }
    
    let amount_out = numerator / denominator;
    
    // No slippage check!
    
    let new_reserve_x = reserve_x.wrapping_add(amount_in);
    let new_reserve_y = reserve_y.wrapping_sub(amount_out);
    
    Some((amount_out, new_reserve_x, new_reserve_y))
}

/// Secure swap implementation (mirrors the on-chain secure code)
///
/// This function uses checked arithmetic and u128 intermediates.
fn secure_swap(
    amount_in: u64,
    min_out: u64,
    reserve_x: u64,
    reserve_y: u64,
) -> Result<(u64, u64, u64), &'static str> {
    if amount_in == 0 {
        return Err("InvalidAmount: amount_in is zero");
    }
    
    // SECURE: Use u128 for intermediate calculations
    let amount_in_u128 = amount_in as u128;
    let reserve_x_u128 = reserve_x as u128;
    let reserve_y_u128 = reserve_y as u128;
    
    // SECURE: checked_mul returns None on overflow
    let numerator = amount_in_u128
        .checked_mul(reserve_y_u128)
        .ok_or("MathOverflow: numerator overflow")?;
    
    let denominator = reserve_x_u128
        .checked_add(amount_in_u128)
        .ok_or("MathOverflow: denominator overflow")?;
    
    if denominator == 0 {
        return Err("MathOverflow: division by zero");
    }
    
    let amount_out_u128 = numerator / denominator;
    
    // SECURE: Ensure result fits in u64
    let amount_out = u64::try_from(amount_out_u128)
        .map_err(|_| "MathOverflow: result too large for u64")?;
    
    // SECURE: Slippage protection
    if amount_out < min_out {
        return Err("SlippageExceeded: output below minimum");
    }
    
    if amount_out > reserve_y {
        return Err("InsufficientReserves: not enough Y in pool");
    }
    
    // Update reserves with checked math
    let new_reserve_x = reserve_x
        .checked_add(amount_in)
        .ok_or("MathOverflow: reserve_x overflow")?;
    
    let new_reserve_y = reserve_y
        .checked_sub(amount_out)
        .ok_or("MathOverflow: reserve_y underflow")?;
    
    Ok((amount_out, new_reserve_x, new_reserve_y))
}

/// Property: The secure swap should never overflow
/// 
/// If the vulnerable swap produces a different result than expected
/// (due to overflow), the secure swap should return an error.
fn check_overflow_property(data: &SwapFuzzData) -> bool {
    // Skip degenerate cases
    if data.initial_reserve_x == 0 || data.initial_reserve_y == 0 {
        return true;
    }
    
    // Calculate what the result SHOULD be using u128 (the "oracle")
    let expected_numerator = (data.amount_in as u128) * (data.initial_reserve_y as u128);
    let expected_denominator = (data.initial_reserve_x as u128) + (data.amount_in as u128);
    
    if expected_denominator == 0 {
        return true;
    }
    
    let expected_out = expected_numerator / expected_denominator;
    
    // If the expected result doesn't fit in u64, secure version should error
    if expected_out > u64::MAX as u128 {
        // Secure version MUST reject this
        return secure_swap(
            data.amount_in,
            0,
            data.initial_reserve_x,
            data.initial_reserve_y,
        ).is_err();
    }
    
    // Check if vulnerable version produces wrong result (overflow occurred)
    if let Some((vulnerable_out, _, _)) = vulnerable_swap(
        data.amount_in,
        data.initial_reserve_x,
        data.initial_reserve_y,
    ) {
        let correct_out = expected_out as u64;
        
        // If vulnerable and correct differ, overflow happened
        if vulnerable_out != correct_out {
            // The secure version should handle this gracefully
            // (either return correct result or error)
            match secure_swap(
                data.amount_in,
                0,
                data.initial_reserve_x,
                data.initial_reserve_y,
            ) {
                Ok((secure_out, _, _)) => secure_out == correct_out,
                Err(_) => true, // Errors are acceptable for edge cases
            }
        } else {
            true // No overflow occurred
        }
    } else {
        true // Vulnerable version failed (division by zero)
    }
}

/// Property: Underflow in reserve_y subtraction should be caught
fn check_underflow_property(data: &SwapFuzzData) -> bool {
    if data.initial_reserve_x == 0 || data.initial_reserve_y == 0 {
        return true;
    }
    
    // Try the secure swap
    match secure_swap(
        data.amount_in,
        0,
        data.initial_reserve_x,
        data.initial_reserve_y,
    ) {
        Ok((amount_out, _, new_reserve_y)) => {
            // Verify no underflow: new_reserve_y should be <= original
            new_reserve_y <= data.initial_reserve_y && 
            amount_out <= data.initial_reserve_y
        }
        Err(_) => true, // Errors are fine - they indicate the check worked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_known_overflow_case() {
        // This is the classic overflow case from the article
        let data = SwapFuzzData {
            amount_in: u64::MAX / 4,
            min_out: 0,
            initial_reserve_x: u64::MAX / 2,
            initial_reserve_y: 1000,
        };
        
        // Vulnerable version will wrap
        let vulnerable_result = vulnerable_swap(
            data.amount_in,
            data.initial_reserve_x,
            data.initial_reserve_y,
        );
        
        // Secure version should catch this
        let secure_result = secure_swap(
            data.amount_in,
            0,
            data.initial_reserve_x,
            data.initial_reserve_y,
        );
        
        // The property should hold
        assert!(check_overflow_property(&data));
        
        println!("Vulnerable result: {:?}", vulnerable_result);
        println!("Secure result: {:?}", secure_result);
    }
    
    #[test]
    fn test_underflow_case() {
        // Case where amount_out could exceed reserve_y
        let data = SwapFuzzData {
            amount_in: 1_000_000_000,
            min_out: 0,
            initial_reserve_x: 100,
            initial_reserve_y: 100,
        };
        
        // Secure version should handle this
        let secure_result = secure_swap(
            data.amount_in,
            0,
            data.initial_reserve_x,
            data.initial_reserve_y,
        );
        
        // Should error or return valid result
        assert!(check_underflow_property(&data));
        
        println!("Secure result for underflow case: {:?}", secure_result);
    }
    
    #[test]
    fn test_normal_swap() {
        let data = SwapFuzzData {
            amount_in: 1000,
            min_out: 900,
            initial_reserve_x: 1_000_000_000,
            initial_reserve_y: 1_000_000_000,
        };
        
        let secure_result = secure_swap(
            data.amount_in,
            data.min_out,
            data.initial_reserve_x,
            data.initial_reserve_y,
        );
        
        assert!(secure_result.is_ok());
        let (amount_out, _, _) = secure_result.unwrap();
        assert!(amount_out >= data.min_out);
        
        println!("Normal swap output: {}", amount_out);
    }
    
    #[test]
    fn test_random_fuzz_iterations() {
        // Run 1000 random iterations
        for i in 0..1000 {
            let data = SwapFuzzData {
                amount_in: rand_u64(i),
                min_out: 0,
                initial_reserve_x: rand_u64(i + 1000).wrapping_add(1),
                initial_reserve_y: rand_u64(i + 2000).wrapping_add(1),
            };
            
            assert!(check_overflow_property(&data), 
                "Overflow property failed for iteration {}: {:?}", i, data);
            assert!(check_underflow_property(&data),
                "Underflow property failed for iteration {}: {:?}", i, data);
        }
        println!("All 1000 random iterations passed!");
    }
    
    /// Simple pseudo-random number generator for testing
    fn rand_u64(seed: u64) -> u64 {
        let mut x = seed.wrapping_add(0x9E3779B97F4A7C15);
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
        x ^ (x >> 31)
    }
}

// Entry point for trident fuzzer (when using full trident)
fn main() {
    println!("Arithmetic Overflow Fuzz Test");
    println!("==============================");
    println!();
    println!("Run unit tests with: cargo test");
    println!("Run full fuzzer with: trident fuzz run fuzz_arithmetic");
    println!();
    println!("This fuzz test generates random u64 values for swap amounts");
    println!("to verify that:");
    println!("  1. The secure swap never silently overflows");
    println!("  2. The secure swap catches all underflow cases");
    println!("  3. Normal swaps produce correct results");
}
