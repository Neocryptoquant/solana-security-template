# Arithmetic Overflow and Precision Loss

**Vulnerability**: Integer overflow/underflow and precision errors in arithmetic  
**Framework**: Anchor  

## Overview

This program demonstrates arithmetic vulnerabilities in a simple AMM swap context, showing how unchecked math can lead to overflow and precision loss.

## The Vulnerability

### Overflow
When multiplying two large `u64` values, the result can exceed `u64::MAX` and wrap around to a small number.

```rust
// VULNERABLE: Can overflow if amount_in * reserve_y > u64::MAX
let numerator = amount_in * reserve_y;

// SECURE: Use u128 intermediate and checked_mul
let numerator = (amount_in as u128)
    .checked_mul(reserve_y as u128)
    .ok_or(Error::MathOverflow)?;
```

### Precision Loss
Integer division truncates. Small amounts divided by large denominators become zero.

```rust
// VULNERABLE: 1 * 100 / 1000 = 0 (user loses tokens!)
let output = (amount_in * reserve_y) / (reserve_x + amount_in);

// SECURE: Use u128 and ceiling division when appropriate
```

## Attack Scenario

1. Attacker deposits `u64::MAX / 2` tokens
2. Multiplication `amount_in * reserve_y` overflows
3. Result wraps to small number, attacker gets disproportionate output
4. Protocol reserves become corrupted

## Attack Flow

### Vulnerable Version
```
Attacker          Program              Math State
   |                 |                      |
   |-- Deposit ------|                      |
   |   large amount  |                      |
   |   (u64::MAX/2)  |                      |
   |                 |                      |
   |-- Call swap ----|                      |
   |   instruction   |                      |
   |                 |   amount_in * -------+
   |                 |   reserve_y          |
   |                 |                      |
   |                 |   (huge * huge)      |
   |                 |                      |
   |                 |   = OVERFLOW! -------+
   |                 |                      |
   |                 |   Result wraps ------+
   |                 |   to small number    |
   |                 |                      |
   |                 |   Output = huge /    |
   |                 |   small = attacker   |
   |                 |   wins BIG!          |
   |                 |                      |
   |<-- Huge output--|   Pool drained!      |
   |   (cheated!)    |   Reserves broken!   |

Result: EXPLOIT SUCCESSFUL - Attacker drains liquidity
```

### Secure Version
```
Attacker          Program              Math State
   |                 |                      |
   |-- Deposit ------|                      |
   |   large amount  |                      |
   |   (u64::MAX/2)  |                      |
   |                 |                      |
   |-- Call swap ----|                      |
   |   instruction   |                      |
   |                 |                      |
   |                 |   Cast to u128 ------+
   |                 |   before multiply    |
   |                 |                      |
   |                 |   (huge_u128 *       |
   |                 |    huge_u128)        |
   |                 |                      |
   |                 |   = Fits in u128!    |
   |                 |                      |
   |                 |   Calculate safely   |
   |                 |                      |
   |                 |   Output = correct   |
   |                 |   value              |
   |                 |                      |
   |<-- Normal output|   Fair rate given!   |
   |   (fair price)  |   Exploit blocked!   |

Result: EXPLOIT BLOCKED - Overflow prevented
```

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry points |
| `state.rs` | Pool account structure |
| `initialize.rs` | Pool initialization |
| `vulnerable.rs` | Unchecked arithmetic (VULNERABLE) |
| `secure.rs` | Checked arithmetic with u128 (SECURE) |
| `error.rs` | Custom error types |

## Key Differences

### Vulnerable Version
```rust
// Raw multiplication - OVERFLOWS
let numerator = amount_in * reserve_y;
let amount_out = numerator / (reserve_x + amount_in);
// No slippage check!
```

### Secure Version
```rust
// u128 intermediates prevent overflow
let numerator = (amount_in as u128)
    .checked_mul(reserve_y as u128)
    .ok_or(PoolError::MathOverflow)?;

let amount_out = u64::try_from(amount_out_u128)
    .map_err(|_| PoolError::MathOverflow)?;

// Slippage protection
require!(amount_out >= min_out, PoolError::SlippageExceeded);
```

## Running Tests

```bash
cargo test -p arithmetic-overflow-tests
```

## Mitigation Checklist

- Use `checked_add`, `checked_sub`, `checked_mul`, `checked_div`
- Use `u128` for intermediate calculations involving `u64` values
- Add slippage protection for DEX operations
- Consider using `saturating_*` when appropriate
- Enable `overflow-checks = true` in release builds
