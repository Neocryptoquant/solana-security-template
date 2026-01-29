# Account Reloading After CPI

**Vulnerability**: Using stale account data after Cross-Program Invocation  
**Framework**: Anchor  

## Overview

This program demonstrates the Account Reloading vulnerability where deserialized account data becomes stale after a CPI modifies the underlying account.

## The Vulnerability

Anchor deserializes accounts at instruction entry. After a CPI, the on-chain account data may change, but your `Account<T>` wrapper still holds the old values.

```rust
// VULNERABLE: counter.balance is STALE after CPI
token::transfer(cpi_ctx, 100)?;
// counter still shows old balance - CPI updated it but we have stale copy!
if counter.balance > threshold {  // WRONG! Using stale data
    // Logic based on incorrect state
}

// SECURE: Reload after CPI
token::transfer(cpi_ctx, 100)?;
counter.reload()?;  // Refresh from storage
if counter.balance > threshold {  // CORRECT! Using fresh data
    // Logic based on current state
}
```

## Attack Scenario

1. Protocol tracks user stake in `stake_account`
2. User deposits 100 SOL, stake = 100
3. CPI to staking pool adds rewards (+10 SOL)
4. Program checks `stake_account.amount` for eligibility
5. **BUG**: Stale data shows 100, not 110
6. User may miss tier upgrade or incorrect rewards calculated

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry points |
| `state.rs` | Counter account structure |
| `vulnerable.rs` | No reload after CPI (VULNERABLE) |
| `secure.rs` | reload() pattern demonstrated (SECURE) |
| `error.rs` | Custom error types |

## Key Differences

### Vulnerable Version
```rust
pub fn vulnerable_operation(&mut self) -> Result<()> {
    // CPI that modifies counter
    some_program::increment(cpi_ctx)?;
    
    // BUG: counter.count is STALE!
    msg!("Count: {}", self.counter.count);  // Shows OLD value
    Ok(())
}
```

### Secure Version
```rust
pub fn secure_operation(&mut self) -> Result<()> {
    // CPI that modifies counter
    some_program::increment(cpi_ctx)?;
    
    // RELOAD: Refresh from on-chain state
    self.counter.reload()?;
    
    msg!("Count: {}", self.counter.count);  // Shows CURRENT value
    Ok(())
}
```

## Running Tests

```bash
cargo test -p account-reloading-tests
```

## Mitigation Checklist

- Call `.reload()` on any account modified by CPI
- Audit all CPI calls for accounts used after the call
- Be especially careful with balance/amount checks after transfers
- Consider defensive reloads before critical calculations
- Document which CPIs modify which accounts
