# Discriminator Bypass (Account Type Confusion)

**Vulnerability**: Passing account of type A where type B expected due to missing type identifier  
**Framework**: Pinocchio (no_std)  

## Overview

This program demonstrates the Discriminator Bypass vulnerability where accounts without discriminators can be confused for different types with similar memory layouts.

## The Vulnerability

Without a discriminator (type identifier byte), a program cannot distinguish between different account types that share the same serialized layout. Attackers can pass a User account where an Admin account is expected.

```rust
// VULNERABLE: No type verification
struct User { pubkey: [u8; 32], balance: u64 }
struct Admin { pubkey: [u8; 32], permissions: u64 }
// Both are 40 bytes - indistinguishable!

// SECURE: Discriminator identifies type
struct User { discriminator: u8, pubkey: [u8; 32], balance: u64 }  // disc = 1
struct Admin { discriminator: u8, pubkey: [u8; 32], permissions: u64 } // disc = 2
```

## Attack Scenario

1. Attacker creates a User account with high "balance" value
2. Attacker passes User account to admin-only instruction
3. Program reads User.balance as Admin.permissions
4. Attacker gains unintended admin privileges

## Attack Flow

### Vulnerable Version

```
Attacker           Program              Memory Layout
   |                  |                       |
   |-- Create User ---|                       |
   |   account with   |                       |
   |   balance = 255  |                       |
   |   (admin level)  |                       |
   |                  |                       |
   |   Memory Layout: |                       |
   |   [pubkey...] [255] (balance field)      |
   |                  |                       |
   |-- Call admin ----|                       |
   |   instruction    |    +-- NO DISC -------+
   |   passing User   |    |   CHECK          |
   |                  |    |                  |
   |   Assumes it's   |    |-- Read as -------+
   |   Admin account  |    |   Admin          |
   |                  |    |                  |
   |                  |    |-- Interpret -----+
   |                  |    |   balance (255)  |
   |                  |    |   as permissions |
   |                  |    |                  |
   |<-- Admin --------|    |-- Grant admin ---+
   |   permissions!   |    |   to attacker    |

Result: EXPLOIT SUCCESSFUL - Type confusion grants admin
```

### Secure Version

```
Attacker           Program              Memory Layout
   |                  |                       |
   |-- Create User ---|                       |
   |   account        |                       |
   |   disc = 1       |                       |
   |   balance = 255  |                       |
   |                  |                       |
   |   Memory Layout: |                       |
   |   [disc:1][pubkey...][255] (User)        |
   |                  |                       |
   |-- Call admin ----|                       |
   |   instruction    |    +-- CHECK ---------+
   |   passing User   |    |   DISCRIMINATOR  |
   |                  |    |<------- Disc=1   |
   |                  |    |                  |
   |                  |    +-- Expected ------+
   |                  |    |   Admin disc=2   |
   |                  |    |                  |
   |                  |    +-- Mismatch! -----+
   |                  |    |   REJECT         |
   |                  |    |                  |
   |<-- Error: -------|    |-- Type mismatch  |
   |    Invalid Type  |    |   Access denied  |

Result: EXPLOIT BLOCKED - Type discriminator prevents confusion
```

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Entry point, account initialization |
| `vulnerable.rs` | No discriminator check (VULNERABLE) |
| `secure.rs` | Discriminator verification (SECURE) |

## Key Differences

### Vulnerable Version
```rust
pub fn process_action(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let data = account.try_borrow()?;
    
    // NO DISCRIMINATOR CHECK - BUG!
    // Reading bytes 1-32 as pubkey, assuming it's a User
    let user_pubkey = &data[0..32];
    // Could actually be an Admin account!
    Ok(())
}
```

### Secure Version
```rust
pub fn process_action(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let data = account.try_borrow()?;
    
    // CHECK DISCRIMINATOR FIRST
    if data[0] != USER_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    let user_pubkey = &data[1..33];  // Skip discriminator
    Ok(())
}
```

## Running Tests

```bash
cargo test -p account-type-mismatch-tests
```

## Mitigation Checklist

- Add discriminator as first byte of all account types
- Always verify discriminator before deserializing
- In Anchor, use `#[account]` macro which adds 8-byte discriminator
- Use unique discriminator values for each account type
- Consider using enums for type safety
