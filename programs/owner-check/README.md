# Missing Owner Check

**Vulnerability**: Trusting account data without verifying account ownership  
**Framework**: Pinocchio (no_std)  

## Overview

This program demonstrates the Missing Owner Check vulnerability using Pinocchio's low-level API. It shows how failing to verify an account's owner allows attackers to inject malicious data.

## The Vulnerability

In Solana, account data can be read without restrictions. If a program reads configuration from an account without verifying the account is owned by the program, attackers can pass any account with fake data.

```rust
// VULNERABLE: Read data without checking owner
let config_data = config_account.try_borrow()?;
let admin = &config_data[..32]; // Could be from ANY account!

// SECURE: Verify owner before reading
if config_account.owner() != program_id {
    return Err(ProgramError::IllegalOwner);
}
let config_data = config_account.try_borrow()?;
```

## Attack Scenario

1. Program stores admin pubkey in a config account
2. Vulnerable instruction reads admin from config without ownership check
3. Attacker creates their own account with their pubkey as "admin"
4. Attacker calls vulnerable instruction, passing their fake config
5. Attacker gains admin privileges

## Attack Flow

### Vulnerable Version
```
Attacker                Program                 Accounts
   |                       |                       |
   |--- Create fake        |                       |
   |    config account     |                       |
   |                       |                       |---- Fake Config
   |                       |                       |    (attacker owned)
   |                       |                       |
   |--- Call instruction --|                       |
   |    with fake config   |                       |
   |                       |                       |
   |                       +---- NO OWNER CHECK    |
   |                       |                       |
   |                       +---- Read admin -------+
   |                       |    (from fake config) |
   |                       |                       |
   |                       +---- Grant attacker ---+
   |                       |    admin privileges   |
   |                       |                       |
   |<-- Granted admin -----|                       |
   |    Access!            |                       |

Result: EXPLOIT SUCCESSFUL - Attacker is now admin
```

### Secure Version
```
Attacker                Program                 Accounts
   |                       |                       |
   |--- Create fake        |                       |
   |    config account     |                       |
   |                       |                       |---- Fake Config
   |                       |                       |    (attacker owned)
   |                       |                       |
   |--- Call instruction --|                       |
   |    with fake config   |                       |
   |                       |                       |
   |                       +---- CHECK OWNER ------+
   |                       |    config.owner?      |
   |                       |<------- Fake config   |
   |                       |    owner != program   |
   |                       |                       |
   |                       +---- REJECT! ----------+
   |                       |
   |<-- Error: IllegalOwner|
   |    Access Denied!     |

Result: EXPLOIT BLOCKED - Attacker denied access
```

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry point and instruction routing |
| `vulnerable.rs` | Missing owner check (VULNERABLE) |
| `secure.rs` | Proper owner verification (SECURE) |

## Key Differences

### Vulnerable Version
```rust
pub fn process_read_config(
    _program_id: &Address,  // Ignored!
    accounts: &[AccountView],
) -> ProgramResult {
    let config_account = accounts.first()?;
    
    // NO OWNER CHECK - BUG!
    let config_data = config_account.try_borrow()?;
    let stored_admin = &config_data[..32];
    // ...
}
```

### Secure Version
```rust
pub fn process_read_config(
    program_id: &Address,
    accounts: &[AccountView],
) -> ProgramResult {
    let config_account = accounts.first()?;
    
    // VERIFY OWNER
    if unsafe { config_account.owner() } != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    
    let config_data = config_account.try_borrow()?;
    // Now safe to read...
}
```

## Running Tests

```bash
cargo test -p owner-check-tests
```

## Mitigation Checklist

- Always verify `account.owner == program_id` before reading program-owned data
- In Anchor, use `Account<'info, T>` which automatically verifies ownership
- For system-owned accounts, verify `account.owner == system_program`
- For token accounts, verify `account.owner == token_program`
