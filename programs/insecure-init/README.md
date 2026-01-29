# Insecure Initialization

**Vulnerability**: Re-initialization attack allowing admin takeover  
**Framework**: Anchor  

## Overview

This program demonstrates the Insecure Initialization vulnerability where critical program state (like admin configuration) can be re-initialized by attackers to take control.

## The Vulnerability

If initialization logic does not check whether an account is already initialized, attackers can call initialize again to overwrite the admin:

```rust
// VULNERABLE: init_if_needed without is_initialized check
#[account(init_if_needed, payer = payer, space = 64, seeds = [b"config"], bump)]
pub config: Account<'info, Config>,

pub fn initialize(&mut self, admin: Pubkey) {
    self.config.admin = admin;  // Overwrites existing!
}

// SECURE: Use `init` which fails if account exists
#[account(init, payer = payer, space = 64, seeds = [b"config"], bump)]
pub config: Account<'info, Config>,

// OR: Check is_initialized flag
require!(!self.config.is_initialized, Error::AlreadyInitialized);
```

## Attack Scenario

1. Protocol deploys with Alice as admin
2. Attacker calls `vulnerable_initialize(attacker_pubkey)`
3. Config.admin is overwritten to attacker's pubkey
4. Attacker now has full admin privileges
5. Attacker drains protocol funds via admin functions

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry points |
| `state.rs` | Config account with is_initialized flag |
| `vulnerable.rs` | init_if_needed without guard (VULNERABLE) |
| `secure.rs` | init constraint OR is_initialized check (SECURE) |
| `error.rs` | Custom error types |

## Key Differences

### Vulnerable Version
```rust
#[account(
    init_if_needed,  // DANGEROUS: allows re-init!
    payer = payer,
    space = Config::SIZE,
    seeds = [b"config"],
    bump
)]
pub config: Account<'info, Config>,

pub fn initialize(&mut self, admin: Pubkey) -> Result<()> {
    // NO CHECK - just overwrites
    self.config.admin = admin;
    Ok(())
}
```

### Secure Version (Option 1: Use `init`)
```rust
#[account(
    init,  // Fails if account already exists
    payer = payer,
    space = Config::SIZE,
    seeds = [b"config"],
    bump
)]
pub config: Account<'info, Config>,
```

### Secure Version (Option 2: Check flag)
```rust
pub fn initialize(&mut self, admin: Pubkey) -> Result<()> {
    require!(!self.config.is_initialized, InitError::AlreadyInitialized);
    self.config.admin = admin;
    self.config.is_initialized = true;
    Ok(())
}
```

## Running Tests

```bash
cargo test -p insecure-init-tests
```

## Mitigation Checklist

- Prefer `init` over `init_if_needed` for one-time initialization
- If using `init_if_needed`, ALWAYS check `is_initialized` flag
- Add `is_initialized: bool` to all config accounts
- Consider making admin transfer a separate, protected instruction
- Audit all initialization paths for re-init vulnerabilities
