# Duplicate Mutable Accounts

**Vulnerability**: Passing the same account twice as different mutable parameters  
**Framework**: Anchor  

## Overview

This program demonstrates the Duplicate Mutable Accounts vulnerability where an attacker passes the same account for both source and destination in a transfer operation, causing unexpected balance manipulation.

## The Vulnerability

When a program accepts two mutable accounts without verifying they are different, passing the same account twice can cause unexpected behavior:

```rust
// VULNERABLE: No check that accounts are different
#[account(mut)]
pub from_account: Account<'info, UserBalance>,
#[account(mut)]
pub to_account: Account<'info, UserBalance>,  // Could be same as from!

// SECURE: Constraint prevents duplicates
#[account(
    mut,
    constraint = from_account.key() != to_account.key() @ Error::DuplicateAccounts
)]
pub to_account: Account<'info, UserBalance>,
```

## Attack Scenario

1. Alice has account with 100 tokens
2. Attacker calls `transfer(50)` passing Alice's account as BOTH from AND to
3. Program debits 50: balance = 50
4. Program credits 50: balance = 100 (same account!)
5. Net effect: Nothing changed, but event shows transfer happened
6. In some cases (order of operations), can create tokens from nothing

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry points and initialize |
| `state.rs` | UserBalance account structure |
| `vulnerable.rs` | No duplicate check (VULNERABLE) |
| `secure.rs` | Constraint prevents duplicates (SECURE) |
| `error.rs` | Custom error types |

## Key Differences

### Vulnerable Version
```rust
#[derive(Accounts)]
pub struct VulnerableTransfer<'info> {
    #[account(mut)]
    pub from_account: Account<'info, UserBalance>,
    
    #[account(mut)]
    pub to_account: Account<'info, UserBalance>,  // No uniqueness check!
}
```

### Secure Version
```rust
#[derive(Accounts)]
pub struct SecureTransfer<'info> {
    #[account(mut)]
    pub from_account: Account<'info, UserBalance>,
    
    #[account(
        mut,
        constraint = from_account.key() != to_account.key() @ TransferError::DuplicateAccounts
    )]
    pub to_account: Account<'info, UserBalance>,  // Must be different!
}
```

## Running Tests

```bash
cargo test -p duplicate-accounts-tests
```

## Mitigation Checklist

- Add `constraint` checking account keys are different
- Use Anchor's built-in duplicate account detection when available
- Audit all instructions with multiple mutable accounts of same type
- Consider using account discriminators to prevent type confusion
