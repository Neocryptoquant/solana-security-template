# Missing Signer Check

**Vulnerability**: Authorization bypass via missing signature verification  
**Framework**: Anchor  

## Overview

This program demonstrates the Missing Signer Check vulnerability where an instruction accepts an authority account without verifying it actually signed the transaction.

## The Vulnerability

In Solana, anyone can pass any public key as an account. If your program does not verify that critical accounts (like authorities) actually signed the transaction, attackers can impersonate them.

```rust
// VULNERABLE: UncheckedAccount does not verify signature
pub authority: UncheckedAccount<'info>,

// SECURE: Signer type enforces signature verification
pub authority: Signer<'info>,
```

## Attack Scenario

1. Alice creates a vault with herself as authority
2. Attacker observes Alice's vault and authority pubkey
3. Attacker calls `vulnerable_withdraw`, passing Alice's pubkey (without signing)
4. Funds are drained because signature was not verified

## Attack Flow

### Vulnerable Version
```
Attacker                Program              Transaction
   |                       |                      |
   |--- Observe Alice's ---|                      |
   |    vault pubkey       |                      |
   |                       |                      |
   |--- Create unsigned ---|                      |
   |    withdraw tx        |                      |
   |    (Alice's key, no sig)                     |
   |                       |                      |
   |--- Submit ------------|--- Validation -------+
   |    withdraw           |    |                 |
   |    instruction        |    |-- Is Alice      |
   |                       |    |   account valid?|
   |                       |    |-- NO SIGNER     |
   |                       |    |   CHECK!        |
   |                       |    |                 |
   |                       +--- Accept and -------+
   |                       |    transfer funds    |
   |                       |                      |
   |<-- Funds received ----|--- Transfer complete +
   |                       |                      |

Result: EXPLOIT SUCCESSFUL - Attacker steals funds
```

### Secure Version
```
Attacker                Program              Transaction
   |                       |                      |
   |--- Observe Alice's ---|                      |
   |    vault pubkey       |                      |
   |                       |                      |
   |--- Create unsigned ---|                      |
   |    withdraw tx        |                      |
   |    (Alice's key, no sig)                     |
   |                       |                      |
   |--- Submit ------------|--- Validation -------+
   |    withdraw           |    |                 |
   |    instruction        |    |-- Is Alice      |
   |                       |    |   account valid?|
   |                       |    |-- YES           |
   |                       |    |                 |
   |                       |    |-- Is Alice      |
   |                       |    |   a SIGNER?     |
   |                       |    |-- NO!           |
   |                       |    |                 |
   |                       +--- Reject! ----------+
   |                       |    (Signer missing)  |
   |                       |                      |
   |<-- Error: ------------|--- Tx Failed         |
   |    Unauthorized       |                      |
   |    Access Denied!     |                      |

Result: EXPLOIT BLOCKED - Transaction rejected
```

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry points |
| `state.rs` | Vault account structure |
| `initialize.rs` | Vault initialization logic |
| `vulnerable.rs` | Missing signer check (VULNERABLE) |
| `secure.rs` | Proper signer validation (SECURE) |
| `error.rs` | Custom error types |

## Key Differences

### Vulnerable Version
```rust
#[derive(Accounts)]
pub struct VulnerableWithdraw<'info> {
    #[account(mut, seeds = [b"vault", authority.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    
    /// CHECK: VULNERABLE - Not validated as signer
    pub authority: UncheckedAccount<'info>,  // Anyone can pass this!
}
```

### Secure Version
```rust
#[derive(Accounts)]
pub struct SecureWithdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump,
        constraint = vault.authority == authority.key() @ VaultError::UnauthorizedAuthority
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,  // Must sign the transaction!
}
```

## Running Tests

```bash
cargo test -p signer-authorization-tests
```

## Mitigation Checklist

- Use `Signer<'info>` for all authority accounts
- Add constraint checks to verify stored authority matches signer
- Never use `UncheckedAccount` for accounts that require authorization
