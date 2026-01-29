# Weak PDA Seeds

**Vulnerability**: Predictable or weak seeds allowing PDA collision/front-running  
**Framework**: Anchor  

## Overview

This program demonstrates vulnerabilities related to weak PDA seed construction, including predictable seeds and insufficient uniqueness that enables front-running or collision attacks.

## The Vulnerability

PDAs are derived deterministically from seeds. If seeds are predictable or insufficient, attackers can:
1. Front-run account creation
2. Create colliding PDAs  
3. Impersonate or hijack user accounts

```rust
// VULNERABLE: Only user pubkey - predictable, no uniqueness
seeds = [b"user", user.key().as_ref()]

// SECURE: Includes random nonce for uniqueness
seeds = [b"user", user.key().as_ref(), &nonce.to_le_bytes()]
```

## Attack Scenario

1. Attacker monitors pending transactions
2. Before victim's `create_user` confirms, attacker computes same PDA
3. Attacker front-runs with their own transaction
4. Victim's transaction fails (account already exists) or worse, uses attacker's account

## Attack Flow

### Vulnerable Version
```
Victim              Attacker           Blockchain
 |                    |                     |
 |-- Prepare tx ------|                     |
 |   create_user      |                     |
 |                    |-- Observe pending tx|
 |                    |                     |
 |                    |-- Compute PDA ------+
 |                    |   (same as victim)  |
 |                    |                     |
 |-- Send tx ---------|-- Front-run --------+
 |                    |   Create same PDA   |
 |                    |                     |
 |                    |   Attacker owns     |
 |                    |   the PDA now!      |
 |                    |                     |
 |                    +-- Victim tx: -------+
 |                    |   "Account exists"  |
 |                    |   FAILS!            |
 |                    |                     |
 |<-- Error! ---------+<-- Success! --------+
 |   Cannot create    |   Attacker hijacked!|

Result: EXPLOIT SUCCESSFUL - Attacker hijacks account
```

### Secure Version
```
Victim              Attacker           Blockchain
 |                    |                     |
 |-- Create random ---|                     |
 |   nonce            |                     |
 |                    |                     |
 |-- Prepare tx ------|                     |
 |   create_user      |-- Observe pending tx|
 |   (with nonce)     |                     |
 |                    |-- Try to compute ---+
 |                    |   PDA (need nonce)  |
 |                    |                     |
 |                    |   No way to know    |
 |                    |   victim's nonce!   |
 |                    |                     |
 |-- Send tx ---------|-- Cannot front-run! |
 |                    |                     |
 |                    +-- Even if attacker  |
 |                    |   creates account,  |
 |                    |   it's different!   |
 |                    |   (different nonce) |
 |                    |                     |
 |<-- Success! -------+<-- Fails! ----------+
 |   Account created  |   Exploit blocked!  |
 |   with victim nonce|                     |

Result: EXPLOIT BLOCKED - Nonce prevents front-running
```

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry points |
| `state.rs` | User account structure |
| `vulnerable.rs` | Weak seeds (user pubkey only) (VULNERABLE) |
| `secure.rs` | Strong seeds (includes nonce) (SECURE) |
| `error.rs` | Custom error types |

## Key Differences

### Vulnerable Version
```rust
#[account(
    init,
    payer = user,
    space = 8 + 32 + 8,
    // WEAK: Any observer can compute this PDA
    seeds = [b"user", user.key().as_ref()],
    bump
)]
pub user_account: Account<'info, UserAccount>,
```

### Secure Version
```rust
#[account(
    init,
    payer = user,
    space = 8 + 32 + 8 + 8,
    // STRONG: Includes random nonce
    seeds = [b"user", user.key().as_ref(), &nonce.to_le_bytes()],
    bump
)]
pub user_account: Account<'info, UserAccountSecure>,
```

## Running Tests

```bash
cargo test -p pda-seeds-tests
```

## Mitigation Checklist

- Include user-controlled random nonce in seeds
- Use Anchor's canonical bump handling (`bump` constraint)
- Never store user-provided bump - derive fresh each time
- For global config, use program authority as seed
- Document seed structure for each PDA type
