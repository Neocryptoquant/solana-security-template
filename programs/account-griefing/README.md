# Account Creation Griefing

**Vulnerability**: DOS attack on seed-based account creation  
**Framework**: Anchor  
**Source**: J4X_Security (2026)

## Overview

This program demonstrates the Account Creation Griefing vulnerability where attackers can permanently block users from creating accounts by pre-funding the target PDA address.

## The Vulnerability

The Solana `system_instruction::create_account()` function reverts if the target address already contains any lamports. Attackers can exploit this by:

1. Computing the deterministic PDA for a victim
2. Sending minimal rent-exempt lamports (~0.002 SOL) to that address
3. The victim's `create_account` call now fails permanently

```rust
// VULNERABLE: Predictable PDA - attacker can compute and fund
seeds = [b"stake", user.key().as_ref()]

// SECURE: Nonce makes address unpredictable
seeds = [b"stake", user.key().as_ref(), &random_nonce.to_le_bytes()]
```

## Attack Scenario

1. Protocol uses deterministic PDAs for user stake accounts
2. Attacker monitors for new users or targets specific victims
3. Attacker computes victim's stake PDA using known seeds
4. Attacker sends 0.002 SOL to the PDA address
5. Victim tries to create stake account - FAILS
6. Victim cannot change the address (seeds are fixed)
7. Victim is permanently blocked from staking

## Attack Flow

### Vulnerable Version
```
Attacker             Victim               Blockchain
   |                    |                      |
   |-- Compute PDA -----|                      |
   |   seeds: ["stake", victim_pubkey]         |
   |                    |                      |
   |-- Send 0.002 SOL --|                      |
   |   to stake PDA     +--- PDA has lamports |
   |                    |                      |
   |                    |-- create_account() --|
   |                    |   for stake PDA      |
   |                    |                      |
   |                    |                +-- REVERT!
   |                    |                |   Address funded
   |                    |                      |
   |                    |<-- Error: -----------+
   |                    |    Cannot create     |
   |                    |    (address in use)  |
   |                    |                      |
   |   Victim blocked!  |                      |
   |   Cost: 0.002 SOL  |                      |
```

### Secure Version
```
Attacker             Victim               Blockchain
   |                    |                      |
   |-- Compute PDA? ----|                      |
   |   Need nonce...    |                      |
   |   (unknown!)       |                      |
   |                    |                      |
   |                    |-- Choose random -----|
   |                    |   nonce: 847291      |
   |                    |                      |
   |                    |-- create_account() --|
   |                    |   seeds include nonce|
   |                    |                      |
   |   Cannot predict!  +--- Success! --------+
   |                    |   Account created    |
   |                    |                      |
   |   Attack FAILED    |                      |
```

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry points |
| `state.rs` | Stake account structures |
| `vulnerable.rs` | Predictable seeds (VULNERABLE) |
| `secure.rs` | Nonce-based seeds + init_if_needed (SECURE) |
| `error.rs` | Custom error types |

## Key Differences

### Vulnerable Version
```rust
#[account(
    init,
    payer = user,
    space = 8 + StakeAccount::INIT_SPACE,
    // VULNERABLE: Only user pubkey - predictable!
    seeds = [b"stake", user.key().as_ref()],
    bump
)]
pub stake_account: Account<'info, StakeAccount>,
```

### Secure Version (Option 1: Random Nonce)
```rust
#[account(
    init,
    payer = user,
    space = 8 + SecureStakeAccount::INIT_SPACE,
    // SECURE: Nonce makes address unpredictable
    seeds = [b"stake", user.key().as_ref(), &nonce.to_le_bytes()],
    bump
)]
pub stake_account: Account<'info, SecureStakeAccount>,
```

### Secure Version (Option 2: Handle Pre-funded)
```rust
#[account(
    init_if_needed,  // Handles existing accounts
    payer = user,
    space = 8 + StakeAccount::INIT_SPACE,
    seeds = [b"stake", user.key().as_ref()],
    bump
)]
pub stake_account: Account<'info, StakeAccount>,

// ALWAYS check is_initialized in handler!
if self.stake_account.is_initialized {
    return Ok(());  // Already set up, skip
}
```

## Running Tests

```bash
cargo test -p security-tests --test account_griefing
```

## Mitigation Checklist

- Include random nonce in PDA seeds for user-specific accounts
- Use init_if_needed with mandatory is_initialized checks
- For protocol initialization, use off-chain randomness
- Consider time-locked creation windows for critical PDAs
- Document which PDAs could be targeted by griefing attacks
