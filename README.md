# Solana Security Template

![CI](https://github.com/Ubuntu-Technologies/solana-security-template/actions/workflows/ci.yml/badge.svg)

A collection of Solana programs demonstrating common smart contract vulnerabilities and their fixes. Each program includes vulnerable and secure implementations with tests that prove exploits fail after remediation.

## Overview

This repository provides hands-on examples of 12 critical vulnerabilities in Solana programs. Each vulnerability is isolated in its own program with:

- **Vulnerable implementation** — Code that can be exploited
- **Secure implementation** — The same code with proper defenses
- **LiteSVM tests** — Demonstrates the exploit and verifies the fix

The programs use both Anchor and Pinocchio frameworks to show patterns across different development approaches.

## Getting Started

### Requirements

| Component | Version |
|-----------|---------|
| Rust | 1.89.0 |
| Solana CLI | 2.2.1+ |
| Anchor | 0.32.1 |

### Installation

```bash
git clone https://github.com/Ubuntu-Technologies/solana-security-template.git
cd solana-security-template

# Build all programs
anchor run build-all

# Run tests
anchor run test

# Run fuzz tests (optional)
cd trident-tests/fuzz_targets && cargo test
```

### Learning Path

1. Start with [owner-check](programs/owner-check/) — the simplest vulnerability to understand
2. Read the vulnerable code and its comments
3. Read the secure code to see the fix
4. Run tests to observe the exploit fail against the secure version
5. Progress to more complex vulnerabilities

## Vulnerability Coverage

| Vulnerability | Program | Severity | Framework | Mitigation |
|--------------|---------|----------|-----------|------------|
| Missing Signer Check | [signer-authorization](programs/signer-authorization/) | Critical | Anchor | Use `Signer<'info>` type |
| Integer Overflow | [arithmetic-overflow](programs/arithmetic-overflow/) | Critical | Anchor | Use `checked_*` methods |
| Missing Owner Check | [owner-check](programs/owner-check/) | Critical | Pinocchio | Verify `account.owner == program_id` |
| Weak PDA Seeds | [pda-security](programs/pda-security/) | High | Anchor | Include user key + nonce in seeds |
| Account Revival | [account-close](programs/account-close/) | High | Anchor | Zero data before close |
| Discriminator Bypass | [account-type-mismatch](programs/account-type-mismatch/) | High | Pinocchio | Add discriminator byte |
| Missing Validation | [p-escrow](programs/p-escrow/) | High | Pinocchio | Verify caller matches stored data |
| Duplicate Accounts | [duplicate-accounts](programs/duplicate-accounts/) | High | Anchor | Add `key() != key()` constraint |
| Insecure Init | [insecure-init](programs/insecure-init/) | High | Anchor | Use `init` or check `is_initialized` |
| Stale Data After CPI | [account-reloading](programs/account-reloading/) | Medium | Anchor | Call `reload()` after CPI |
| Unvalidated Remaining | [remaining-accounts](programs/remaining-accounts/) | Medium | Anchor | Validate owner and type manually |
| Insecure Authority | [authority-transfer](programs/authority-transfer/) | Critical | Anchor | Two-step propose/accept pattern |
| Multiple Combined | [amm](programs/amm/) | Critical | Anchor | All of the above |

## Quick Reference

### Authorization

```rust
// Vulnerable: No signature verification
pub authority: AccountInfo<'info>

// Secure: Requires signature
pub authority: Signer<'info>
```

### Arithmetic

```rust
// Vulnerable: Can overflow
let result = a * b;

// Secure: Returns error on overflow
let result = a.checked_mul(b).ok_or(MathError::Overflow)?;
```

### Account Ownership

```rust
// Vulnerable: Trusts any account
let data = account.data();

// Secure: Verifies program owns account
require!(account.owner == program_id, Error::InvalidOwner);
```

### PDA Derivation

```rust
// Vulnerable: Predictable seeds
seeds = [b"config"]

// Secure: Unpredictable with user-provided nonce
seeds = [b"config", user.key().as_ref(), &nonce.to_le_bytes()]
```

### Account Closure

```rust
// Vulnerable: Data persists after lamport transfer
**account.lamports.borrow_mut() = 0;

// Secure: Zero data before closing
account.data.borrow_mut().fill(0);
account.close(destination)?;
```

### Discriminator Validation

```rust
// Vulnerable: No type identification
struct User { pubkey: Pubkey, balance: u64 }

// Secure: Discriminator identifies account type
struct User { discriminator: u8, pubkey: Pubkey, balance: u64 }
```

### Duplicate Account Prevention

```rust
// Vulnerable: Same account can be passed twice
#[account(mut)]
pub from: Account<'info, Balance>,
#[account(mut)]
pub to: Account<'info, Balance>,

// Secure: Constraint prevents duplicates
#[account(mut, constraint = from.key() != to.key())]
pub from: Account<'info, Balance>,
```

### Initialization Guard

```rust
// Vulnerable: Can be reinitialized
#[account(init_if_needed, ...)]
pub config: Account<'info, Config>,

// Secure: Explicit check
require!(!config.is_initialized, Error::AlreadyInitialized);
```

### CPI Data Refresh

```rust
// Vulnerable: Stale data after CPI
invoke(&transfer_ix, accounts)?;
let balance = account.balance; // Stale

// Secure: Reload after CPI
invoke(&transfer_ix, accounts)?;
account.reload()?;
let balance = account.balance; // Fresh
```

### Authority Transfer

```rust
// Vulnerable: Immediate transfer
config.authority = new_authority;

// Secure: Two-step process
config.pending_authority = Some(new_authority);
// ... new authority must call accept() ...
```

## Project Structure

```
programs/
├── signer-authorization/     # Missing signer check
├── arithmetic-overflow/      # Integer overflow
├── owner-check/              # Missing owner check (Pinocchio)
├── pda-security/             # Weak PDA seeds
├── account-close/            # Account revival
├── account-type-mismatch/    # Discriminator bypass (Pinocchio)
├── p-escrow/                 # Missing validation (Pinocchio)
├── duplicate-accounts/       # Duplicate mutable accounts
├── insecure-init/            # Re-initialization
├── account-reloading/        # Stale data after CPI
├── remaining-accounts/       # Unvalidated remaining accounts
├── authority-transfer/       # Insecure authority transfer
└── amm/
    ├── buggy-amm/            # Multiple vulnerabilities combined
    └── secure-amm/           # Fixed implementation
```

Each program contains:
- `README.md` — Vulnerability explanation
- `src/lib.rs` — Program entry points
- `src/vulnerable.rs` — Exploitable implementation
- `src/secure.rs` — Fixed implementation

## Additional Resources

- [Security Checklist](SECURITY_CHECKLIST.md) — Pre-deployment checklist
- [Trident Fuzzing](trident-tests/README.md) — Fuzz testing for edge cases
- [Contributing](CONTRIBUTING.md) — How to contribute

## Dependencies

| Package | Version |
|---------|---------|
| Anchor | 0.32.1 |
| Pinocchio | 0.9.2 / 0.10 |
| LiteSVM | 0.6.1 |
| Trident | 0.12.0 |

## License

MIT
