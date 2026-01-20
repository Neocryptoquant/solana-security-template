# Solana Security Template

A collection of Solana programs demonstrating common vulnerabilities and their fixes. Each program includes vulnerable and secure implementations with LiteSVM tests on each program.

## Requirements

- Rust 1.89.0
- Solana CLI 3.0.11
- Anchor 0.32.1

## Setup

```bash
# Clone
git clone https://github.com/Ubuntu-Technologies/solana-security-template.git
cd solana-security-template

# Build all programs
anchor run build-all

# Run tests
anchor run test
```

## Programs

| Program | Vulnerability | Framework |
|---------|--------------|-----------|
| signer-authorization | Missing `is_signer` check | Anchor |
| arithmetic-overflow | Unchecked u64 multiplication | Anchor |
| owner-check | No `account.owner` validation | Pinocchio |
| pda-seeds | Predictable PDA seeds | Anchor |
| account-close | Revival attack (data not zeroed) | Anchor |
| account-type-mismatch | Missing discriminator | Pinocchio |
| p-escrow | Missing refund recipient check | Pinocchio |

### AMM Examples

Two consolidated programs showing multiple vulnerabilities in a realistic context:

**buggy-amm** - All vulnerabilities combined in a program that still works:
- Weak PDA seeds (`b"config"` only)
- No token account ownership validation
- Unchecked `u64 * u64` overflow
- Slippage parameter ignored
- No vault owner verification

**secure-amm** - Fixed implementation with inline comments explaining each fix.

## Vulnerability Details

### 1. Missing Signer Check

```rust
// VULNERABLE: No verification that authority signed
pub authority: AccountInfo<'info>,

// SECURE: Anchor's Signer constraint
pub authority: Signer<'info>,
```

### 2. Arithmetic Overflow

```rust
// VULNERABLE: Wraps on large values
let result = a * b;

// SECURE: Returns error on overflow
let result = a.checked_mul(b).ok_or(ErrorCode::Overflow)?;
```

### 3. Missing Owner Check

```rust
// VULNERABLE: Trusts account data without owner verification
let data = account.data.borrow();

// SECURE: Verify owner before reading
if account.owner != program_id {
    return Err(ProgramError::IncorrectProgramId);
}
```

### 4. Weak PDA Seeds

```rust
// VULNERABLE: Globally predictable
seeds = [b"config"]

// SECURE: Unique per user
seeds = [b"config", user.key().as_ref(), &nonce.to_le_bytes()]
```

### 5. Account Revival

```rust
// VULNERABLE: Just transfer lamports
**dest.lamports.borrow_mut() += account.lamports();
**account.lamports.borrow_mut() = 0;

// SECURE: Zero data first, then close
account.data.borrow_mut().fill(0);
account.close(dest)?;
```

### 6. Missing Discriminator

```rust
// VULNERABLE: No type identification
struct UserData { balance: u64 }

// SECURE: First byte identifies type
struct UserData { discriminator: u8, balance: u64 }
```

### 7. Missing Refund Validation

```rust
// VULNERABLE: Anyone can redirect refund
let destination = accounts[3];

// SECURE: Verify caller is maker
if caller.key() != escrow.maker {
    return Err(ProgramError::InvalidAccountData);
}
```

## Testing

28 tests across 8 test files using LiteSVM 0.6.1:

```
signer_authorization    3 tests
arithmetic_overflow     3 tests
owner_check            3 tests
pda_seeds              4 tests
account_close          3 tests
account_type_mismatch  3 tests
p_escrow               3 tests
amm                    6 tests
```

Each test demonstrates that the vulnerable version accepts the attack, while the secure version mitigates the attack. Normal operations work on both versions.

## Project Structure

```
programs/
├── signer-authorization/   # Anchor
├── arithmetic-overflow/    # Anchor
├── owner-check/           # Pinocchio
├── pda-seeds/             # Anchor
├── account-close/         # Anchor
├── account-type-mismatch/ # Pinocchio
├── p-escrow/              # Pinocchio
└── amm/
    ├── buggy-amm/         # Anchor
    └── secure-amm/        # Anchor

tests/
├── signer_authorization.rs
├── arithmetic_overflow.rs
├── owner_check.rs
├── pda_seeds.rs
├── account_close.rs
├── account_type_mismatch.rs
├── p_escrow.rs
└── amm.rs
```

## Versions

| Component | Version |
|-----------|---------|
| Rust | 1.89.0 |
| Solana CLI | 3.0.11 |
| Anchor | 0.32.1 |
| Pinocchio | 0.9.2 / 0.10 |
| LiteSVM | 0.6.1 |

## License

MIT
