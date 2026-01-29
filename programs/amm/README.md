# AMM Vulnerability Suite

**Vulnerabilities**: Multiple combined in realistic DeFi context  
**Framework**: Anchor  

## Overview

This directory contains two companion programs demonstrating real-world AMM vulnerabilities in context:

| Program | Purpose |
|---------|---------|
| **buggy-amm** | Multiple intentional vulnerabilities (VULNERABLE) |
| **secure-amm** | Properly secured implementation (SECURE) |

## Vulnerabilities Demonstrated

### 1. Weak PDA Seeds
```rust
// buggy-amm: Globally predictable seeds (VULNERABLE)
seeds = [b"config"]

// secure-amm: Unique per creator + seed (SECURE)
seeds = [b"amm", authority.key().as_ref(), &seed.to_le_bytes()]
```

### 2. Unchecked Arithmetic Overflow
```rust
// buggy-amm: Raw multiplication overflows (VULNERABLE)
let product = amount_x * amount_y;

// secure-amm: u128 intermediates + checked math (SECURE)
let product = (amount_x as u128)
    .checked_mul(amount_y as u128)
    .ok_or(AmmError::MathOverflow)?;
```

### 3. Missing Slippage Protection
```rust
// buggy-amm: min_out parameter ignored! (VULNERABLE)
pub fn swap(ctx: Context<Swap>, amount_in: u64, _min_out: u64)

// secure-amm: Enforced slippage check (SECURE)
require!(amount_out >= min_out, AmmError::SlippageExceeded);
```

### 4. Missing Token Account Ownership Validation
```rust
// buggy-amm: No vault ownership verification (VULNERABLE)
pub user_token_x: Account<'info, TokenAccount>,

// secure-amm: Verify vault is owned by config PDA (SECURE)
#[account(
    token::mint = mint_x,
    token::authority = config
)]
pub vault_x: Account<'info, TokenAccount>,
```

### 5. No Vault Authority Verification
```rust
// buggy-amm: Deposits without verifying vault ownership (VULNERABLE)
pub vault_x: Account<'info, TokenAccount>,

// secure-amm: Vault authority must match config (SECURE)
constraint = vault_x.owner == config.key()
```

## File Structure

```
amm/
├── buggy-amm/
│   └── src/
│       ├── lib.rs
│       ├── state.rs
│       └── instructions/
│           ├── initialize.rs  # Weak seeds
│           ├── deposit.rs     # Missing validation
│           ├── swap.rs        # Overflow + no slippage
│           └── withdraw.rs    # Missing checks
│
└── secure-amm/
    └── src/
        ├── lib.rs
        ├── state.rs
        └── instructions/
            ├── initialize.rs  # Strong seeds
            ├── deposit.rs     # Full validation
            ├── swap.rs        # Checked math + slippage
            └── withdraw.rs    # Complete security
```

## Running Tests

```bash
cargo test -p amm-tests
```

## Test Coverage

| Test | buggy-amm | secure-amm |
|------|-----------|------------|
| Normal swap | Works | Works |
| Overflow exploit | Succeeds (bad!) | Fails correctly |
| Slippage bypass | Succeeds (bad!) | Fails correctly |
| Unauthorized access | Succeeds (bad!) | Fails correctly |

## Key Learnings

1. **Never ignore slippage parameters** - Always enforce min_out/max_in
2. **Use u128 for intermediates** - Prevent overflow in multiplication
3. **Verify all account relationships** - Do not trust caller-provided accounts
4. **Use strong PDA seeds** - Include authority + nonce to prevent prediction
5. **Combine defenses** - Real exploits chain multiple vulnerabilities
