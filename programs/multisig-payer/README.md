# Multisig as Payer (PDA Signing Limitation)

**Vulnerability**: Using PDA as payer for account creation  
**Framework**: Anchor  
**Source**: J4X_Security (2026)

## Overview

This program demonstrates the Multisig as Payer anti-pattern where a PDA authority is incorrectly used as the payer for account creation, causing transactions to always fail.

## The Vulnerability

PDAs cannot sign System Program operations. When you use a PDA as the `payer` in Anchor's `init` constraint:

1. Anchor generates a CPI to `system_program::create_account`
2. This requires the payer to sign a transfer of lamports
3. PDAs can only sign CPIs to programs that derived them
4. The System Program did not derive your PDA - it fails

```rust
// VULNERABLE: PDA cannot sign system transfers
#[account(
    init,
    payer = multisig_treasury,  // PDA as payer - ALWAYS FAILS!
    space = 8 + Proposal::INIT_SPACE,
    seeds = [b"proposal", &id.to_le_bytes()],
    bump
)]
pub proposal: Account<'info, Proposal>,

// SECURE: Separate rent payer from authority
#[account(mut)]
pub rent_payer: Signer<'info>,  // Regular signer pays rent

#[account(
    init,
    payer = rent_payer,  // Works correctly
    ...
)]
pub proposal: Account<'info, Proposal>,
```

## Attack Scenario

This is not an "attack" per se - it is a design flaw that breaks functionality:

1. DAO uses multisig PDA as authority
2. DAO tries to create new proposal accounts
3. Multisig PDA is set as payer in `init` constraint
4. Transaction FAILS with "unauthorized signer"
5. DAO cannot create proposals - governance is broken

## Error Messages

You will see errors like:
- "Cross-program invocation with unauthorized signer or writable account"
- "Transfer: `from` must not carry data"
- "instruction spent from the balance of an account it does not own"

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry points |
| `state.rs` | DAO and proposal structures |
| `vulnerable.rs` | PDA as payer (VULNERABLE) |
| `secure.rs` | Separate rent payer (SECURE) |
| `error.rs` | Custom error types |

## Key Differences

### Vulnerable Version
```rust
#[derive(Accounts)]
pub struct VulnerableCreateProposal<'info> {
    /// Treasury PDA - CANNOT be a payer!
    #[account(mut)]
    pub treasury: Account<'info, MultisigTreasury>,

    #[account(
        init,
        payer = treasury,  // BUG: PDA cannot sign!
        space = 8 + Proposal::INIT_SPACE,
        seeds = [b"proposal", &proposal_id.to_le_bytes()],
        bump
    )]
    pub proposal: Account<'info, Proposal>,
    // ...
}
```

### Secure Version
```rust
#[derive(Accounts)]
pub struct SecureCreateProposal<'info> {
    /// Regular signer pays rent - no authority role
    #[account(mut)]
    pub rent_payer: Signer<'info>,

    /// Treasury PDA validates authority only
    pub treasury: Account<'info, MultisigTreasury>,

    #[account(
        init,
        payer = rent_payer,  // Regular signer pays
        space = 8 + Proposal::INIT_SPACE,
        seeds = [b"proposal", &proposal_id.to_le_bytes()],
        bump
    )]
    pub proposal: Account<'info, Proposal>,
    // ...
}
```

## Running Tests

```bash
cargo test -p security-tests --test multisig_payer
```

## Design Patterns

### Pattern 1: Separate Rent Payer
```
rent_payer: Signer<'info>     --> Pays for account creation
authority: Account<MultisigPDA> --> Validates permissions
```

### Pattern 2: Creator Pays
```
creator: Signer<'info>        --> Creates AND pays for account
authority: Account<MultisigPDA> --> Validates creator has permission
```

### Pattern 3: Protocol Treasury (via CPI)
```
treasury: Account<'info>      --> Holds funds
program: --                   --> Uses invoke_signed to transfer from treasury
--                            --> NOT using init constraint for this
```

## Mitigation Checklist

- Never use PDAs as `payer` in `init` constraints
- Separate "authority" (permission validation) from "payer" (rent funding)
- Use regular Signer accounts for rent payment
- Document which accounts are authorities vs payers
- For treasury-funded operations, use manual CPI with invoke_signed
