# Missing Refund Validation (Escrow)

**Vulnerability**: Escrow refund allows redirection to unauthorized recipient  
**Framework**: Pinocchio (no_std)  

## Overview

This program demonstrates a common escrow vulnerability where the refund instruction does not verify that the refund destination matches the original maker (depositor).

## The Vulnerability

When refunding an escrow, the program must verify the destination matches the stored maker. Without this check, attackers can redirect refunds to themselves.

```rust
// VULNERABLE: No verification that destination is the maker
let destination = accounts[3];  // Attacker can pass any account!
transfer_tokens(escrow_vault, destination, amount)?;

// SECURE: Verify destination matches stored maker
if destination.key() != escrow.maker {
    return Err(ProgramError::InvalidAccountData);
}
```

## Attack Scenario

1. Alice creates escrow depositing 100 tokens
2. Trade does not complete, Alice requests refund
3. Attacker front-runs with their own refund call
4. Attacker passes their wallet as destination
5. Attacker receives Alice's 100 tokens

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Entry point and instruction routing |
| `state.rs` | Escrow account structure |
| `instructions/` | |
| `make.rs` | Create escrow |
| `take.rs` | Complete trade |
| `vulnerable_refund.rs` | No maker verification (VULNERABLE) |
| `secure_refund.rs` | Proper maker check (SECURE) |

## Key Differences

### Vulnerable Version
```rust
pub fn process_vulnerable_refund(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let escrow = accounts[0];
    let destination = accounts[3];  // No verification!
    
    // Transfers to whoever was passed as destination
    transfer_tokens_to(destination, escrow.amount)?;
    Ok(())
}
```

### Secure Version
```rust
pub fn process_secure_refund(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let escrow = accounts[0];
    let destination = accounts[3];
    let caller = accounts[1];
    
    // VERIFY: Only maker can refund, and only to themselves
    if caller.key.as_ref() != &escrow_data.maker {
        return Err(ProgramError::InvalidAccountData);
    }
    
    transfer_tokens_to(destination, escrow.amount)?;
    Ok(())
}
```

## Running Tests

```bash
cargo test -p p-escrow-tests
```

## Mitigation Checklist

- Store maker pubkey in escrow account
- Verify caller is maker before allowing refund
- Verify destination matches stored maker
- Use Anchor's `has_one` constraint for automatic verification
- Consider time-locked refunds to prevent race conditions
