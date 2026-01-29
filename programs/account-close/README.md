# Account Revival Attack

**Vulnerability**: Improper account closure allowing revival and stale data access  
**Framework**: Anchor  

## Overview

This program demonstrates the Account Revival vulnerability where improperly closed accounts can be revived within the same transaction, potentially exposing stale data or allowing re-initialization.

## The Vulnerability

When closing an account:
1. Lamports are transferred to destination
2. If data is not zeroed, stale data remains
3. Attacker can send lamports back in same transaction
4. Account is "revived" with old data

```rust
// VULNERABLE: Only transfer lamports, data not zeroed
**dest.lamports.borrow_mut() += account.lamports();
**account.lamports.borrow_mut() = 0;

// SECURE: Zero data first, then close properly
account.data.borrow_mut().fill(0);  // Zero data
account.close(destination)?;         // Use Anchor's close
```

## Attack Scenario

1. User creates account with 100 tokens
2. User withdraws tokens and closes account
3. Attacker CPIs to send lamports back in same tx
4. Account is "alive" again with stale balance of 100
5. Attacker can claim the stale balance

## Attack Flow

### Vulnerable Version

```
User                    Program            Blockchain
 |                         |                   |
 |-- Create account -------|                   |
 |                         +--- Account -------+
 |-- Deposit 100 ----------|    created with   |
 |   tokens                |    100 tokens     |
 |                         |                   |
 |-- Withdraw & -----------|                   |
 |   close account         +--- Lamports ------+
 |                         |    = 0            |
 |                         |    Data still     |
 |                         |    contains 100!  |
 |                         |                   |
 | [Later in same tx]      |                   |
 |                         |                   |
 |-- Attacker CPIs --------|                   |
 |   to send lamports      +--- Account -------+
 |                         |    revived with   |
 |                         |    old data!      |
 |                         |                   |
 |-- Claim stale -----------|                   |
 |   balance of 100        +--- Attacker ------+
 |                         |    gets 100       |
 |-- Success! -------------|    tokens!        |

Result: EXPLOIT SUCCESSFUL - Attacker exploits stale data
```

### Secure Version

```
User                    Program            Blockchain
 |                         |                   |
 |-- Create account -------|                   |
 |                         +--- Account -------+
 |-- Deposit 100 ----------|    created        |
 |   tokens                |                   |
 |                         |                   |
 |-- Withdraw & -----------|                   |
 |   close account         +--- Zero data -----+
 |                         |    (fill(0))      |
 |                         |                   |
 |                         +--- Close ---------+
 |                         |    lamports = 0   |
 |                         |    Account        |
 |                         |    removed!       |
 |                         |                   |
 | [Later in same tx]      |                   |
 |                         |                   |
 |-- Attacker CPIs --------|                   |
 |   to send lamports      +--- Error! --------+
 |                         |    Cannot revive  |
 |                         |    closed account |
 |                         |                   |
 |-- Transaction fails!    |                   |

Result: EXPLOIT BLOCKED - Account properly closed
```

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry points |
| `state.rs` | User account structure with initialize trait |
| `vulnerable.rs` | Close without zeroing data (VULNERABLE) |
| `secure.rs` | Proper closure with close constraint (SECURE) |
| `error.rs` | Custom error types |

## Key Differences

### Vulnerable Version
```rust
pub fn close(&mut self) -> Result<()> {
    // VULNERABLE: Just transfer lamports
    let lamports = self.user_account.to_account_info().lamports();
    **self.user_account.to_account_info().lamports.borrow_mut() = 0;
    **self.destination.lamports.borrow_mut() += lamports;
    
    // DATA IS STILL THERE! Account can be revived
    Ok(())
}
```

### Secure Version
```rust
#[derive(Accounts)]
pub struct SecureClose<'info> {
    #[account(
        mut,
        close = destination,  // Anchor zeros and closes atomically
        has_one = authority
    )]
    pub user_account: Account<'info, UserAccount>,
    // ...
}
```

## Running Tests

```bash
cargo test -p account-close-tests
```

## Mitigation Checklist

- Use Anchor's `close = destination` constraint
- Always zero account data before closing
- Consider using `force_defund` pattern for absolute closure
- Be aware of same-transaction revival attacks
- Add `is_initialized` check for re-initialization prevention
