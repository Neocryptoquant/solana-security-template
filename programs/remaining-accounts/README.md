# Unvalidated Remaining Accounts

**Vulnerability**: Using ctx.remaining_accounts without validation  
**Framework**: Anchor  

## Overview

This program demonstrates the danger of using `ctx.remaining_accounts` without manual validation. Unlike declared accounts, remaining_accounts bypass all Anchor constraints.

## The Vulnerability

Anchor's `remaining_accounts` are completely unvalidated. No owner check, no type check, no constraints. Attackers can pass any accounts they want.

```rust
// VULNERABLE: Blindly trusting remaining_accounts
for account in ctx.remaining_accounts.iter() {
    // Attacker passed malicious accounts here!
    credit_rewards(account, amount)?;
}

// SECURE: Validate each account manually
for account in ctx.remaining_accounts.iter() {
    require!(account.owner == &program_id, Error::InvalidOwner);
    let data = account.try_borrow_data()?;
    // Check discriminator, deserialize, verify eligibility...
    credit_rewards(account, amount)?;
}
```

## Attack Scenario

1. Protocol has batch reward distribution
2. Legitimate recipients are passed in remaining_accounts
3. Attacker calls with their own accounts as remaining_accounts
4. Rewards are distributed to attacker's accounts
5. Attacker steals all rewards

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry points |
| `state.rs` | Config and recipient structures |
| `vulnerable.rs` | No remaining_accounts validation (VULNERABLE) |
| `secure.rs` | Manual validation of each account (SECURE) |
| `error.rs` | Custom error types |

## Key Differences

### Vulnerable Version
```rust
pub fn process_rewards(&self, remaining: &[AccountInfo]) {
    for account in remaining.iter() {
        // NO VALIDATION - BUG!
        credit_rewards(account, amount)?;
    }
}
```

### Secure Version
```rust
pub fn process_rewards(&self, remaining: &[AccountInfo]) {
    for account in remaining.iter() {
        // 1. Check owner
        require!(account.owner == &program_id, Error::InvalidOwner);
        
        // 2. Verify discriminator/type
        let data = account.try_borrow_data()?;
        verify_discriminator(&data)?;
        
        // 3. Deserialize and check eligibility
        let recipient = Recipient::deserialize(&data)?;
        require!(recipient.is_eligible, Error::NotEligible);
        
        credit_rewards(account, amount)?;
    }
}
```

## Running Tests

```bash
cargo test -p remaining-accounts-tests
```

## Mitigation Checklist

- Always validate owner of remaining_accounts
- Check discriminator/type before deserializing
- Verify business logic (eligibility, whitelist, etc.)
- Consider using declared accounts when count is known
- Document expected format of remaining_accounts
