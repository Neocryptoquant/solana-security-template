# Insecure Authority Transfer

**Vulnerability**: Single-step authority transfer with no confirmation  
**Framework**: Anchor  

## Overview

This program demonstrates vulnerabilities in admin/authority transfer functionality. Improper implementation can lead to permanent loss of protocol control.

## The Vulnerability

Single-step authority transfer is dangerous:
- Typos = permanent lockout
- Exploits = immediate takeover
- No confirmation = no recovery

```rust
// VULNERABLE: Single-step, immediate, irreversible
pub fn transfer_authority(new_auth: Pubkey) {
    config.authority = new_auth;  // Done! No going back!
}

// SECURE: Two-step with confirmation
pub fn propose_authority(new_auth: Pubkey) {
    config.pending_authority = Some(new_auth);  // Step 1
}
pub fn accept_authority() {
    require!(signer == config.pending_authority);
    config.authority = config.pending_authority;  // Step 2
}
```

## Attack Scenario

1. Protocol uses single-step transfer
2. Attacker finds bug allowing them to call `transfer_authority`
3. Attacker immediately becomes admin
4. No timelock, no multi-sig, no recovery
5. Protocol is permanently compromised

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Program entry points |
| `state.rs` | Config with pending_authority field |
| `vulnerable.rs` | Single-step immediate transfer (VULNERABLE) |
| `secure.rs` | Two-step propose/accept pattern (SECURE) |
| `error.rs` | Custom error types |

## Key Differences

### Vulnerable Version
```rust
pub fn transfer(&mut self, new_authority: Pubkey) -> Result<()> {
    // DANGEROUS: Immediate, irreversible transfer
    self.config.authority = new_authority;
    Ok(())
}
```

### Secure Version
```rust
// Step 1: Current authority proposes
pub fn propose(&mut self, new_authority: Pubkey) -> Result<()> {
    require!(new_authority != Pubkey::default());
    self.config.pending_authority = Some(new_authority);
    Ok(())
}

// Step 2: New authority must accept (proves they control the key)
pub fn accept(&mut self) -> Result<()> {
    require!(self.new_authority.key() == self.config.pending_authority);
    self.config.authority = self.config.pending_authority.take().unwrap();
    Ok(())
}
```

## Running Tests

```bash
cargo test -p authority-transfer-tests
```

## Mitigation Checklist

- Use two-step (propose/accept) transfer pattern
- Check for zero/invalid addresses
- Consider adding timelock between propose and accept
- Consider requiring multi-sig for authority changes
- Add events for off-chain monitoring
- Allow proposal cancellation before acceptance
