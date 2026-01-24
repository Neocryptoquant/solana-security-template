# Trident Fuzz Tests

This directory contains fuzz tests for the security template programs using [Trident](https://github.com/Ackee-Blockchain/trident).

## Overview

Fuzzing complements unit testing by generating random inputs to find edge cases that developers miss. While unit tests prove expected behavior, fuzzing discovers unexpected vulnerabilities.

## Setup

1. **Install Trident CLI:**
   ```bash
   cargo install trident-cli
   ```

2. **Install Honggfuzz (required by Trident):**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install build-essential binutils-dev libunwind-dev libblocksruntime-dev liblzma-dev
   
   cargo install honggfuzz
   ```

## Available Fuzz Tests

### `fuzz_arithmetic`

Tests the arithmetic overflow program by generating random `u64` values for swap amounts.

**What it tests:**
- Integer overflow in multiplication (`amount_in * reserve_y`)
- Integer underflow in subtraction (`reserve_y - amount_out`)
- Edge cases in the constant product formula

**Run it:**
```bash
cd /path/to/solana-security-template
trident fuzz run fuzz_arithmetic
```

## Running Unit Tests (Without Fuzzer)

You can also run the fuzz tests as regular unit tests:

```bash
cd trident-tests/fuzz_targets
cargo test
```

This is useful for verifying the test logic before running the full fuzzer.

## Configuration

See `Trident.toml` in the repository root for fuzzing configuration options:
- `iterations`: Number of fuzzing iterations
- `timeout`: Per-test timeout
- `threads`: Parallel fuzzing threads
- `exit_on_crash`: Stop on first crash

## Understanding the Output

When Trident finds a crash:
1. It saves the crashing input to `trident-tests/hfuzz_workspace/`
2. You can reproduce with: `trident fuzz run-debug fuzz_arithmetic <crash_file>`
3. The crash represents a potential vulnerability

## Resources

- [Trident Documentation](https://ackee.xyz/trident/docs/latest/)
- [Trident GitHub](https://github.com/Ackee-Blockchain/trident)
- [Honggfuzz](https://github.com/google/honggfuzz)
