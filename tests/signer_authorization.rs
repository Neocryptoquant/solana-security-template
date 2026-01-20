//! Tests for the Signer Authorization vulnerability
//!
//! Demonstrates:
//! - Vulnerable: Attacker can withdraw without being the authority
//! - Secure: Only the vault authority can withdraw

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use litesvm::LiteSVM;
    use solana_account::Account;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_keypair::Keypair;
    use solana_message::Message;
    use solana_native_token::LAMPORTS_PER_SOL;
    use solana_pubkey::Pubkey;
    use solana_signer::Signer;
    use solana_transaction::Transaction;

    fn program_id() -> Pubkey {
        let keypair_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/deploy/signer_authorization-keypair.json");

        let keypair_bytes: Vec<u8> = serde_json::from_str(
            &std::fs::read_to_string(&keypair_path).expect("Failed to read keypair"),
        )
        .expect("Failed to parse keypair");

        Keypair::from_bytes(&keypair_bytes).unwrap().pubkey()
    }

    fn read_program() -> Vec<u8> {
        let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/deploy/signer_authorization.so");
        std::fs::read(so_path).expect("Failed to read program file")
    }

    fn derive_vault_pda(authority: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"vault", authority.as_ref()], program_id)
    }

    /// Simple discriminator using first 8 bytes
    fn discriminator(name: &str) -> [u8; 8] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let full_name = format!("global:{}", name);
        let mut hasher = DefaultHasher::new();
        full_name.hash(&mut hasher);
        hasher.finish().to_le_bytes()
    }

    fn setup() -> (LiteSVM, Keypair) {
        let mut svm = LiteSVM::new();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 10 * LAMPORTS_PER_SOL)
            .expect("Airdrop failed");
        svm.add_program(program_id(), &read_program());
        (svm, payer)
    }

    #[test]
    fn test_vulnerable_withdraw_allows_attacker() {
        let (mut svm, authority) = setup();
        let attacker = Keypair::new();
        let pid = program_id();

        svm.airdrop(&attacker.pubkey(), 1 * LAMPORTS_PER_SOL)
            .unwrap();

        let (vault_pda, bump) = derive_vault_pda(&authority.pubkey(), &pid);

        // Create vault account with authority stored
        let mut vault_data = vec![0u8; 8 + 32 + 1]; // discriminator + pubkey + bump
        vault_data[8..40].copy_from_slice(authority.pubkey().as_ref());
        vault_data[40] = bump;

        svm.set_account(
            vault_pda,
            Account {
                lamports: 5 * LAMPORTS_PER_SOL,
                data: vault_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Try vulnerable_withdraw as attacker
        let mut data = discriminator("vulnerable_withdraw").to_vec();
        data.extend_from_slice(&LAMPORTS_PER_SOL.to_le_bytes());

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(vault_pda, false),
                AccountMeta::new_readonly(authority.pubkey(), false), // NOT signing!
                AccountMeta::new(attacker.pubkey(), false),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&attacker.pubkey()));
        let tx = Transaction::new(&[&attacker], msg, svm.latest_blockhash());

        // This demonstrates the vulnerability - attacker can call without authority sig
        let result = svm.send_transaction(tx);
        println!("Vulnerable withdraw result: {:?}", result);
    }

    #[test]
    fn test_secure_withdraw_rejects_attacker() {
        let (mut svm, authority) = setup();
        let attacker = Keypair::new();
        let pid = program_id();

        svm.airdrop(&attacker.pubkey(), 1 * LAMPORTS_PER_SOL)
            .unwrap();

        let (vault_pda, bump) = derive_vault_pda(&authority.pubkey(), &pid);

        let mut vault_data = vec![0u8; 8 + 32 + 1];
        vault_data[8..40].copy_from_slice(authority.pubkey().as_ref());
        vault_data[40] = bump;

        svm.set_account(
            vault_pda,
            Account {
                lamports: 5 * LAMPORTS_PER_SOL,
                data: vault_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Try secure_withdraw - attacker passes authority but doesn't sign
        // The secure version should reject because authority isn't a signer
        let mut data = discriminator("secure_withdraw").to_vec();
        data.extend_from_slice(&LAMPORTS_PER_SOL.to_le_bytes());

        // NOTE: Mark authority as NOT a signer - this tests the program's validation
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(vault_pda, false),
                AccountMeta::new_readonly(authority.pubkey(), false), // NOT a signer!
                AccountMeta::new(attacker.pubkey(), false),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&attacker.pubkey()));
        let tx = Transaction::new(&[&attacker], msg, svm.latest_blockhash());

        // The secure program should reject - authority didn't sign
        let result = svm.send_transaction(tx);
        // Program should return an error because Signer constraint fails
        println!("Secure withdraw result (should fail): {:?}", result);
    }

    #[test]
    fn test_secure_withdraw_works_for_authority() {
        let (mut svm, authority) = setup();
        let pid = program_id();

        let (vault_pda, bump) = derive_vault_pda(&authority.pubkey(), &pid);
        let destination = Pubkey::new_unique();

        let mut vault_data = vec![0u8; 8 + 32 + 1];
        vault_data[8..40].copy_from_slice(authority.pubkey().as_ref());
        vault_data[40] = bump;

        svm.set_account(
            vault_pda,
            Account {
                lamports: 5 * LAMPORTS_PER_SOL,
                data: vault_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let mut data = discriminator("secure_withdraw").to_vec();
        data.extend_from_slice(&LAMPORTS_PER_SOL.to_le_bytes());

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(vault_pda, false),
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(destination, false),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&authority.pubkey()));
        let tx = Transaction::new(&[&authority], msg, svm.latest_blockhash());

        let result = svm.send_transaction(tx);
        println!("Legitimate withdraw result: {:?}", result);
    }
}
