//! Tests for the Owner Check vulnerability (Pinocchio program)

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
            .join("target/deploy/owner_check-keypair.json");

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
            .join("target/deploy/owner_check.so");
        std::fs::read(so_path).expect("Failed to read program file")
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
    fn test_vulnerable_accepts_fake_config() {
        let (mut svm, admin) = setup();
        let attacker = Keypair::new();
        let pid = program_id();

        svm.airdrop(&attacker.pubkey(), 1 * LAMPORTS_PER_SOL)
            .unwrap();

        // Create a LEGITIMATE config with admin as authority
        let config_addr = Pubkey::new_unique();
        let mut config_data = vec![0u8; 32];
        config_data.copy_from_slice(admin.pubkey().as_ref());

        svm.set_account(
            config_addr,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: config_data.clone(),
                owner: pid, // Owned by our program
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Create FAKE config with attacker as admin
        // VULNERABILITY: Different owner (system program), but vulnerable code doesn't check!
        let fake_config = Pubkey::new_unique();
        let mut fake_data = vec![0u8; 32];
        fake_data.copy_from_slice(attacker.pubkey().as_ref());

        svm.set_account(
            fake_config,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: fake_data,
                owner: solana_sdk_ids::system_program::ID, // WRONG OWNER!
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Vulnerable instruction (discriminator = 0)
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(fake_config, false), // Pass fake config!
                AccountMeta::new_readonly(attacker.pubkey(), true),
            ],
            data: vec![0], // Vulnerable variant
        };

        let msg = Message::new(&[ix], Some(&attacker.pubkey()));
        let tx = Transaction::new(&[&attacker], msg, svm.latest_blockhash());

        // In vulnerable version, this might succeed with fake config
        let result = svm.send_transaction(tx);
        println!("Vulnerable with fake config: {:?}", result);
    }

    #[test]
    fn test_secure_rejects_fake_config() {
        let (mut svm, admin) = setup();
        let attacker = Keypair::new();
        let pid = program_id();

        svm.airdrop(&attacker.pubkey(), 1 * LAMPORTS_PER_SOL)
            .unwrap();

        // Fake config not owned by our program
        let fake_config = Pubkey::new_unique();
        let mut fake_data = vec![0u8; 32];
        fake_data.copy_from_slice(attacker.pubkey().as_ref());

        svm.set_account(
            fake_config,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: fake_data,
                owner: solana_sdk_ids::system_program::ID, // WRONG OWNER
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Secure instruction (discriminator = 1)
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(fake_config, false),
                AccountMeta::new_readonly(attacker.pubkey(), true),
            ],
            data: vec![1], // Secure variant
        };

        let msg = Message::new(&[ix], Some(&attacker.pubkey()));
        let tx = Transaction::new(&[&attacker], msg, svm.latest_blockhash());

        // Secure version MUST reject - wrong owner
        let result = svm.send_transaction(tx);
        assert!(result.is_err(), "Secure should reject fake config");
        println!(
            "Secure correctly rejected fake config: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn test_secure_accepts_real_config() {
        let (mut svm, admin) = setup();
        let pid = program_id();

        // Real config owned by our program
        let config_addr = Pubkey::new_unique();
        let mut config_data = vec![0u8; 32];
        config_data.copy_from_slice(admin.pubkey().as_ref());

        svm.set_account(
            config_addr,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: config_data,
                owner: pid, // Correct owner
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Secure instruction
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(config_addr, false),
                AccountMeta::new_readonly(admin.pubkey(), true),
            ],
            data: vec![1], // Secure variant
        };

        let msg = Message::new(&[ix], Some(&admin.pubkey()));
        let tx = Transaction::new(&[&admin], msg, svm.latest_blockhash());

        let result = svm.send_transaction(tx);
        println!("Secure with real config: {:?}", result);
    }
}
