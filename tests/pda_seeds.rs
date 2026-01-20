//! Tests for the PDA Seeds vulnerability

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use litesvm::LiteSVM;
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
            .join("target/deploy/pda_seeds-keypair.json");

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
            .join("target/deploy/pda_seeds.so");
        std::fs::read(so_path).expect("Failed to read program file")
    }

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
    fn test_weak_seeds_predictable() {
        let (mut svm, user) = setup();
        let pid = program_id();

        // Weak seeds: only user pubkey
        let (weak_pda, _bump) = Pubkey::find_program_address(&[user.pubkey().as_ref()], &pid);

        // Anyone can compute this PDA for any user
        println!("Weak PDA for user {}: {}", user.pubkey(), weak_pda);

        // Attacker can compute same PDA
        let attacker = Keypair::new();
        let (attacker_predicted, _) = Pubkey::find_program_address(&[user.pubkey().as_ref()], &pid);
        assert_eq!(weak_pda, attacker_predicted);
        println!("Attacker computed same PDA: {}", attacker_predicted);
    }

    #[test]
    fn test_strong_seeds_unpredictable() {
        let (mut svm, user) = setup();
        let pid = program_id();

        // Strong seeds: prefix + user + random nonce
        let nonce: u64 = 12345;
        let (strong_pda, _bump) = Pubkey::find_program_address(
            &[b"user_v1", user.pubkey().as_ref(), &nonce.to_le_bytes()],
            &pid,
        );

        // Different nonce = different PDA
        let different_nonce: u64 = 99999;
        let (different_pda, _) = Pubkey::find_program_address(
            &[
                b"user_v1",
                user.pubkey().as_ref(),
                &different_nonce.to_le_bytes(),
            ],
            &pid,
        );

        assert_ne!(strong_pda, different_pda);
        println!("Strong PDA with nonce {}: {}", nonce, strong_pda);
        println!(
            "Different nonce {} gives: {}",
            different_nonce, different_pda
        );
    }

    #[test]
    fn test_vulnerable_create_user() {
        let (mut svm, user) = setup();
        let pid = program_id();

        let (weak_pda, _bump) = Pubkey::find_program_address(&[user.pubkey().as_ref()], &pid);

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(user.pubkey(), true),
                AccountMeta::new(weak_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            ],
            data: discriminator("vulnerable_create_user").to_vec(),
        };

        let msg = Message::new(&[ix], Some(&user.pubkey()));
        let tx = Transaction::new(&[&user], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Vulnerable create user: {:?}", result);
    }

    #[test]
    fn test_secure_create_user() {
        let (mut svm, user) = setup();
        let pid = program_id();

        let nonce: u64 = 42;
        let (strong_pda, _bump) = Pubkey::find_program_address(
            &[b"user_v1", user.pubkey().as_ref(), &nonce.to_le_bytes()],
            &pid,
        );

        let mut data = discriminator("secure_create_user").to_vec();
        data.extend_from_slice(&nonce.to_le_bytes());

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(user.pubkey(), true),
                AccountMeta::new(strong_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&user.pubkey()));
        let tx = Transaction::new(&[&user], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Secure create user: {:?}", result);
    }
}
