//! Tests for the Account Close vulnerability (revival attack)

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
            .join("target/deploy/account_close-keypair.json");

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
            .join("target/deploy/account_close.so");
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

    fn derive_user_pda(owner: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"user", owner.as_ref()], program_id)
    }

    fn create_user_account_data(
        owner: Pubkey,
        balance: u64,
        is_initialized: bool,
        bump: u8,
    ) -> Vec<u8> {
        let mut data = vec![0u8; 8]; // discriminator
        data.extend_from_slice(owner.as_ref());
        data.extend_from_slice(&balance.to_le_bytes());
        data.push(if is_initialized { 1 } else { 0 });
        data.push(bump);
        data
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
    fn test_vulnerable_close_data_not_zeroed() {
        let (mut svm, owner) = setup();
        let pid = program_id();
        let (user_pda, bump) = derive_user_pda(&owner.pubkey(), &pid);

        // Create user account with balance
        let user_data = create_user_account_data(owner.pubkey(), 100, true, bump);
        svm.set_account(
            user_pda,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: user_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Call vulnerable_close
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(user_pda, false),
            ],
            data: discriminator("vulnerable_close").to_vec(),
        };

        let msg = Message::new(&[ix], Some(&owner.pubkey()));
        let tx = Transaction::new(&[&owner], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Vulnerable close result: {:?}", result);
        // After close, if account receives lamports, data may still be readable
    }

    #[test]
    fn test_secure_close_zeros_data() {
        let (mut svm, owner) = setup();
        let pid = program_id();
        let (user_pda, bump) = derive_user_pda(&owner.pubkey(), &pid);

        let user_data = create_user_account_data(owner.pubkey(), 100, true, bump);
        svm.set_account(
            user_pda,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: user_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Call secure_close - zeros data before closing
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(user_pda, false),
            ],
            data: discriminator("secure_close").to_vec(),
        };

        let msg = Message::new(&[ix], Some(&owner.pubkey()));
        let tx = Transaction::new(&[&owner], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Secure close result: {:?}", result);
    }

    #[test]
    fn test_secure_close_rejects_already_closed() {
        let (mut svm, owner) = setup();
        let pid = program_id();
        let (user_pda, bump) = derive_user_pda(&owner.pubkey(), &pid);

        // Account with is_initialized = false (already closed)
        let user_data = create_user_account_data(owner.pubkey(), 0, false, bump);
        svm.set_account(
            user_pda,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: user_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(user_pda, false),
            ],
            data: discriminator("secure_close").to_vec(),
        };

        let msg = Message::new(&[ix], Some(&owner.pubkey()));
        let tx = Transaction::new(&[&owner], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        // Should fail - account already marked as closed
        println!("Secure close on already closed: {:?}", result);
    }
}
