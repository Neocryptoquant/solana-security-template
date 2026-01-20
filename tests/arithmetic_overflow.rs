//! Tests for the Arithmetic Overflow vulnerability

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
            .join("target/deploy/arithmetic_overflow-keypair.json");

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
            .join("target/deploy/arithmetic_overflow.so");
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

    fn derive_pool_pda(authority: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"pool", authority.as_ref()], program_id)
    }

    fn create_pool_data(authority: Pubkey, reserve_a: u64, reserve_b: u64, bump: u8) -> Vec<u8> {
        let mut data = vec![0u8; 8]; // discriminator
        data.extend_from_slice(authority.as_ref());
        data.extend_from_slice(&reserve_a.to_le_bytes());
        data.extend_from_slice(&reserve_b.to_le_bytes());
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
    fn test_vulnerable_swap_overflow() {
        let (mut svm, user) = setup();
        let pid = program_id();
        let (pool_pda, bump) = derive_pool_pda(&user.pubkey(), &pid);

        // Pool with reserves that could cause overflow
        let pool_data = create_pool_data(
            user.pubkey(),
            u64::MAX / 2, // Very large reserve_a
            1000,         // Small reserve_b
            bump,
        );

        svm.set_account(
            pool_pda,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: pool_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Large amount that could overflow: amount * reserve_b
        let exploit_amount = u64::MAX / 4;
        let min_out: u64 = 1;

        let mut data = discriminator("vulnerable_swap").to_vec();
        data.extend_from_slice(&exploit_amount.to_le_bytes());
        data.extend_from_slice(&min_out.to_le_bytes());

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(pool_pda, false),
                AccountMeta::new_readonly(user.pubkey(), true),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&user.pubkey()));
        let tx = Transaction::new(&[&user], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Vulnerable swap with overflow input: {:?}", result);
    }

    #[test]
    fn test_secure_swap_handles_large_values() {
        let (mut svm, user) = setup();
        let pid = program_id();
        let (pool_pda, bump) = derive_pool_pda(&user.pubkey(), &pid);

        let pool_data = create_pool_data(user.pubkey(), u64::MAX / 2, 1000, bump);

        svm.set_account(
            pool_pda,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: pool_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let exploit_amount = u64::MAX / 4;
        let min_out: u64 = 1;

        let mut data = discriminator("secure_swap").to_vec();
        data.extend_from_slice(&exploit_amount.to_le_bytes());
        data.extend_from_slice(&min_out.to_le_bytes());

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(pool_pda, false),
                AccountMeta::new_readonly(user.pubkey(), true),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&user.pubkey()));
        let tx = Transaction::new(&[&user], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Secure swap with large values: {:?}", result);
        // Should either succeed (u128 handles it) or fail gracefully
    }

    #[test]
    fn test_secure_swap_normal() {
        let (mut svm, user) = setup();
        let pid = program_id();
        let (pool_pda, bump) = derive_pool_pda(&user.pubkey(), &pid);

        let pool_data = create_pool_data(
            user.pubkey(),
            1_000_000_000, // 1B
            1_000_000_000, // 1B
            bump,
        );

        svm.set_account(
            pool_pda,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: pool_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let amount_in: u64 = 1000;
        let min_out: u64 = 900;

        let mut data = discriminator("secure_swap").to_vec();
        data.extend_from_slice(&amount_in.to_le_bytes());
        data.extend_from_slice(&min_out.to_le_bytes());

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(pool_pda, false),
                AccountMeta::new_readonly(user.pubkey(), true),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&user.pubkey()));
        let tx = Transaction::new(&[&user], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Normal secure swap: {:?}", result);
    }
}
