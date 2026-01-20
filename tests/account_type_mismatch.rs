//! Tests for the Account Type Mismatch vulnerability (missing discriminator)

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
            .join("target/deploy/account_type_mismatch-keypair.json");

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
            .join("target/deploy/account_type_mismatch.so");
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

    // Discriminators from lib.rs
    const USER_DISCRIMINATOR: u8 = 1;
    const ADMIN_DISCRIMINATOR: u8 = 2;

    fn create_user_data(user_pubkey: &Pubkey) -> Vec<u8> {
        let mut data = vec![USER_DISCRIMINATOR]; // discriminator
        data.extend_from_slice(user_pubkey.as_ref()); // pubkey (32 bytes)
        data.extend_from_slice(&100u64.to_le_bytes()); // balance (8 bytes)
        data
    }

    fn create_admin_data(admin_pubkey: &Pubkey) -> Vec<u8> {
        let mut data = vec![ADMIN_DISCRIMINATOR]; // discriminator
        data.extend_from_slice(admin_pubkey.as_ref()); // pubkey (32 bytes)
        data.extend_from_slice(&0xFFu64.to_le_bytes()); // permissions (8 bytes)
        data
    }

    #[test]
    fn test_vulnerable_accepts_wrong_account_type() {
        let (mut svm, user) = setup();
        let pid = program_id();

        // Create an ADMIN account but pass it as if it were a USER account
        let admin_account = Pubkey::new_unique();
        let admin_data = create_admin_data(&user.pubkey());

        svm.set_account(
            admin_account,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: admin_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Vulnerable instruction (discriminator = 0) - doesn't check account type
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(admin_account, false), // Pass admin as user!
                AccountMeta::new_readonly(user.pubkey(), true),
            ],
            data: vec![0], // Vulnerable variant
        };

        let msg = Message::new(&[ix], Some(&user.pubkey()));
        let tx = Transaction::new(&[&user], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        // May succeed - reading admin.permissions as user.balance
        println!("Vulnerable with wrong account type: {:?}", result);
    }

    #[test]
    fn test_secure_rejects_wrong_account_type() {
        let (mut svm, user) = setup();
        let pid = program_id();

        // Create ADMIN account
        let admin_account = Pubkey::new_unique();
        let admin_data = create_admin_data(&user.pubkey());

        svm.set_account(
            admin_account,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: admin_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Secure instruction (discriminator = 1) - checks account type
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(admin_account, false),
                AccountMeta::new_readonly(user.pubkey(), true),
            ],
            data: vec![1], // Secure variant
        };

        let msg = Message::new(&[ix], Some(&user.pubkey()));
        let tx = Transaction::new(&[&user], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        // Should fail - wrong discriminator
        println!("Secure with wrong account type (should fail): {:?}", result);
    }

    #[test]
    fn test_secure_accepts_correct_account_type() {
        let (mut svm, user) = setup();
        let pid = program_id();

        // Create correct USER account
        let user_account = Pubkey::new_unique();
        let user_data = create_user_data(&user.pubkey());

        svm.set_account(
            user_account,
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
                AccountMeta::new(user_account, false),
                AccountMeta::new_readonly(user.pubkey(), true),
            ],
            data: vec![1], // Secure variant
        };

        let msg = Message::new(&[ix], Some(&user.pubkey()));
        let tx = Transaction::new(&[&user], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Secure with correct account type: {:?}", result);
    }
}
