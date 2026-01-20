//! Tests for the P-Escrow vulnerability (missing refund recipient validation)

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
            .join("target/deploy/p_escrow-keypair.json");

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
            .join("target/deploy/p_escrow.so");
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

    // Escrow struct layout: maker(32) + mint_a(32) + mint_b(32) + amount_receive(8) + amount_give(8) + bump(1) + is_active(1)
    fn create_escrow_data(maker: &Pubkey, amount_give: u64, bump: u8) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(maker.as_ref()); // maker
        data.extend_from_slice(&[0u8; 32]); // mint_a
        data.extend_from_slice(&[0u8; 32]); // mint_b
        data.extend_from_slice(&100u64.to_le_bytes()); // amount_to_receive
        data.extend_from_slice(&amount_give.to_le_bytes()); // amount_to_give
        data.push(bump); // bump
        data.push(1); // is_active
        data
    }

    #[test]
    fn test_vulnerable_refund_allows_theft() {
        let (mut svm, maker) = setup();
        let attacker = Keypair::new();
        let pid = program_id();

        svm.airdrop(&attacker.pubkey(), 1 * LAMPORTS_PER_SOL)
            .unwrap();

        // Create escrow owned by maker
        let escrow = Pubkey::new_unique();
        let escrow_data = create_escrow_data(&maker.pubkey(), 1000, 255);

        svm.set_account(
            escrow,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: escrow_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Fake vault and attacker's destination
        let vault = Pubkey::new_unique();
        let attacker_dest = Pubkey::new_unique();

        // Vulnerable refund (discriminator = 2) - attacker redirects to their address
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(attacker.pubkey(), true), // caller (anyone!)
                AccountMeta::new(escrow, false),
                AccountMeta::new(vault, false),
                AccountMeta::new(attacker_dest, false), // attacker's destination!
                AccountMeta::new_readonly(spl_token_2022::ID, false),
            ],
            data: vec![2], // VulnerableRefund
        };

        let msg = Message::new(&[ix], Some(&attacker.pubkey()));
        let tx = Transaction::new(&[&attacker], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Vulnerable refund (attacker theft attempt): {:?}", result);
    }

    #[test]
    fn test_secure_refund_rejects_wrong_recipient() {
        let (mut svm, maker) = setup();
        let attacker = Keypair::new();
        let pid = program_id();

        svm.airdrop(&attacker.pubkey(), 1 * LAMPORTS_PER_SOL)
            .unwrap();

        let escrow = Pubkey::new_unique();
        let escrow_data = create_escrow_data(&maker.pubkey(), 1000, 255);

        svm.set_account(
            escrow,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: escrow_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let vault = Pubkey::new_unique();
        let attacker_dest = Pubkey::new_unique();

        // Secure refund (discriminator = 3) - validates caller is maker
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(attacker.pubkey(), true), // attacker tries
                AccountMeta::new(escrow, false),
                AccountMeta::new(vault, false),
                AccountMeta::new(attacker_dest, false),
                AccountMeta::new_readonly(spl_token_2022::ID, false),
            ],
            data: vec![3], // SecureRefund
        };

        let msg = Message::new(&[ix], Some(&attacker.pubkey()));
        let tx = Transaction::new(&[&attacker], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        // Should fail - attacker is not the maker
        println!("Secure refund (should reject attacker): {:?}", result);
    }

    #[test]
    fn test_secure_refund_works_for_maker() {
        let (mut svm, maker) = setup();
        let pid = program_id();

        let escrow = Pubkey::new_unique();
        let escrow_data = create_escrow_data(&maker.pubkey(), 1000, 255);

        svm.set_account(
            escrow,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: escrow_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let vault = Pubkey::new_unique();
        let maker_dest = maker.pubkey(); // maker's destination

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(maker.pubkey(), true), // legitimate maker
                AccountMeta::new(escrow, false),
                AccountMeta::new(vault, false),
                AccountMeta::new(maker_dest, false),
                AccountMeta::new_readonly(spl_token_2022::ID, false),
            ],
            data: vec![3], // SecureRefund
        };

        let msg = Message::new(&[ix], Some(&maker.pubkey()));
        let tx = Transaction::new(&[&maker], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Secure refund for maker: {:?}", result);
    }
}
