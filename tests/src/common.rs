use litesvm::LiteSVM;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use std::path::PathBuf;

pub fn read_program(name: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("target");
    path.push("deploy");
    path.push(format!("{}.so", name));
    std::fs::read(path).expect("Failed to read program")
}

pub fn setup_svm(program_id: Pubkey, program_name: &str) -> LiteSVM {
    let mut svm = LiteSVM::new();
    svm.add_program(program_id, &read_program(program_name))
        .unwrap();
    svm
}

pub fn airdrop(svm: &mut LiteSVM, pubkey: &Pubkey, lamports: u64) {
    svm.airdrop(pubkey, lamports).unwrap();
}
