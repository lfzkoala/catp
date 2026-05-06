//! Generates a Solidity verifier for the ProveAuthorization circuit.
//!
//! Outputs `Halo2SolidityVerifier.sol` and `catp-layer2-k12.srs` in the current
//! directory. The SRS file must be passed to `AuthorizationProofSystem::from_file`
//! so that proofs and the deployed verifier share the same trusted setup.
//!
//! For production, replace the generated SRS with one from the Ethereum KZG
//! ceremony (EIP-4844 powers-of-tau) via `ParamsKZG::read`. See Phase C in
//! IMPLEMENTATION_PLAN.md.

use halo2_proofs::{
    plonk::keygen_vk,
    poly::{
        commitment::{Params, ParamsProver},
        kzg::commitment::ParamsKZG,
    },
};
use halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use snark_verifier::{
    loader::evm::EvmLoader,
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use std::{fs::File, rc::Rc};

use catp_layer2::circuit::ProveAuthorization;

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

fn gen_solidity_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &halo2_proofs::plonk::VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> String {
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );
    // KZG verifying key: (g1_generator, g2, s_g2)
    let vk_kzg = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk_kzg, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk_kzg, &protocol, &instances, &proof).unwrap();

    loader.solidity_code()
}

fn main() {
    let k = 12u32;
    let srs_path = "catp-layer2-k12.srs";

    let params = if std::path::Path::new(srs_path).exists() {
        println!("Loading SRS from {srs_path}...");
        let mut f = File::open(srs_path).expect("failed to open SRS file");
        ParamsKZG::<Bn256>::read(&mut f).expect("failed to read SRS")
    } else {
        println!("Generating SRS (k={k})...");
        let p = ParamsKZG::<Bn256>::new(k);
        let mut f = File::create(srs_path).expect("failed to create SRS file");
        p.write(&mut f).expect("failed to write SRS");
        println!("SRS written to {srs_path}");
        p
    };

    let empty_circuit = ProveAuthorization::default();
    println!("Generating verifying key...");
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk failed");

    // One instance column with 13 values: policy commitment, action fields, timestamp, spend.
    let num_instance = vec![13];

    println!("Generating Solidity verifier...");
    let solidity = gen_solidity_verifier(&params, &vk, num_instance)
        // Foundry currently compiles the contracts with via-IR. The EVM loader
        // emits a memory-layout guard that via-IR can constant-fold, erasing the
        // generated fallback into an always-reverting runtime. Keep the guard
        // semantics, but make the memory read opaque to the optimizer.
        .replace(
            "mload(0x40)",
            "mload(add(0x40, mul(iszero(calldatasize()), calldatasize())))",
        );

    let out_path = "Halo2SolidityVerifier.sol";
    std::fs::write(out_path, &solidity).expect("failed to write verifier");
    println!(
        "Solidity verifier written to {out_path} ({} bytes)",
        solidity.len()
    );
}
