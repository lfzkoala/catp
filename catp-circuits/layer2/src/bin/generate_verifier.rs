//! Generates a Solidity verifier for the ProveAuthorization circuit.
//!
//! Outputs `Halo2SolidityVerifier.sol` in the current directory. Deploy this
//! contract and set it as the `IVerifier` in `AgentAuthorizer.sol`.
//!
//! WARNING: Uses a randomly-generated SRS. The deployed Solidity verifier must
//! be regenerated from the same SRS used to create proofs. For production, load
//! both the SRS and verifying key from the Ethereum KZG ceremony files.

use halo2_proofs::{
    plonk::keygen_vk,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use snark_verifier::{
    loader::evm::EvmLoader,
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use std::rc::Rc;

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
    let proof =
        PlonkVerifier::read_proof(&vk_kzg, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk_kzg, &protocol, &instances, &proof).unwrap();

    loader.solidity_code()
}

fn main() {
    let k = 8u32;
    println!("Generating SRS (k={k})...");
    let params = ParamsKZG::<Bn256>::new(k);

    let empty_circuit = ProveAuthorization::default();
    println!("Generating verifying key...");
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk failed");

    // Two instance columns, both empty (all witnesses are private).
    let num_instance = vec![0, 0];

    println!("Generating Solidity verifier...");
    let solidity = gen_solidity_verifier(&params, &vk, num_instance);

    let out_path = "Halo2SolidityVerifier.sol";
    std::fs::write(out_path, &solidity).expect("failed to write verifier");
    println!("Solidity verifier written to {out_path} ({} bytes)", solidity.len());
}
