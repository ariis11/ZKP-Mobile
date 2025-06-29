use ark_std::rand::thread_rng;
use ark_std::Zero;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_ff::PrimeField;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::eq::EqGadget;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::CryptographicSponge;
use std::time::Instant;

#[derive(Clone)]
struct HashVerificationCircuit {
    field_inputs: Vec<Option<Fr>>, 
    expected_hash: Fr,         
    expected_degree: Fr,       
    params: PoseidonConfig<Fr>, 
}

impl ConstraintSynthesizer<Fr> for HashVerificationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let input_vars: Vec<FpVar<Fr>> = self.field_inputs.iter()
            .map(|val| FpVar::new_witness(cs.clone(), || val.ok_or(SynthesisError::AssignmentMissing)))
            .collect::<Result<_, _>>()?;

        let expected_hash_var = FpVar::new_input(cs.clone(), || Ok(self.expected_hash))?;
        let expected_degree_var = FpVar::new_input(cs.clone(), || Ok(self.expected_degree))?;

        let mut sponge = PoseidonSponge::<Fr>::new(&self.params);

        for var in &input_vars {
            let val = var.value().unwrap_or(Fr::zero());
            sponge.absorb(&val);
        }

        let circuit_hash = sponge.squeeze_field_elements::<Fr>(1)[0];
        let computed_hash_var = FpVar::new_witness(cs.clone(), || Ok(circuit_hash))?;

        computed_hash_var.enforce_equal(&expected_hash_var)?;

        input_vars[1].enforce_equal(&expected_degree_var)?;

        Ok(())
    }
}

fn main() {
    let rng = &mut thread_rng();

    let start_data_preparation = Instant::now();

    let inputs = ["Lukas", "Financial Technologies", "Vilnius", "2025"];
    let expected_degree = Fr::from_le_bytes_mod_order(b"Financial Technologies");

    let field_inputs: Vec<Fr> = inputs.iter().map(|input| {
        let bytes = input.as_bytes();
        Fr::from_le_bytes_mod_order(bytes)
    }).collect();

    let params = PoseidonConfig {
        full_rounds: 8,
        partial_rounds: 31,
        alpha: 5,
        mds: vec![
            vec![Fr::from(1), Fr::from(0), Fr::from(0)],
            vec![Fr::from(0), Fr::from(1), Fr::from(0)],
            vec![Fr::from(0), Fr::from(0), Fr::from(1)],
        ],
        ark: vec![vec![Fr::from(0); 3]; 8 + 31],
        rate: 2,
        capacity: 1,
    };

    let mut sponge = PoseidonSponge::<Fr>::new(&params);
    for elem in &field_inputs {
        sponge.absorb(elem);
    }
    let hash_result = sponge.squeeze_field_elements::<Fr>(1);
    let expected_hash = hash_result[0];
    println!("✅ Input data prepared");
    let data_preparation_time = start_data_preparation.elapsed();
    println!("⏱️ Data preparation time: {:?}", data_preparation_time);

    let start_circuit_and_setup = Instant::now();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        HashVerificationCircuit {
            field_inputs: vec![None; 4],
            expected_hash,
            expected_degree,
            params: params.clone(),
        }, 
        rng
    ).unwrap();

    let vk = pk.vk.clone();
    let pvk = PreparedVerifyingKey::from(vk.clone());
    println!("✅ Trusted setup completed (PK and VK generated)");
    let trusted_setup_time = start_circuit_and_setup.elapsed();
    println!("⏱️ Circuit + Trusted setup time: {:?}", trusted_setup_time);

    let proof_circuit = HashVerificationCircuit {
        field_inputs: field_inputs.iter().map(|v| Some(*v)).collect(),
        expected_hash,
        expected_degree,
        params: params.clone(),
    };
    let start_proof_generation = Instant::now();
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(proof_circuit, &pk, rng).unwrap();
    println!("✅ Generated proof");
    let proof_generation_time = start_proof_generation.elapsed();
    println!("⏱️ Proof generation time: {:?}", proof_generation_time);

    let start_proof_verification = Instant::now();
    
    let public_inputs = [expected_hash, expected_degree];
    let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).unwrap();

    if is_valid {
        println!("✅ Proof is valid");
    } else {
        println!("❌ Proof is invalid");
    }

    let verification_time = start_proof_verification.elapsed();
    println!("⏱️ Verification time: {:?}", verification_time);
}
