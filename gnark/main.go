package main

import (
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc" // Import to register MiMC_BN254
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	dataPrepStart := time.Now()
	vcFields := []string{"Lukas", "Financial Technologies", "VU", "2025"}
	expectedDegree := new(big.Int).SetBytes([]byte("Financial Technologies"))

	hasher := hash.MIMC_BN254.New()
	for _, field := range vcFields {
		hasher.Write([]byte(field))
	}
	finalVCHashBytes := hasher.Sum(nil)
	finalHashInt := new(big.Int).SetBytes(finalVCHashBytes)

	var fields [4]frontend.Variable
	for i := 0; i < 4; i++ {
		fields[i] = new(big.Int).SetBytes([]byte(vcFields[i]))
	}
	fmt.Printf("⏱️ Data preparation took: %s\n", time.Since(dataPrepStart))

	// --- Compile Circuit ---
	circuitCompilationStart := time.Now()
	var circuit Circuit
	ccs, err := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Circuit compilation failed: %v", err)
	}
	fmt.Println("✅ Circuit compiled successfully")
	fmt.Printf("⏱️ Circuit compilation took: %s\n", time.Since(circuitCompilationStart))

	// --- Trusted Setup ---
	trustedSetupStart := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("Groth16 setup failed: %v", err)
	}
	fmt.Println("✅ Groth16 setup completed")
	fmt.Printf("⏱️ Trusted setup took: %s\n", time.Since(trustedSetupStart))

	// --- Witness Assignment ---
	witnessAssignmentStart := time.Now()
	assignment := Circuit{
		Secret:        fields,
		Hash:          finalHashInt,
		ExpectedField: expectedDegree,
	}

	witness, err := frontend.NewWitness(&assignment, bn254.ID.ScalarField())
	if err != nil {
		log.Fatalf("Witness creation failed: %v", err)
	}
	fmt.Println("✅ Witness created")
	fmt.Printf("⏱️ Witness assignment took: %s\n", time.Since(witnessAssignmentStart))

	// --- Proof Generation ---
	proofGenerationStart := time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("Proof generation failed: %v", err)
	}
	fmt.Println("✅ Proof generated")
	fmt.Printf("⏱️ Proof generation took: %s\n", time.Since(proofGenerationStart))

	// --- Proof Verification ---
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("Public witness extraction failed: %v", err)
	}

	proofVerificationStart := time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	fmt.Printf("⏱️ Proof verification took: %s\n", time.Since(proofVerificationStart))
	if err != nil {
		log.Fatalf("❌ Proof verification failed: %v", err)
	}
	fmt.Println("🎉✅ Proof verified successfully!")
}
