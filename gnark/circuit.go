package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Circuit struct {
	Secret        [4]frontend.Variable `gnark:",private"` // Secret inputs (pre-image)
	Hash          frontend.Variable    `gnark:",public"`  // Public expected hash
	ExpectedField frontend.Variable    `gnark:",public"`  // Public expected degree field (as int)
}

func (circuit *Circuit) Define(api frontend.API) error {
	// Ensure that the second secret field (index 1) matches the expected degree
	api.AssertIsEqual(circuit.Secret[1], circuit.ExpectedField)

	// MiMC hash of all secrets
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	for i := 0; i < 4; i++ {
		hasher.Write(circuit.Secret[i])
	}

	// Finalize hash and enforce equality with the public hash
	api.AssertIsEqual(hasher.Sum(), circuit.Hash)
	return nil
}
