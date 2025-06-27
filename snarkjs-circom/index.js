const snarkjs = require("snarkjs");
const fs = require("fs");
const circomlibjs = require("circomlibjs");
const { execSync } = require("child_process");

async function compileCircuit() {
    console.log("🚀 Compiling Circom Circuit...");
    try {
        execSync("circom circuit.circom --r1cs --wasm --sym", { stdio: "inherit" });
        console.log("✅ Circuit compiled successfully.");
    } catch (err) {
        throw new Error("❌ Circuit compilation failed: " + err.message);
    }
}

async function trustedSetup() {
    console.log("🚀 Running Trusted Setup...");
    await snarkjs.zKey.newZKey(
        "circuit.r1cs",
        "powersOfTau28_hez_final_15.ptau",
        "circuit_0000.zkey"
    );
    const vKey = await snarkjs.zKey.exportVerificationKey("circuit_0000.zkey");
    fs.writeFileSync("verification_key.json", JSON.stringify(vKey));
    console.log("✅ Trusted setup complete.");
}

async function generateWitness() {
    console.log("🚀 Generating Witness...");

    const wc = require("./circuit_js/witness_calculator.js");

    const wasmBuffer = fs.readFileSync("circuit_js/circuit.wasm");
    const witnessCalculator = await wc(wasmBuffer);

    const vc = {
        name: "Lukas",
        degreeTitle: "Financial Technologies",
        university: "Vilnius",
        year: "2025"
    };
    const layout = {
        name: 12,
        degreeTitle: 32,
        university: 8,
        year: 8
    };

    let serialized = "";
    for (const [key, padLength] of Object.entries(layout)) {
        let value = vc[key] || "";
        value = value.padEnd(padLength).substring(0, padLength);
        serialized += value;
    }

    const degreeString = serialized.slice(layout.name, layout.name + layout.degreeTitle);
    const expectedDegreeCharCodes = Array.from(degreeString).map(c => c.charCodeAt(0));
    const charCodes = Array.from(serialized).map(c => c.charCodeAt(0));

    const poseidon = await circomlibjs.buildPoseidon();
    const F = poseidon.F;
    const groupHashes = [];

    for (let i = 0; i < 4; i++) {
        const chunk = charCodes.slice(i * 15, (i + 1) * 15);
        const hash = poseidon(chunk);
        groupHashes.push(hash);
    }

    const finalHash = poseidon(groupHashes);
    const expectedHash = F.toString(finalHash);

    const input = {
        preimage: charCodes.map(v => v.toString()),
        expectedHash: expectedHash,
        expectedDegree: expectedDegreeCharCodes.map(v => v.toString())
    };

    const witness = await witnessCalculator.calculateWTNSBin(input, 0);
    fs.writeFileSync("witness.wtns", witness);
    console.log("✅ Witness generated.");
}

async function generateProof() {
    console.log("🚀 Generating Proof...");
    const witness = fs.readFileSync("witness.wtns");

    const { proof, publicSignals } = await snarkjs.groth16.prove(
        "circuit_0000.zkey",
        witness
    );

    fs.writeFileSync("proof.json", JSON.stringify(proof));
    fs.writeFileSync("public.json", JSON.stringify(publicSignals));
    console.log("✅ Proof generated.");
}

async function verifyProof() {
    console.log("🚀 Verifying Proof...");
    const vKey = JSON.parse(fs.readFileSync("verification_key.json"));
    const proof = JSON.parse(fs.readFileSync("proof.json"));
    const publicSignals = JSON.parse(fs.readFileSync("public.json"));

    const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);

    if (res === true) {
        console.log("🎉 Proof is VALID!");
    } else {
        console.log("❌ Proof is INVALID!");
    }
}

async function runAll() {
    try {
        console.time("⏱️ Compile Circuit Time");
        await compileCircuit();
        console.timeEnd("⏱️ Compile Circuit Time");
        console.time("⏱️ Trusted Setup Time");
        await trustedSetup();
        console.timeEnd("⏱️ Trusted Setup Time");
        console.time("⏱️ Generate Witness Time");
        await generateWitness();
        console.timeEnd("⏱️ Generate Witness Time");
        console.time("⏱️ Generate Proof Time");
        await generateProof();
        console.timeEnd("⏱️ Generate Proof Time");
        console.time("⏱️ Verify Proof Time");
        await verifyProof();
        console.timeEnd("⏱️ Verify Proof Time");
        console.log("✅ All steps completed successfully!");
        process.exit(0);
    } catch (err) {
        console.error("🔥 Error encountered:", err);
        process.exit(1);
    }
}


runAll();
