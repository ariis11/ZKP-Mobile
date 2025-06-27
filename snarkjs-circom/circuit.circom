pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";

template HashObject() {
    signal input preimage[60];
    signal input expectedHash;
    signal input expectedDegree[32];
    signal output finalHash;

    component groupHashers[4];

    for (var g = 0; g < 4; g++) {
        groupHashers[g] = Poseidon(15);
        for (var i = 0; i < 15; i++) {
            groupHashers[g].inputs[i] <== preimage[g * 15 + i];
        }
    }

    component finalHasher = Poseidon(4);
    for (var i = 0; i < 4; i++) {
        finalHasher.inputs[i] <== groupHashers[i].out;
    }

    finalHash <== finalHasher.out;
    finalHash === expectedHash;

    for (var i = 0; i < 32; i++) {
        preimage[12 + i] === expectedDegree[i];
    }
}

component main = HashObject();
