import crypto from "crypto";
import { initialize } from "zokrates-js";

function toU32ArrayPadded(message) {
    const msgBuf = Buffer.from(message, 'utf8');
    const messageBitLength = msgBuf.length * 8;

    const paddingStart = Buffer.from([0x80]);
    const totalLength = msgBuf.length + 1 + 8;
    const paddingZerosLength = 64 - totalLength;
    const paddingZeros = Buffer.alloc(paddingZerosLength, 0);

    const lengthBuf = Buffer.alloc(8);
    lengthBuf.writeUInt32BE(0, 0);
    lengthBuf.writeUInt32BE(messageBitLength, 4);

    const padded = Buffer.concat([msgBuf, paddingStart, paddingZeros, lengthBuf]);

    if (padded.length !== 64) {
        throw new Error("Padding error: message block must be 64 bytes");
    }

    const result = [];
    for (let i = 0; i < 64; i += 4) {
        result.push('0x' + padded.readUInt32BE(i).toString(16).padStart(8, '0'));
    }

    return result;
}

function serializeObject(obj, layout) {
    const keys = Object.keys(layout);
    let result = '';

    for (const key of keys) {
        const maxLength = layout[key];
        const value = (obj[key] ?? '').toString();

        if (value.length > maxLength) {
            throw new Error(`Value for '${key}' is too long: "${value}" (max ${maxLength})`);
        }

        const padded = value.padEnd(maxLength, ' ');
        result += padded;
    }

    const totalExpectedLength = Object.values(layout).reduce((sum, len) => sum + len, 0);
    if (result.length !== totalExpectedLength) {
        throw new Error(`Final string length ${result.length} doesn't match expected ${totalExpectedLength}`);
    }

    return result;
}

function hexHashToU32Array(hexHash) {
    const hashBuf = Buffer.from(hexHash, 'hex');
    const result = [];
    for (let i = 0; i < 32; i += 4) {
        result.push('0x' + hashBuf.readUInt32BE(i).toString(16).padStart(8, '0'));
    }
    return result;
}

function strToU32Array(str, expectedLength) {
    const buf = Buffer.from(str, 'utf8');

    if (expectedLength % 4 !== 0) {
        throw new Error("Expected length must be divisible by 4");
    }

    if (buf.length > expectedLength) {
        throw new Error(`Input string is too long (max ${expectedLength} bytes)`);
    }

    const paddedBuf = Buffer.alloc(expectedLength, ' '.charCodeAt(0));
    buf.copy(paddedBuf);

    const u32 = [];
    for (let i = 0; i < expectedLength; i += 4) {
        u32.push('0x' + paddedBuf.readUInt32BE(i).toString(16).padStart(8, '0'));
    }

    return u32;
}

const zokratesProvider = await initialize();

const source = `
    import "hashes/sha256/512bit" as sha256;

    def main(private u32[16] vc_data, public u32[8] vc_hash, public u32[8] expected_degree) -> bool {
        u32[8] hash = sha256(vc_data[0..8], vc_data[8..16]);

        for u32 i in 0..8 {
            assert(hash[i] == vc_hash[i]);
        }

        for u32 i in 0..8 {
            assert(vc_data[i + 3] == expected_degree[i]);
        }

        return true;
    }
`;

console.time("Compile");
const artifacts = zokratesProvider.compile(source);
console.timeEnd("Compile");

const vc = {
    name: "Lukas",
    degree: "Financial Technologies",
    university: "VU",
    year: "2025"
};
// Layout of object attributes lengths, max sum 52 bytes for easy comparison in zokrates circuit, max sum 55 bytes in general.
const layout = {
    name: 12,
    degree: 32,
    university: 4,
    year: 4
};
const expectedDegree = "Financial Technologies";

const serializedVC = serializeObject(vc, layout);
const vcDataU32 = toU32ArrayPadded(serializedVC);

const expectedDegreeU32 = strToU32Array(expectedDegree, 32);

const vcHash = crypto.createHash('sha256').update(serializedVC).digest('hex');
const vcHashU32 = hexHashToU32Array(vcHash);

console.time("Setup");
const keypair = zokratesProvider.setup(artifacts.program);
console.timeEnd("Setup");

console.time("Compute Witness");
const { witness, output } = zokratesProvider.computeWitness(artifacts, [vcDataU32, vcHashU32, expectedDegreeU32]);
console.timeEnd("Compute Witness");
console.log("output:", output);

console.time("Generate Proof");
const proof = zokratesProvider.generateProof(artifacts.program, witness, keypair.pk);
console.timeEnd("Generate Proof");

console.time("Verify Proof");
const isVerified = zokratesProvider.verify(keypair.vk, proof);
console.timeEnd("Verify Proof");
console.log("isVerified:", isVerified);