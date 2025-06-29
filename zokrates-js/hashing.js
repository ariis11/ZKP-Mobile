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

const zokratesProvider = await initialize();

const source = `
    import "hashes/sha256/512bit" as sha256;

    def main(u32[16] input) -> u32[8] {
        u32[8] hash = sha256(input[0..8], input[8..16]);
        return hash;
    }
`;
const artifacts = zokratesProvider.compile(source);

const originalMessage = 'abc';
const input = toU32ArrayPadded(originalMessage);
console.log("originalMessage:", originalMessage);
console.log("Input to ZoKrates:", input);

const { output } = zokratesProvider.computeWitness(artifacts, [input]);
console.log("ZoKrates output:", output);

const hash = crypto.createHash('sha256').update(originalMessage).digest('hex');
console.log("Node SHA256:", hash);