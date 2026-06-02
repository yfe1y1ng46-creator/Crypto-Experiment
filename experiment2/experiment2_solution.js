const crypto = require("crypto");

const BLOCK_SIZE = 16;

function pkcs7Pad(buffer, blockSize = BLOCK_SIZE) {
  const remainder = buffer.length % blockSize;
  const padLen = remainder === 0 ? blockSize : blockSize - remainder;
  return Buffer.concat([buffer, Buffer.alloc(padLen, padLen)]);
}

function pkcs7Unpad(buffer, blockSize = BLOCK_SIZE) {
  if (buffer.length === 0 || buffer.length % blockSize !== 0) {
    throw new Error("invalid padding length");
  }
  const padLen = buffer[buffer.length - 1];
  if (padLen < 1 || padLen > blockSize) {
    throw new Error("invalid padding byte");
  }
  const tail = buffer.subarray(buffer.length - padLen);
  if (![...tail].every((b) => b === padLen)) {
    throw new Error("invalid padding content");
  }
  return buffer.subarray(0, buffer.length - padLen);
}

function aesEcbEncrypt(plaintext, key) {
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

function aesEcbDecrypt(ciphertext, key) {
  const decipher = crypto.createDecipheriv("aes-128-ecb", key, null);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function xorBuffers(a, b) {
  return Buffer.from(a.map((byte, i) => byte ^ b[i]));
}

function aesCbcEncrypt(plaintext, key, iv) {
  const padded = pkcs7Pad(plaintext);
  const blocks = [];
  let previous = iv;
  for (let i = 0; i < padded.length; i += BLOCK_SIZE) {
    const block = padded.subarray(i, i + BLOCK_SIZE);
    const encrypted = aesEcbEncrypt(xorBuffers(block, previous), key);
    blocks.push(encrypted);
    previous = encrypted;
  }
  return Buffer.concat(blocks);
}

function aesCbcDecrypt(ciphertext, key, iv, unpad = true) {
  const blocks = [];
  let previous = iv;
  for (let i = 0; i < ciphertext.length; i += BLOCK_SIZE) {
    const block = ciphertext.subarray(i, i + BLOCK_SIZE);
    const decrypted = xorBuffers(aesEcbDecrypt(block, key), previous);
    blocks.push(decrypted);
    previous = block;
  }
  const plaintext = Buffer.concat(blocks);
  return unpad ? pkcs7Unpad(plaintext) : plaintext;
}

function countRepeatedBlocks(buffer, blockSize = BLOCK_SIZE) {
  const seen = new Set();
  let repeated = 0;
  for (let i = 0; i < buffer.length; i += blockSize) {
    const block = buffer.subarray(i, i + blockSize).toString("hex");
    if (seen.has(block)) repeated += 1;
    seen.add(block);
  }
  return repeated;
}

function detectMode(ciphertext) {
  return countRepeatedBlocks(ciphertext) > 0 ? "ECB" : "CBC";
}

function encryptionOracle(input) {
  const key = crypto.randomBytes(16);
  const prefix = crypto.randomBytes(5 + Math.floor(Math.random() * 6));
  const suffix = crypto.randomBytes(5 + Math.floor(Math.random() * 6));
  const plaintext = pkcs7Pad(Buffer.concat([prefix, input, suffix]));
  if (Math.random() < 0.5) {
    return { mode: "ECB", ciphertext: aesEcbEncrypt(plaintext, key) };
  }
  return {
    mode: "CBC",
    ciphertext: aesCbcEncrypt(Buffer.concat([prefix, input, suffix]), key, crypto.randomBytes(16)),
  };
}

const UNKNOWN_B64 =
  "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
  "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
  "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

const SIMPLE_KEY = Buffer.from("YELLOW SUBMARINE");

function simpleEcbOracle(input) {
  return aesEcbEncrypt(pkcs7Pad(Buffer.concat([input, Buffer.from(UNKNOWN_B64, "base64")])), SIMPLE_KEY);
}

function discoverBlockSize(oracle) {
  const initial = oracle(Buffer.alloc(0)).length;
  for (let n = 1; n <= 64; n++) {
    const length = oracle(Buffer.alloc(n, 0x41)).length;
    if (length > initial) return length - initial;
  }
  throw new Error("block size not found");
}

function discoverUnknownLength(oracle, knownPrefixLength = 0, fixedInput = Buffer.alloc(0)) {
  const baseLen = oracle(fixedInput).length;
  for (let n = 1; n <= BLOCK_SIZE * 2; n++) {
    const length = oracle(Buffer.concat([fixedInput, Buffer.alloc(n, 0x41)])).length;
    if (length > baseLen) {
      return baseLen - knownPrefixLength - n;
    }
  }
  throw new Error("unknown length not found");
}

function byteAtATimeEcbSimple() {
  const blockSize = discoverBlockSize(simpleEcbOracle);
  if (detectMode(simpleEcbOracle(Buffer.alloc(blockSize * 4, 0x41))) !== "ECB") {
    throw new Error("oracle is not ECB");
  }

  const recovered = [];
  const unknownLen = discoverUnknownLength(simpleEcbOracle);
  for (let i = 0; i < unknownLen; i++) {
    const padLen = blockSize - 1 - (i % blockSize);
    const prefix = Buffer.alloc(padLen, 0x41);
    const targetBlock = Math.floor(i / blockSize);
    const target = simpleEcbOracle(prefix).subarray(targetBlock * blockSize, (targetBlock + 1) * blockSize);
    const dict = new Map();
    for (let b = 0; b < 256; b++) {
      const probe = Buffer.concat([prefix, Buffer.from(recovered), Buffer.from([b])]);
      const block = simpleEcbOracle(probe).subarray(targetBlock * blockSize, (targetBlock + 1) * blockSize);
      dict.set(block.toString("hex"), b);
    }
    const found = dict.get(target.toString("hex"));
    if (found === undefined) break;
    recovered.push(found);
  }
  return Buffer.from(recovered);
}

function profileFor(email) {
  const clean = email.replace(/[&=]/g, "");
  return `email=${clean}&uid=10&role=user`;
}

const PROFILE_KEY = Buffer.from("0123456789abcdef");

function encryptProfile(email) {
  return aesEcbEncrypt(pkcs7Pad(Buffer.from(profileFor(email))), PROFILE_KEY);
}

function decryptProfile(ciphertext) {
  return pkcs7Unpad(aesEcbDecrypt(ciphertext, PROFILE_KEY)).toString("utf8");
}

function ecbCutAndPasteAdmin() {
  const adminBlockEmail = "A".repeat(10) + "admin" + String.fromCharCode(11).repeat(11);
  const adminBlock = encryptProfile(adminBlockEmail).subarray(16, 32);
  const normal = encryptProfile("foo@bar12.com");
  const forged = Buffer.concat([normal.subarray(0, 32), adminBlock]);
  return decryptProfile(forged);
}

const HARD_PREFIX = crypto.randomBytes(19);

function hardEcbOracle(input) {
  return aesEcbEncrypt(
    pkcs7Pad(Buffer.concat([HARD_PREFIX, input, Buffer.from(UNKNOWN_B64, "base64")])),
    SIMPLE_KEY
  );
}

function findPrefixAlignment(oracle, blockSize) {
  for (let padLen = 0; padLen < blockSize; padLen++) {
    const probe = Buffer.concat([Buffer.alloc(padLen, 0x41), Buffer.alloc(blockSize * 2, 0x42)]);
    const ct = oracle(probe);
    for (let block = 0; block < ct.length / blockSize - 1; block++) {
      const a = ct.subarray(block * blockSize, (block + 1) * blockSize).toString("hex");
      const b = ct.subarray((block + 1) * blockSize, (block + 2) * blockSize).toString("hex");
      if (a === b) return { padLen, prefixBlocks: block };
    }
  }
  throw new Error("prefix alignment not found");
}

function byteAtATimeEcbHarder() {
  const blockSize = discoverBlockSize(hardEcbOracle);
  const { padLen, prefixBlocks } = findPrefixAlignment(hardEcbOracle, blockSize);
  const align = Buffer.alloc(padLen, 0x41);
  const recovered = [];
  const knownPrefixLength = prefixBlocks * blockSize;
  const unknownLen = discoverUnknownLength(hardEcbOracle, knownPrefixLength, align);

  for (let i = 0; i < unknownLen; i++) {
    const shortPadLen = blockSize - 1 - (i % blockSize);
    const prefix = Buffer.concat([align, Buffer.alloc(shortPadLen, 0x41)]);
    const targetBlock = prefixBlocks + Math.floor(i / blockSize);
    const target = hardEcbOracle(prefix).subarray(targetBlock * blockSize, (targetBlock + 1) * blockSize);
    const dict = new Map();
    for (let b = 0; b < 256; b++) {
      const probe = Buffer.concat([prefix, Buffer.from(recovered), Buffer.from([b])]);
      const block = hardEcbOracle(probe).subarray(targetBlock * blockSize, (targetBlock + 1) * blockSize);
      dict.set(block.toString("hex"), b);
    }
    const found = dict.get(target.toString("hex"));
    if (found === undefined) break;
    recovered.push(found);
  }
  return Buffer.from(recovered);
}

const BITFLIP_KEY = Buffer.from("fedcba9876543210");
const BITFLIP_IV = Buffer.alloc(16, 0);

function bitflipEncrypt(userdata) {
  const clean = userdata.replace(/[;=]/g, "");
  const text = `comment1=cooking%20MCs;userdata=${clean};comment2=%20like%20a%20pound%20of%20bacon`;
  return aesCbcEncrypt(Buffer.from(text), BITFLIP_KEY, BITFLIP_IV);
}

function bitflipIsAdmin(ciphertext) {
  const plaintext = aesCbcDecrypt(ciphertext, BITFLIP_KEY, BITFLIP_IV, false);
  return plaintext.includes(Buffer.from(";admin=true;"));
}

function cbcBitflippingAttack() {
  const injected = "XadminXtrueX";
  const attackText = "A".repeat(16) + injected;
  const ciphertext = Buffer.from(bitflipEncrypt(attackText));
  const target = ";admin=true;";
  const offset = "comment1=cooking%20MCs;userdata=".length + 16;
  for (let i = 0; i < target.length; i++) {
    ciphertext[offset - BLOCK_SIZE + i] ^= injected.charCodeAt(i) ^ target.charCodeAt(i);
  }
  return bitflipIsAdmin(ciphertext);
}

function mrzCheckDigit(chars) {
  const values = { "<": 0 };
  for (let i = 0; i <= 9; i++) values[String(i)] = i;
  for (let i = 0; i < 26; i++) values[String.fromCharCode(65 + i)] = 10 + i;
  const weights = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < chars.length; i++) sum += values[chars[i]] * weights[i % 3];
  return String(sum % 10);
}

function oddParityByte(byte) {
  const high7 = byte & 0xfe;
  const ones = high7.toString(2).split("1").length - 1;
  return ones % 2 === 0 ? high7 | 1 : high7;
}

function deriveMrzAesKey() {
  const partial = "12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4";
  const expiryCheck = mrzCheckDigit("111116");
  const mrz = partial.replace("?", expiryCheck);
  const mrzInfo = mrz.slice(0, 10) + mrz.slice(13, 20) + mrz.slice(21, 28);
  const kSeed = crypto.createHash("sha1").update(mrzInfo, "ascii").digest().subarray(0, 16);
  const d = crypto
    .createHash("sha1")
    .update(Buffer.concat([kSeed, Buffer.from("00000001", "hex")]))
    .digest();
  const rawKey = d.subarray(0, 16);
  const key = Buffer.from([...rawKey].map(oddParityByte));
  const ciphertext = Buffer.from(
    "9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI",
    "base64"
  );
  const decipher = crypto.createDecipheriv("aes-128-cbc", key, Buffer.alloc(16, 0));
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return { mrz, key: key.toString("hex"), plaintext: decrypted.toString("utf8").replace(/\x01\x00*$/g, "") };
}

function main() {
  const mtc3 = deriveMrzAesKey();
  const oracleRuns = Array.from({ length: 20 }, () => {
    const result = encryptionOracle(Buffer.alloc(64, 0x41));
    return detectMode(result.ciphertext) === result.mode;
  });
  const simple = byteAtATimeEcbSimple();
  const hard = byteAtATimeEcbHarder();

  console.log("MTC3 completed MRZ:", mtc3.mrz);
  console.log("MTC3 AES key:", mtc3.key);
  console.log("MTC3 codeword:", mtc3.plaintext.match(/Codewort lautet: (.*)!/)[1]);
  console.log("MTC3 plaintext SHA256:", crypto.createHash("sha256").update(mtc3.plaintext).digest("hex"));
  console.log("PKCS#7:", pkcs7Pad(Buffer.from("YELLOW SUBMARINE"), 20).toString("hex"));
  console.log("CBC roundtrip:", aesCbcDecrypt(aesCbcEncrypt(Buffer.from("CBC mode test"), SIMPLE_KEY, Buffer.alloc(16)), SIMPLE_KEY, Buffer.alloc(16)).toString());
  console.log("Oracle accuracy:", `${oracleRuns.filter(Boolean).length}/${oracleRuns.length}`);
  console.log("Byte-at-time simple len/hash:", simple.length, crypto.createHash("sha256").update(simple).digest("hex"));
  console.log("ECB cut-and-paste profile:", ecbCutAndPasteAdmin());
  console.log("Byte-at-time harder len/hash:", hard.length, crypto.createHash("sha256").update(hard).digest("hex"));
  console.log("PKCS#7 valid:", pkcs7Unpad(Buffer.from("ICE ICE BABY\x04\x04\x04\x04")).toString());
  console.log("CBC bitflipping admin:", cbcBitflippingAttack());
}

main();
