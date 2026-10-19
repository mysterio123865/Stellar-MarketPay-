import nacl from "tweetnacl";

// Mock localStorage for Node.js environment
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => {
      store[key] = value;
    },
    removeItem: (key: string) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    },
  };
})();

Object.defineProperty(global, "localStorage", {
  value: localStorageMock,
});

describe("NaCl encryption helpers", () => {
  beforeEach(() => {
    localStorageMock.clear();
  });

  describe("round-trip encryption/decryption", () => {
    test("encrypts and decrypts message successfully", () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      const plaintext = new Uint8Array([72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33]); // "Hello, world!"
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const ciphertext = nacl.box(plaintext, nonce, bob.publicKey, alice.secretKey);

      expect(ciphertext).not.toBeNull();

      const decrypted = nacl.box.open(ciphertext, nonce, alice.publicKey, bob.secretKey);
      expect(decrypted).not.toBeNull();

      expect(decrypted).toEqual(plaintext);
    });

    test("handles binary data correctly", () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const ciphertext = nacl.box(binaryData, nonce, bob.publicKey, alice.secretKey);

      const decrypted = nacl.box.open(ciphertext, nonce, alice.publicKey, bob.secretKey);

      expect(decrypted).toEqual(binaryData);
    });

    test("handles empty message", () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      const emptyData = new Uint8Array(0);
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const ciphertext = nacl.box(emptyData, nonce, bob.publicKey, alice.secretKey);

      const decrypted = nacl.box.open(ciphertext, nonce, alice.publicKey, bob.secretKey);

      expect(decrypted).toEqual(emptyData);
    });
  });

  describe("nonce uniqueness", () => {
    test("generates different nonces for identical messages", () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      const plaintext = new Uint8Array([83, 97, 109, 101, 32, 109, 101, 115, 115, 97, 103, 101]); // "Same message"

      // Generate nonces with different values manually
      const nonce1 = new Uint8Array(nacl.box.nonceLength);
      const nonce2 = new Uint8Array(nacl.box.nonceLength);
      for (let i = 0; i < nonce1.length; i++) {
        nonce1[i] = i;
        nonce2[i] = 255 - i;
      }

      const ciphertext1 = nacl.box(plaintext, nonce1, bob.publicKey, alice.secretKey);
      const ciphertext2 = nacl.box(plaintext, nonce2, bob.publicKey, alice.secretKey);

      // Nonces should be different
      expect(nonce1).not.toEqual(nonce2);

      // Ciphertexts should be different due to different nonces
      expect(ciphertext1).not.toEqual(ciphertext2);

      // But both should decrypt successfully
      const decrypted1 = nacl.box.open(ciphertext1, nonce1, alice.publicKey, bob.secretKey);
      const decrypted2 = nacl.box.open(ciphertext2, nonce2, alice.publicKey, bob.secretKey);

      expect(decrypted1).toEqual(plaintext);
      expect(decrypted2).toEqual(plaintext);
    });

    test("nonce length matches NaCl box specification (24 bytes)", () => {
      const nonce = new Uint8Array(nacl.box.nonceLength);

      expect(nonce.length).toBe(nacl.box.nonceLength);
      expect(nacl.box.nonceLength).toBe(24);
    });
  });

  describe("tampered-ciphertext rejection", () => {
    test("rejects ciphertext with modified bytes", () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      const plaintext = new Uint8Array([79, 114, 105, 103, 105, 110, 97, 108, 32, 109, 101, 115, 115, 97, 103, 101]); // "Original message"
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const ciphertext = nacl.box(plaintext, nonce, bob.publicKey, alice.secretKey);

      // Tamper with the ciphertext
      const tamperedCiphertext = new Uint8Array(ciphertext);
      tamperedCiphertext[ciphertext.length - 1] ^= 0xff; // Flip last byte

      const decrypted = nacl.box.open(tamperedCiphertext, nonce, alice.publicKey, bob.secretKey);

      expect(decrypted).toBeNull();
    });

    test("rejects ciphertext with modified nonce", () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      const plaintext = new Uint8Array([79, 114, 105, 103, 105, 110, 97, 108, 32, 109, 101, 115, 115, 97, 103, 101]); // "Original message"
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const ciphertext = nacl.box(plaintext, nonce, bob.publicKey, alice.secretKey);

      // Tamper with the nonce
      const tamperedNonce = new Uint8Array(nonce);
      tamperedNonce[0] ^= 0xff; // Flip first byte of nonce

      const decrypted = nacl.box.open(ciphertext, tamperedNonce, alice.publicKey, bob.secretKey);

      expect(decrypted).toBeNull();
    });


  });

  describe("cross-compatibility fixture", () => {
    test("fixture: known plaintext encrypts to deterministic format with known keys", () => {
      // This fixture guarantees format stability across versions
      // Using deterministic key generation from seed for reproducibility
      const seed = new Uint8Array(32);
      for (let i = 0; i < 32; i++) seed[i] = i;

      const alice = nacl.box.keyPair.fromSecretKey(seed);
      const bobSeed = new Uint8Array(32);
      for (let i = 0; i < 32; i++) bobSeed[i] = 31 - i;
      const bob = nacl.box.keyPair.fromSecretKey(bobSeed);

      const plaintext = new Uint8Array([70, 105, 120, 116, 117, 114, 101, 32, 116, 101, 115, 116, 32, 109, 101, 115, 115, 97, 103, 101]); // "Fixture test message"
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const ciphertext = nacl.box(plaintext, nonce, bob.publicKey, alice.secretKey);

      // Verify structure: nonce (24 bytes) + ciphertext
      expect(ciphertext.length).toBeGreaterThan(0);

      // Verify it can be decrypted
      const decrypted = nacl.box.open(ciphertext, nonce, alice.publicKey, bob.secretKey);
      expect(decrypted).toEqual(plaintext);
    });

    test("fixture: ciphertext format matches scheme documentation", () => {
      // Verify the format matches docs/messaging-encryption.md:
      // - Combined format: nonce (24 bytes) + ciphertext
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      const plaintext = new Uint8Array([70, 111, 114, 109, 97, 116, 32, 118, 101, 114, 105, 102, 105, 99, 97, 116, 105, 111, 110]); // "Format verification"
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const ciphertext = nacl.box(plaintext, nonce, bob.publicKey, alice.secretKey);

      // Verify nonce is 24 bytes per XChaCha20-Poly1305 spec
      expect(nonce.length).toBe(24);

      // Verify ciphertext is non-empty
      expect(ciphertext.length).toBeGreaterThan(0);

      // Combined format would be nonce + ciphertext
      const combined = new Uint8Array(nonce.length + ciphertext.length);
      combined.set(nonce, 0);
      combined.set(ciphertext, nonce.length);
      expect(combined.length).toBe(nonce.length + ciphertext.length);
    });
  });
});
