"use strict";

/********* External Imports ********/

const {
  stringToBuffer,
  bufferToString,
  encodeBuffer,
  decodeBuffer,
  getRandomBytes,
} = require("./lib");
const { subtle } = require("crypto").webcrypto;
const fs = require("fs");

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64; // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   *  You may design the constructor with any parameters you would like.
   * Return Type: void
   */

  constructor(hmacKey, aesKey, salt, kvs = {}) {
    this.data = {
      kvs,
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      hmacKey,
      aesKey,
      salt,
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
    };
  }

  /**
   * Creates an empty keychain with the given password.
   *
   * Arguments:
   *   password: string
   * Return Type: void
   */
  static async init(password) {
    // Derive the key material using PBKDF2
    const salt = getRandomBytes(16); // Generate random salt
    const keyMaterial = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    // Derive HMAC key and AES-GCM key from the password
    const hmacKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      true,
      ["sign", "verify"]
    );

    const aesKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // Return a new Keychain object with empty KVS
    return new Keychain(hmacKey, aesKey, salt);
  }

  /**
   * Loads the keychain state from the provided representation (repr). The
   * repr variable will contain a JSON encoded serialization of the contents
   * of the KVS (as returned by the dump function). The trustedDataCheck
   * is an *optional* SHA-256 checksum that can be used to validate the
   * integrity of the contents of the KVS. If the checksum is provided and the
   * integrity check fails, an exception should be thrown. You can assume that
   * the representation passed to load is well-formed (i.e., it will be
   * a valid JSON object).Returns a Keychain object that contains the data
   * from repr.
   *
   * Arguments:
   *   password:           string
   *   repr:               string
   *   trustedDataCheck: string
   * Return Type: Keychain
   */
  static async load(password, repr, trustedDataCheck = "") {
    const parsedRepr = JSON.parse(repr);
    const kvs = parsedRepr.kvs;
    const storedChecksum = parsedRepr.checksum;

    // Recalculate checksum
    const currentChecksum = await subtle.digest(
      "SHA-256",
      stringToBuffer(JSON.stringify(parsedRepr))
    );
    if (
      trustedDataCheck &&
      encodeBuffer(currentChecksum) !== trustedDataCheck
    ) {
      throw new Error("Data integrity check failed (tampering detected).");
    }

    // Initialize the keys using PBKDF2 and password
    const salt = decodeBuffer(parsedRepr.salt);
    const keyMaterial = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const hmacKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      true,
      ["sign", "verify"]
    );

    const aesKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    let allKeys = Object.keys(kvs);
    try {
      if (allKeys.length) {
        const testKey = allKeys[0]; // Grab one key from the KVS
        const testEntry = kvs[testKey];
        const iv = decodeBuffer(testEntry.iv);
        const encryptedData = decodeBuffer(testEntry.data);

        // Attempt decryption using derived AES key to verify the password
        await subtle.decrypt(
          { name: "AES-GCM", iv: iv },
          aesKey,
          encryptedData
        );
      }
      return new Keychain(hmacKey, aesKey, salt, kvs);
    } catch (e) {
      // console.error(e.message);
      throw "Incorrect account password";
    }
  }

  /**
   * Returns a JSON serialization of the contents of the keychain that can be
   * loaded back using the load function. The return value should consist of
   * an array of two strings:
   *   arr[0] = JSON encoding of password manager
   *   arr[1] = SHA-256 checksum (as a string)
   * As discussed in the handout, the first element of the array should contain
   * all of the data in the password manager. The second element is a SHA-256
   * checksum computed over the password manager to preserve integrity.
   *
   * Return Type: array
   */
  async dump() {
    // Serialize the KVS and generate a SHA-256 hash
    const kvsString = JSON.stringify({
      kvs: this.data.kvs,
      salt: encodeBuffer(this.secrets.salt),
    });
    const kvsHash = await subtle.digest("SHA-256", stringToBuffer(kvsString));

    // fs.writeFile("data.json", kvsString, (err) => {
    //   if (err) {
    //     console.error(err);
    //   }
    // });
    // Return the serialized KVS and its hash
    return [kvsString, encodeBuffer(kvsHash)];
  }

  /**
   * Fetches the data (as a string) corresponding to the given domain from the KVS.
   * If there is no entry in the KVS that matches the given domain, then return
   * null.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<string>
   */
  async get(domain) {
    // Generate HMAC for the domain name
    const domainHMAC = await subtle.sign(
      "HMAC",
      this.secrets.hmacKey,
      stringToBuffer(domain)
    );

    // Look up the encrypted password and IV
    const record = this.data.kvs[encodeBuffer(domainHMAC)];
    if (!record) return null; // Return null if domain is not found

    // Decrypt the password using AES-GCM
    const iv = decodeBuffer(record.iv);
    const encryptedPassword = decodeBuffer(record.data);
    const decryptedPassword = await subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      this.secrets.aesKey,
      encryptedPassword
    );

    return bufferToString(decryptedPassword);
  }

  /**
   * Inserts the domain and associated data into the KVS. If the domain is
   * already in the password manager, this method should update its value. If
   * not, create a new entry in the password manager.
   *
   * Arguments:
   *   name: string
   *   value: string
   * Return Type: void
   */
  async set(domain, value) {
    // Generate HMAC for the domain name
    const domainHMAC = await subtle.sign(
      "HMAC",
      this.secrets.hmacKey,
      stringToBuffer(domain)
    );

    // Encrypt the password using AES-GCM
    const iv = getRandomBytes(12); // Generate IV for encryption
    const encryptedPassword = await subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      this.secrets.aesKey,
      stringToBuffer(value)
    );

    // Store the encrypted password and IV in the KVS
    this.data.kvs[encodeBuffer(domainHMAC)] = {
      iv: encodeBuffer(iv),
      data: encodeBuffer(encryptedPassword),
    };
  }

  /**
   * Removes the record with name from the password manager. Returns true
   * if the record with the specified name is removed, false otherwise.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<boolean>
   */
  async remove(name) {
    // Generate HMAC for the domain name
    const domainHMAC = await subtle.sign(
      "HMAC",
      this.secrets.hmacKey,
      stringToBuffer(name)
    );

    // Check if the domain exists in the KVS and remove it
    const key = encodeBuffer(domainHMAC);
    if (this.data.kvs.hasOwnProperty(key)) {
      delete this.data.kvs[key];
      return true;
    }
    return false;
  }
}

module.exports = { Keychain };
