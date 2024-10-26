"use strict";
const fs = require("fs");

const { getRandomValues } = require("crypto");

/**
 * Converts a plaintext string into a buffer for use in SubtleCrypto functions.
 * @param {string} str - A plaintext string
 * @returns {Buffer} A buffer representation for use in SubtleCrypto functions
 */
function stringToBuffer(str) {
  return Buffer.from(str);
}

/**
 * Converts a buffer object representing string data back into a string
 * @param {BufferSource} buf - A buffer containing string data
 * @returns {string} The original string
 */
function bufferToString(buf) {
  return Buffer.from(buf).toString();
}

/**
 * Converts a buffer to a Base64 string which can be used as a key in a map and
 * can be easily serialized.
 * @param {BufferSource} buf - A buffer-like object
 * @returns {string} A Base64 string representing the bytes in the buffer
 */
function encodeBuffer(buf) {
  return Buffer.from(buf).toString("base64");
}

/**
 * Converts a Base64 string back into a buffer
 * @param {string} base64 - A Base64 string representing a buffer
 * @returns {Buffer} A Buffer object
 */
function decodeBuffer(base64) {
  return Buffer.from(base64, "base64");
}

/**
 * Generates a buffer of random bytes
 * @param {number} len - The number of random bytes
 * @returns {Uint8Array} A buffer of `len` random bytes
 */
function getRandomBytes(len) {
  return getRandomValues(new Uint8Array(len));
}

// Simple encryption function using XOR
function simpleEncrypt(text, key) {
  let encryptedText = "";
  for (let i = 0; i < text.length; i++) {
    // XOR each character with the key character (loop through the key)
    encryptedText += String.fromCharCode(
      text.charCodeAt(i) ^ key.charCodeAt(i % key.length)
    );
  }
  return btoa(encryptedText); // Convert to base64 for safe storage
}

// Simple decryption function using XOR
function simpleDecrypt(encryptedText, key) {
  const decodedText = atob(encryptedText); // Decode base64
  let decryptedText = "";
  for (let i = 0; i < decodedText.length; i++) {
    decryptedText += String.fromCharCode(
      decodedText.charCodeAt(i) ^ key.charCodeAt(i % key.length)
    );
  }
  return decryptedText;
}

function getJsonFile(fileName) {
  try {
    let jsonString = fs.readFileSync(`database/${fileName}`, "utf8");
    jsonString = JSON.parse(jsonString);
    return jsonString;
  } catch (e) {
    console.log(e.message);
    return false;
  }
}

function writeToJsonFile(fileName, jsonString) {
  jsonString = JSON.stringify(jsonString);

  fs.writeFileSync(`database/${fileName}`, jsonString, (err) => {
    if (err) {
      console.error("Error writing to file", err);
    }
  });
}

function verifyPassword(password) {
  let { pass, key } = getJsonFile("session.json");
  return simpleDecrypt(pass, key) === password;
}

module.exports = {
  stringToBuffer,
  bufferToString,
  encodeBuffer,
  decodeBuffer,
  getRandomBytes,
  //Added lib functions
  getJsonFile,
  writeToJsonFile,
  simpleEncrypt,
  simpleDecrypt,
  verifyPassword,
};
