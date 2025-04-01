const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
require('dotenv').config();

const secret = process.env.JWT_SECRET;
const encryptionKey = process.env.ENCRYPTION_KEY;

const encrypt = (payload) => {
  // Generate JWT token
  const token = jwt.sign(payload, secret, { expiresIn: '1h' });

  // Encrypt using AES
  const encryptedToken = CryptoJS.AES.encrypt(token, encryptionKey).toString();

  return encryptedToken;
};

const decrypt = (token) => {
  try {
    // Decrypt AES encrypted token
    const bytes = CryptoJS.AES.decrypt(token, encryptionKey);
    const decryptedToken = bytes.toString(CryptoJS.enc.Utf8);

    // Verify and decode JWT
    return jwt.verify(decryptedToken, secret);
  } catch (error) {
    console.error("❌ Error decrypting JWT:", error.message);
    return null;
  }
};

module.exports = {
  encrypt,
  decrypt,
};
