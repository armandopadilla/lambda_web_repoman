const crypto = require('crypto')

const ENCRYPT_KEY = ''
const IV_LENGTH = 16
const ITERATIONS = 2000

module.exports = {
  encrypt: (text) => {
    const iv = crypto.randomBytes(IV_LENGTH)
    const cipher = crypto.createCipheriv('aes-256-cbc', new Buffer(ENCRYPT_KEY), iv);
    let encrypted = cipher.update(text);

    encrypted = Buffer.concat([encrypted, cipher.final()])
    return iv.toString('hex') + ':' + encrypted.toString('hex');
  },

  decrypt: (text) => {
    const parts = text.split(':');
    const iv = new Buffer(parts.shift(), 'hex')
    const encryptedText = new Buffer(parts.join(':'), 'hex')
    const decipher = crypto.createDecipheriv('aes-256-cbc', new Buffer(ENCRYPT_KEY), iv)
    let decrypted = decipher.update(encryptedText);

    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString()
  },

  hashString: (string) => {
    return new Promise((resolve, reject) => {
      const salt = crypto.randomBytes(128).toString('base64');
      return crypto.pbkdf2(string, salt, ITERATIONS, 512, 'sha512', (err, key) => {
        if (err) throw err
        return resolve({
          salt,
          stringHash: key.toString('base64')
        })
      })
    })
  },

  checkHash: (string, hashedString, salt) => {
    return hashedString === crypto.pbkdf2Sync(string, salt, ITERATIONS, 512, 'sha512').toString('base64')
  },

  getRandomBytes: () => crypto.randomBytes(128).toString('base64')
}
