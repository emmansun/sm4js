/** @fileOverview parse pkcs8 implementation.
 *  @author Emman Sun
 */
const { Builder, Parser } = require('./asn1')

const oidEccPublicKey = '1.2.840.10045.2.1'
const oidPBES2 = '1.2.840.113549.1.5.13'
const oidPBKDF2 = '1.2.840.113549.1.5.12'

const supportedHMACAlgorithms = [
  { oid: '1.2.840.113549.2.7', hash: 'sha1' }, // HMAC(SHA-1)
  { oid: '1.2.840.113549.2.9', hash: 'sha256' }, // HMAC(SHA-256)
  { oid: '1.2.840.113549.2.11', hash: 'sha512' }, // HMAC(SHA-512)
  { oid: '1.2.156.10197.1.401.2', hash: 'sm3' } // HMAC(SM3)
]

const supportedEncryptionSchemes = [
  { keyBitLen: 128, cipher: 'aes', mode: 'cbc', oid: '2.16.840.1.101.3.4.1.2' },
  { keyBitLen: 192, cipher: 'aes', mode: 'cbc', oid: '2.16.840.1.101.3.4.1.22' },
  { keyBitLen: 256, cipher: 'aes', mode: 'cbc', oid: '2.16.840.1.101.3.4.1.42' },
  { keyBitLen: 128, cipher: 'sm4', mode: 'cbc', oid: '1.2.156.10197.1.104.2' },
  { keyBitLen: 128, cipher: 'aes', mode: 'gcm', oid: '2.16.840.1.101.3.4.1.6' },
  { keyBitLen: 192, cipher: 'aes', mode: 'gcm', oid: '2.16.840.1.101.3.4.1.26' },
  { keyBitLen: 256, cipher: 'aes', mode: 'gcm', oid: '2.16.840.1.101.3.4.1.46' },
  { keyBitLen: 128, cipher: 'sm4', mode: 'gcm', oid: '1.2.156.10197.1.104.8' }
]

function _isValidObject (obj) {
  return obj && typeof obj === 'object' && !Array.isArray(obj)
}

function bindPKCS8 (sjcl) {
  if (sjcl.pkcs8) return
  sjcl.beware[
    "CBC mode is dangerous because it doesn't protect message integrity."
  ]()
  require('./sm3').bindSM3(sjcl)
  require('./sm4').bindSM4(sjcl)
  require('./pkix').bindPKIX(sjcl)
  sjcl.pkcs8 = {
    /**
     * Marshal EC private key to PKCS#8 DER-encoded ASN.1.
     * @param {sjcl.ecc.sm2.secretKey|sjcl.ecc.ecdsa.secretKey|sjcl.ecc.elGamal.secretKey} key EC private key object
     * @param {boolean}[includePublicKey=true] - whether to include public key
     * @param {string|bitArray} [password] - the password to encrypt the private key
     * @param {Object} [opts] - PKCS#5  Password-Based Cryptography related parameters
     */
    marshalPKCS8ECPrivateKey: function (key, includePublicKey = true, password, opts) {
      if (!password) {
        return this._marshalPKCS8ECPrivateKey(key, includePublicKey)
      }
      opts = this._mergeMarshalOptions(opts)
      const cipherOpts = opts.cipherOpts
      const kdfOpts = opts.kdfOpts

      const keyPlaintext = sjcl.codec.bytes.toBits(this._marshalPKCS8ECPrivateKey(key, includePublicKey))

      // derive key
      const hmacOID = this._getHMACOID(kdfOpts)
      const Hash = sjcl.hash[kdfOpts.hash]
      const salt = this._generateSalt(kdfOpts)
      const encryptionKey = this._pbkdf2(password, salt, kdfOpts.iter, cipherOpts.keyBitLen, Hash)

      // encryption key material
      const cipherOID = this._getCipherOID(cipherOpts)
      const Cipher = sjcl.cipher[cipherOpts.cipher]
      const cipher = new Cipher(encryptionKey)

      let ivLen = 4
      if (cipherOpts.mode === 'gcm') {
        ivLen = Math.ceil(cipherOpts.gcm.nonceLen / 4)
      }
      const iv = sjcl.random.randomWords(ivLen, 0)
      const keyCiphertext = sjcl.codec.bytes.fromBits(sjcl.mode[cipherOpts.mode].encrypt(cipher, keyPlaintext, iv, undefined, cipherOpts.gcm.ICVlen * 8))

      // marshal
      const builder = new Builder()
      builder.addASN1Sequence((b) => {
        b.addASN1Sequence((b1) => {
          b1.addASN1ObjectIdentifier(oidPBES2)
          b1.addASN1Sequence((b2) => {
            b2.addASN1Sequence((b3) => {
              b3.addASN1ObjectIdentifier(oidPBKDF2)
              b3.addASN1Sequence((b4) => {
                b4.addASN1OctetString(sjcl.codec.bytes.fromBits(salt))
                b4.addASN1Unsigned(kdfOpts.iter)
                b4.addASN1Unsigned(cipherOpts.keyLen)
                b4.addASN1Sequence((b5) => {
                  b5.addASN1ObjectIdentifier(hmacOID)
                  b5.addASN1NULL()
                })
              })
            })
            b2.addASN1Sequence((b3) => {
              b3.addASN1ObjectIdentifier(cipherOID)
              if (cipherOpts.mode === 'gcm') {
                b3.addASN1Sequence((b4) => {
                  b4.addASN1OctetString(sjcl.codec.bytes.fromBits(iv))
                  b4.addASN1Unsigned(cipherOpts.gcm.ICVlen)
                })
              } else if (cipherOpts.mode === 'cbc') {
                b3.addASN1OctetString(sjcl.codec.bytes.fromBits(iv))
              }
            })
          })
        })
        b.addASN1OctetString(keyCiphertext)
      })
      return builder.bytes()
    },

    _getHMACOID: function (kdfOpts) {
      let hmacOID
      for (let i = 0; i < supportedHMACAlgorithms.length; i++) {
        const curAlg = supportedHMACAlgorithms[i]
        if (kdfOpts.hash === curAlg.hash) {
          hmacOID = curAlg.oid
        }
      }
      if (!hmacOID) {
        throw new Error(`pkcs8: unsupported hash algorithm ${kdfOpts.hash}`)
      }
      return hmacOID
    },

    _getCipherOID: function (cipherOpts) {
      let cipherOID
      for (let i = 0; i < supportedEncryptionSchemes.length; i++) {
        const curScheme = supportedEncryptionSchemes[i]
        if (cipherOpts.cipher === curScheme.cipher && cipherOpts.mode === curScheme.mode && cipherOpts.keyBitLen === curScheme.keyBitLen) {
          cipherOID = curScheme.oid
        }
      }
      if (!cipherOID) {
        throw new Error(`pkcs8: unsupported cipher ${cipherOpts.cipher}-${cipherOpts.keyBitLen}-${cipherOpts.mode}`)
      }
      return cipherOID
    },

    _generateSalt: function (kdfOpts) {
      const wordSize = Math.ceil(kdfOpts.saltLen / 32)
      let salt = sjcl.random.randomWords(wordSize, 0)
      if (salt.length * 32 !== kdfOpts.saltLen) {
        salt = sjcl.bitArray.clamp(salt, kdfOpts.saltLen)
      }
      return salt
    },

    _mergeMarshalOptions: function (opts) {
      opts = opts || {}
      if (!_isValidObject(opts)) {
        throw new TypeError('opts must be an object')
      }
      opts.cipherOpts = opts.cipherOpts || {}
      opts.cipherOpts.cipher = opts.cipherOpts.cipher || 'aes'
      opts.cipherOpts.mode = opts.cipherOpts.mode || 'cbc'
      opts.cipherOpts.keyLen = opts.cipherOpts.keyLen || 16
      opts.cipherOpts.keyBitLen = opts.cipherOpts.keyLen * 8
      opts.cipherOpts.gcm = opts.cipherOpts.gcm || {}
      opts.cipherOpts.gcm.nonceLen = opts.cipherOpts.gcm.nonceLen || 12
      if (!(opts.cipherOpts.gcm.nonceLen > 0)) {
        throw new Error('invalid nonce length in bytes')
      }
      opts.cipherOpts.gcm.ICVlen = opts.cipherOpts.gcm.ICVlen || 12
      if (opts.cipherOpts.gcm.ICVlen < 12 || opts.cipherOpts.gcm.ICVlen > 16) {
        throw new Error('ICVlen should be in [12,16]')
      }
      opts.kdfOpts = opts.kdfOpts || {}
      opts.kdfOpts.hash = opts.kdfOpts.hash || 'sha1'
      opts.kdfOpts.iter = opts.kdfOpts.iter || 1000
      opts.kdfOpts.saltLen = opts.kdfOpts.saltLen || 64
      return opts
    },

    _marshalPKCS8ECPrivateKey: function (key, includePublicKey = true) {
      if (!(key instanceof sjcl.ecc.sm2.secretKey) && !(key instanceof sjcl.ecc.ecdsa.secretKey) && !(key instanceof sjcl.ecc.elGamal.secretKey)) {
        throw new Error('pkcs8: invalid/unsupported private key')
      }
      const serialized = key.serialize()
      const curve = sjcl.ecc.curves[serialized.curve]
      const curveOID = curve.oid
      if (!curveOID) {
        throw new Error('pkcs8: unsupported curve')
      }
      const builder = new Builder()
      builder.addASN1Sequence((b) => {
        b.addBytes([2, 1, 0]) // integer 0
        b.addASN1Sequence((b1) => {
          b1.addASN1ObjectIdentifier(oidEccPublicKey)
          b1.addASN1ObjectIdentifier(curveOID)
        })
        b.addASN1OctetString(sjcl.pkix.marshalECPrivateKey(key, includePublicKey))
      })
      return builder.bytes()
    },

    /**
     * parsePKCS8ECPrivateKey parses private key from DER-encoded byte array
     * @param {Array} keyDer DER-encoded byte array
     * @param {string|bitArray} [password] the password used to decrypt the key material
     * @returns {sjcl.ecc.sm2.secretKey|sjcl.ecc.ecdsa.secretKey} the private key object
     */
    parsePKCS8ECPrivateKey: function (keyDer, password) {
      if (!password) {
        return this._parsePKCS8ECPrivateKey(keyDer)
      }
      if (typeof password === 'string') {
        password = sjcl.codec.utf8String.toBits(password)
      }
      if (sjcl.bitArray.bitLength(password) === 0) {
        return this._parsePKCS8ECPrivateKey(keyDer)
      }
      const input = new Parser(keyDer)
      let inner = {}
      const alg = {}
      let algOID = {}
      const algParam = {}
      const encryptedKey = {}
      if (
        !input.readASN1Sequence(inner) ||
            !input.isEmpty() ||
            !inner.out.readASN1Sequence(alg) ||
            !alg.out.readASN1ObjectIdentifier(algOID) ||
            !alg.out.readAnyASN1Element(algParam) ||
            !alg.out.isEmpty() ||
            !inner.out.readASN1OctetString(encryptedKey) ||
            !inner.out.isEmpty()
      ) {
        throw new Error('pkcs8: invalid PKCS#8 asn1')
      }
      algOID = algOID.out
      if (algOID !== oidPBES2) {
        throw new Error('pkcs8: only PKCS #5 v2.0 supported')
      }
      inner = {}
      algOID = {}
      const keyDeriveStr = {}
      const encryptionSchemeStr = {}
      if (!algParam.out.readASN1Sequence(inner) ||
          !inner.out.readASN1Sequence(keyDeriveStr) ||
          !inner.out.readASN1Sequence(encryptionSchemeStr) ||
          !inner.out.isEmpty() ||
          !keyDeriveStr.out.readASN1ObjectIdentifier(algOID)
      ) {
        throw new Error('pkcs8: invalid PKCS #5 v2.0 asn1')
      }

      const kdfParam = this._parseKDFParameters(algOID.out, keyDeriveStr.out)
      const encrytpionParam = this._parseEncryptionScheme(encryptionSchemeStr.out)
      const key = this._deriveKey(kdfParam, encrytpionParam, password)
      const plaintext = this._decryptKeyContent(key, encrytpionParam, encryptedKey.out)
      return this._parsePKCS8ECPrivateKey(sjcl.codec.bytes.fromBits(plaintext))
    },

    _deriveKey: function (kdfParam, encrytpionParam, password) {
      return this._pbkdf2(password, sjcl.codec.bytes.toBits(kdfParam.salt), kdfParam.iterCnt, encrytpionParam.scheme.keyBitLen, kdfParam.scheme)
    },

    _decryptKeyContent: function (key, encrytpionParam, encryptedKey) {
      const Cipher = sjcl.cipher[encrytpionParam.scheme.cipher]
      const cipher = new Cipher(key)
      if (encrytpionParam.scheme.mode === 'gcm') {
        return sjcl.mode[encrytpionParam.scheme.mode].decrypt(cipher, sjcl.codec.bytes.toBits(encryptedKey), sjcl.codec.bytes.toBits(encrytpionParam.iv), undefined, encrytpionParam.ICVlen * 8)
      }
      return sjcl.mode[encrytpionParam.scheme.mode].decrypt(cipher, sjcl.codec.bytes.toBits(encryptedKey), sjcl.codec.bytes.toBits(encrytpionParam.iv))
    },

    _parseEncryptionScheme: function (encryptionSchemeParser) {
      const algStr = {}
      const ivStr = {}
      if (!encryptionSchemeParser.readASN1ObjectIdentifier(algStr)) {
        throw new Error('pkcs8: invalid PKCS #5 v2.0 EncryptionScheme')
      }
      const ret = { alg: algStr.out }
      for (let i = 0; i < supportedEncryptionSchemes.length; i++) {
        if (ret.alg === supportedEncryptionSchemes[i].oid) {
          ret.scheme = supportedEncryptionSchemes[i]
        }
      }
      if (!ret.scheme) {
        throw new Error(`pkcs8: unsupported encryption scheme <${ret.alg}>`)
      }

      if (ret.scheme.mode === 'gcm') {
        const inner = {}
        const ICVlenStr = {}
        if (!encryptionSchemeParser.readASN1Sequence(inner) ||
                    !inner.out.readASN1OctetString(ivStr) ||
                    !inner.out.readASN1Unsigned(ICVlenStr) ||
                    !inner.out.isEmpty()) {
          throw new Error('pkcs8: invalid ecnryption scheme parameters')
        }
        ret.ICVlen = ICVlenStr.out
        ret.iv = ivStr.out
      } else if (encryptionSchemeParser.peekASN1Tag(4)) {
        if (!encryptionSchemeParser.readASN1OctetString(ivStr)) {
          throw new Error('pkcs8: invalid PKCS #5 v2.0 EncryptionScheme')
        }
        ret.iv = ivStr.out
      }
      if (ret.scheme.mode === 'cbc' && (!ret.iv || ret.iv.length === 0)) {
        throw new Error('pkcs8: cbc mode requires iv')
      }
      return ret
    },

    _parseKDFParameters: function (algOID, paramParser) {
      if (algOID === oidPBKDF2) {
        return this._parsePBKDF2Parameters(algOID, paramParser)
      } else {
        throw new Error(`pkcs8: unsupported KDF (OID: ${algOID})`)
      }
    },

    _parsePBKDF2Parameters: function (algOID, paramParser) {
      const inner = {}
      const saltStr = {}
      const iterStr = {}
      if (!paramParser.readASN1Sequence(inner) ||
        !paramParser.isEmpty() ||
        !inner.out.readASN1OctetString(saltStr) ||
        !inner.out.readASN1Unsigned(iterStr)
      ) {
        throw new Error('pkcs8: invalid PKCS #5 v2.0 PBKDF2 param')
      }
      const iterCnt = iterStr.out
      // Just skip key length
      if (inner.out.peekASN1Tag(2)) {
        inner.out.skipASN1(2)
      }
      // handle prf
      const algStr = {}
      const algOIDStr = {}
      if (inner.out.peekASN1Tag(0x30)) {
        if (!inner.out.readASN1Sequence(algStr) ||
            !algStr.out.readASN1ObjectIdentifier(algOIDStr)) {
          throw new Error('pkcs8: invalid PRF AlgorithmIdentifier')
        }
      }
      const ret = { alg: algOID, salt: saltStr.out, iterCnt, prf: algOIDStr.out }
      if (ret.prf) {
        for (let i = 0; i < supportedHMACAlgorithms.length; i++) {
          if (ret.prf === supportedHMACAlgorithms[i].oid) {
            ret.scheme = sjcl.hash[supportedHMACAlgorithms[i].hash]
          }
        }
        if (!ret.scheme) {
          throw new Error(`pkcs8: unsupported hmac scheme <${ret.prf}>`)
        }
      } else {
        ret.scheme = sjcl.hash.sha1
      }
      return ret
    },

    _parsePKCS8ECPrivateKey: function (keyDer) {
      const input = new Parser(keyDer)
      const inner = {}
      const alg = {}
      const algOID = {}
      const algParam = {}
      const version = {}
      const keyStr = {}
      if (
        !input.readASN1Sequence(inner) ||
            !input.isEmpty() ||
            !inner.out.readASN1Unsigned(version) ||
            !inner.out.readASN1Sequence(alg) ||
            !alg.out.readASN1ObjectIdentifier(algOID) ||
            !alg.out.readASN1ObjectIdentifier(algParam) ||
            !alg.out.isEmpty() ||
            !inner.out.readASN1OctetString(keyStr)
      ) {
        throw new Error('pkcs8: invalid pkcs8 EC private key asn1')
      }
      if (algOID.out !== oidEccPublicKey) {
        throw new Error(`pkcs8: unsupported alg <${algOID.out}>`)
      }
      return sjcl.pkix.parseECPrivateKey(keyStr.out, algParam.out)
    },

    // An updated version of sjcl.misc.pbkdf2
    _pbkdf2: function (password, salt, count, length, Hash) {
      const HMAC = sjcl.misc.hmac
      const InvalidException = sjcl.exception.invalid
      count = count || 10000

      if (length < 0 || count < 0 || !Hash) {
        throw new InvalidException('invalid params to pbkdf2')
      }

      if (typeof password === 'string') {
        password = sjcl.codec.utf8String.toBits(password)
      }

      if (typeof salt === 'string') {
        salt = sjcl.codec.utf8String.toBits(salt)
      }

      const prf = new HMAC(password, Hash)
      const b = sjcl.bitArray

      let u; let ui; let out = []

      for (let k = 1; 32 * out.length < (length || 1); k++) {
        u = ui = prf.encrypt(b.concat(salt, [k]))

        for (let i = 1; i < count; i++) {
          ui = prf.encrypt(ui)
          for (let j = 0; j < ui.length; j++) {
            u[j] ^= ui[j]
          }
        }

        out = out.concat(u)
      }

      if (length) { out = b.clamp(out, length) }

      return out
    }
  }
}

module.exports = {
  bindPKCS8
}
