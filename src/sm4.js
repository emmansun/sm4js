/** @fileOverview Low-level SM4 implementation.
 *  @author Emman Sun
 */

const rounds = 32
const fk = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
const ck = [
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
  0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
  0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
  0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
  0x484f565d, 0x646b7279
]

/**
 * Schedule out an SM4 key for both encryption and decryption.  This
 * is a low-level class.  Use a cipher mode to do bulk encryption.
 *
 * @constructor
 * @param {Array} key The key as an array of 4 words.
 */
const SM4 = function (key) {
  if (!this._tables[0][0]) {
    this._precompute()
  }
  if (key.length !== 4) {
    throw new Error('invalid sm4 key size')
  }

  let encKey = key.slice(0)
  const decKey = []

  // schedule encryption keys
  for (let i = 0; i < 4; i++) {
    encKey[i] ^= fk[i]
  }

  const sbox = this._tables[4]
  let tmp
  for (let i = 0; i < rounds; i++) {
    tmp = encKey[i + 1] ^ encKey[i + 2] ^ encKey[i + 3] ^ ck[i]
    tmp =
      (sbox[tmp >>> 24] << 24) |
      (sbox[(tmp >> 16) & 255] << 16) |
      (sbox[(tmp >> 8) & 255] << 8) |
      sbox[tmp & 255]
    tmp ^= (tmp << 13) ^ (tmp >>> 19) ^ (tmp << 23) ^ (tmp >>> 9)
    encKey[i + 4] = encKey[i] ^ tmp
    decKey[rounds - i - 1] = encKey[i + 4]
  }
  encKey = encKey.slice(4)
  this._key = [encKey, decKey]
}

SM4.prototype = {
  /**
   * Encrypt an array of 4 big-endian words.
   * @param {Array} data The plaintext.
   * @return {Array} The ciphertext.
   */
  encrypt: function (data) {
    return this._crypt(data, 0)
  },

  /**
   * Decrypt an array of 4 big-endian words.
   * @param {Array} data The ciphertext.
   * @return {Array} The plaintext.
   */
  decrypt: function (data) {
    return this._crypt(data, 1)
  },

  _tables: [[], [], [], [], []],

  _sm4L: function (x) {
    const y = (x ^=
      (x << 1) ^
      (x >> 7) ^
      ((x << 3) ^ (x >> 5)) ^
      ((x << 6) ^ (x >> 2)) ^
      ((x << 7) ^ (x >> 1)) ^
      0xd3)
    return y & 0xff
  },

  _precompute: function () {
    const sbox = this._tables[4]
    const tmp = []
    const reverseTable = []
    // generate elements of GF(2^8)
    let x = 1
    for (let i = 0; i < 256; i++) {
      tmp[i] = x
      reverseTable[x] = i
      x ^= (x << 1) ^ ((x >> 7) * 0x1f5)
    }

    for (let i = 0; i < 256; i++) {
      const x = this._sm4L(i)
      if (x === 0) {
        sbox[i] = this._sm4L(0)
      } else {
        sbox[i] = this._sm4L(tmp[255 - reverseTable[x]])
      }
      let tEnc =
        sbox[i] ^
        ((sbox[i] << 2) | (sbox[i] >>> 30)) ^
        ((sbox[i] << 10) | (sbox[i] >>> 22)) ^
        ((sbox[i] << 18) | (sbox[i] >>> 14)) ^
        ((sbox[i] << 24) | (sbox[i] >>> 8))
      for (let j = 0; j < 4; j++) {
        this._tables[j][i] = tEnc = (tEnc << 24) ^ (tEnc >>> 8)
      }
    }

    // Compactify.  Considerable speedup on Firefox.
    for (let i = 0; i < 5; i++) {
      this._tables[i] = this._tables[i].slice(0)
    }
  },

  /**
   * Encryption and decryption core.
   * @param {Array} input Four words to be encrypted or decrypted.
   * @param dir The direction, 0 for encrypt and 1 for decrypt.
   * @return {Array} The four encrypted or decrypted words.
   * @private
   */
  _crypt: function (input, dir) {
    if (input.length !== 4) {
      throw new Error('invalid sm4 block size')
    }
    const key = this._key[dir]

    let a = input[0]
    let b = input[1]
    let c = input[2]
    let d = input[3]

    a ^= this._t(b ^ c ^ d ^ key[0])
    b ^= this._t(c ^ d ^ a ^ key[1])
    c ^= this._t(d ^ a ^ b ^ key[2])
    d ^= this._t(a ^ b ^ c ^ key[3])

    for (let i = 4; i < 28; i = i + 4) {
      a ^= this._precomputedT(b ^ c ^ d ^ key[i])
      b ^= this._precomputedT(c ^ d ^ a ^ key[i + 1])
      c ^= this._precomputedT(d ^ a ^ b ^ key[i + 2])
      d ^= this._precomputedT(a ^ b ^ c ^ key[i + 3])
    }

    a ^= this._t(b ^ c ^ d ^ key[28])
    b ^= this._t(c ^ d ^ a ^ key[29])
    c ^= this._t(d ^ a ^ b ^ key[30])
    d ^= this._t(a ^ b ^ c ^ key[31])

    return [d, c, b, a]
  },

  _t: function (x) {
    const sbox = this._tables[4]
    const tmp =
      (sbox[x >>> 24] << 24) |
      (sbox[(x >> 16) & 255] << 16) |
      (sbox[(x >> 8) & 255] << 8) |
      sbox[x & 255]

    return (
      tmp ^
      ((tmp << 2) | (tmp >>> 30)) ^
      ((tmp << 10) | (tmp >>> 22)) ^
      ((tmp << 18) | (tmp >>> 14)) ^
      ((tmp << 24) | (tmp >>> 8))
    )
  },

  _precomputedT: function (x) {
    const t0 = this._tables[0]
    const t1 = this._tables[1]
    const t2 = this._tables[2]
    const t3 = this._tables[3]
    return (
      t0[x >>> 24] ^ t1[(x >>> 16) & 255] ^ t2[(x >>> 8) & 255] ^ t3[x & 255]
    )
  }
}

module.exports = SM4
