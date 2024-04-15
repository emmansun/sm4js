/** @fileOverview Low-level SM3 implementation.
 *  @author Emman Sun
 */

function bindSM3 (sjcl) {
  /**
   * Context for a SM3 operation in progress.
   * @constructor
   */
  sjcl.hash.sm3 = sjcl.hash.sm3 || function (hash) {
    if (!this._t[0]) {
      this._precompute()
    }
    if (hash) {
      this._h = hash._h.slice(0)
      this._buffer = hash._buffer.slice(0)
      this._length = hash._length
    } else {
      this.reset()
    }
  }

  const SM3 = sjcl.hash.sm3
  /**
   * Hash a string or an array of words.
   * @static
   * @param {bitArray|String} data the data to hash.
   * @return {bitArray} The hash value, an array of 16 big-endian words.
   */
  SM3.hash = function (data) {
    return new SM3().update(data).finalize()
  }

  SM3.prototype = {
    /**
     * The hash's block size, in bits.
     * @constant
     */
    blockSize: 512,

    /**
     * Reset the hash state.
     * @return this
     */
    reset: function () {
      this._h = this._init.slice(0)
      this._buffer = []
      this._length = 0
      return this
    },

    /**
     * Input several words to the hash.
     * @param {bitArray|String} data the data to hash.
     * @return this
     */
    update: function (data) {
      if (typeof data === 'string') {
        data = sjcl.codec.utf8String.toBits(data)
      }
      let i
      const b = (this._buffer = sjcl.bitArray.concat(this._buffer, data))
      const ol = this._length
      const nl = (this._length = ol + sjcl.bitArray.bitLength(data))
      if (nl > 9007199254740991) {
        throw new Error('Cannot hash more than 2^53 - 1 bits')
      }

      if (typeof Uint32Array !== 'undefined') {
        const c = new Uint32Array(b)
        let j = 0
        for (i = 512 + ol - ((512 + ol) & 511); i <= nl; i += 512) {
          this._block(c.subarray(16 * j, 16 * (j + 1)))
          j += 1
        }
        b.splice(0, 16 * j)
      } else {
        for (i = 512 + ol - ((512 + ol) & 511); i <= nl; i += 512) {
          this._block(b.splice(0, 16))
        }
      }
      return this
    },

    /**
     * Complete hashing and output the hash value.
     * @return {bitArray} The hash value, an array of 8 big-endian words.
     */
    finalize: function () {
      let i
      let b = this._buffer
      const h = this._h

      // Round out and push the buffer
      b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)])

      // Round out the buffer to a multiple of 16 words, less the 2 length words.
      for (i = b.length + 2; i & 15; i++) {
        b.push(0)
      }

      // append the length
      b.push(Math.floor(this._length / 0x100000000))
      b.push(this._length | 0)

      while (b.length) {
        this._block(b.splice(0, 16))
      }

      this.reset()
      return h
    },

    /**
     * Perform one cycle of SM3.
     * @param {Uint32Array|bitArray} w one block of words.
     * @private
     */
    _block: function (w) {
      const H = this._h
      const t = this._t
      let a = H[0]
      let b = H[1]
      let c = H[2]
      let d = H[3]
      let e = H[4]
      let f = H[5]
      let g = H[6]
      let h = H[7]
      const W = []
      let ss1, ss2, tt1, tt2
      for (let i = 0; i < 4; i++) {
        W[i] = w[i] | 0
      }
      for (let i = 0; i < 12; i++) {
        W[i + 4] = w[i + 4] | 0
        tt2 = this._rotateLeft32(a, 12)
        ss1 = this._rotateLeft32(tt2 + e + t[i], 7)
        ss2 = ss1 ^ tt2
        tt1 = (a ^ b ^ c) + d + ss2 + (W[i] ^ W[i + 4])
        tt2 = (e ^ f ^ g) + h + ss1 + W[i]
        d = c
        c = this._rotateLeft32(b, 9)
        b = a
        a = tt1 | 0
        h = g
        g = this._rotateLeft32(f, 19)
        f = e
        e = this._p0(tt2)
      }
      for (let i = 12; i < 16; i++) {
        W[i + 4] = this._p1(W[i - 12] ^ W[i - 5] ^ this._rotateLeft32(W[i + 1], 15)) ^
          this._rotateLeft32(W[i - 9], 7) ^ W[i - 2]
        tt2 = this._rotateLeft32(a, 12)
        ss1 = this._rotateLeft32(tt2 + e + t[i], 7)
        ss2 = ss1 ^ tt2
        tt1 = (a ^ b ^ c) + d + ss2 + (W[i] ^ W[i + 4])
        tt2 = (e ^ f ^ g) + h + ss1 + W[i]
        d = c
        c = this._rotateLeft32(b, 9)
        b = a
        a = tt1 | 0
        h = g
        g = this._rotateLeft32(f, 19)
        f = e
        e = this._p0(tt2)
      }
      for (let i = 16; i < 64; i++) {
        W[i + 4] = this._p1(W[i - 12] ^ W[i - 5] ^ this._rotateLeft32(W[i + 1], 15)) ^
          this._rotateLeft32(W[i - 9], 7) ^ W[i - 2]
        tt2 = this._rotateLeft32(a, 12)
        ss1 = this._rotateLeft32(tt2 + e + t[i], 7)
        ss2 = ss1 ^ tt2
        tt1 = this._ff(a, b, c) + d + ss2 + (W[i] ^ W[i + 4])
        tt2 = this._gg(e, f, g) + h + ss1 + W[i]
        d = c
        c = this._rotateLeft32(b, 9)
        b = a
        a = tt1 | 0
        h = g
        g = this._rotateLeft32(f, 19)
        f = e
        e = this._p0(tt2)
      }
      H[0] = H[0] ^ a
      H[1] = H[1] ^ b
      H[2] = H[2] ^ c
      H[3] = H[3] ^ d
      H[4] = H[4] ^ e
      H[5] = H[5] ^ f
      H[6] = H[6] ^ g
      H[7] = H[7] ^ h
    },

    /**
     * The SM3 initialization vector.
     * @private
     */
    _init: [
      0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa,
      0xe38dee4d, 0xb0fb0e4e
    ],

    /**
     * The SM3 hash constant T, to be precomputed.
     * @private
     */
    _t: [],

    /**
     * Function to precompute _t.
     * @private
     */
    _precompute: function () {
      for (let i = 0; i < 16; i++) {
        this._t[i] = this._rotateLeft32(0x79cc4519, i)
      }
      for (let i = 16; i < 64; i++) {
        this._t[i] = this._rotateLeft32(0x7a879d8a, i)
      }
    },

    _rotateLeft32: function (x, k) {
      const n = 32
      return (x << k) | (x >>> (n - k))
    },

    _p0: function (x) {
      return x ^ this._rotateLeft32(x, 9) ^ this._rotateLeft32(x, 17)
    },

    _p1: function (x) {
      return x ^ this._rotateLeft32(x, 15) ^ this._rotateLeft32(x, 23)
    },

    _ff: function (x, y, z) {
      return (x & y) | (x & z) | (y & z)
    },

    _gg: function (x, y, z) {
      return ((y ^ z) & x) ^ z
    }
  }
}

module.exports = {
  bindSM3
}
