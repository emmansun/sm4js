/** @fileOverview Low-level SM2 implementation.
 *  @author Emman Sun
 */

function bindSM2 (sjcl) {
  if (sjcl.ecc.curves.sm2p256v1) return

  const sbp = sjcl.bn.pseudoMersennePrime
  sjcl.bn.prime.sm2p256v1 = sbp(256, [
    [0, -1],
    [64, 1],
    [96, -1],
    [224, -1]
  ])
  const Curve = sjcl.ecc.curve
  sjcl.ecc.curves.sm2p256v1 = new Curve(
    sjcl.bn.prime.sm2p256v1,
    '0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    -3,
    '0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
    '0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7',
    '0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'
  )

  const BigInt = sjcl.bn
  const sm2Curve = sjcl.ecc.curves.sm2p256v1
  const one = new BigInt(1)
  const defaultUID = sjcl.codec.utf8String.toBits('1234567812345678')

  sjcl.ecc.deserialize = function (key) {
    const types = ['elGamal', 'ecdsa', 'sm2']

    const InvalidError = sjcl.exception.invalid

    if (!key || !key.curve || !sjcl.ecc.curves[key.curve]) {
      throw new InvalidError('invalid serialization')
    }
    if (types.indexOf(key.type) === -1) {
      throw new InvalidError('invalid type')
    }

    const curve = sjcl.ecc.curves[key.curve]

    if (key.secretKey) {
      if (!key.exponent) {
        throw new InvalidError('invalid exponent')
      }
      const exponent = new BigInt(key.exponent)
      const PrivateKey = sjcl.ecc[key.type].secretKey
      return new PrivateKey(curve, exponent)
    } else {
      if (!key.point) {
        throw new InvalidError('invalid point')
      }
      const PublicKey = sjcl.ecc[key.type].publicKey
      const point = curve.fromBits(sjcl.codec.hex.toBits(key.point))
      return new PublicKey(curve, point)
    }
  }

  /** sm2 keys */
  sjcl.ecc.sm2 = {
    /** sm2 publicKey.
     * @constructor
     * @param {point} point the point on the sm2 curve
     */
    publicKey: function (point) {
      this._curve = sm2Curve
      this._curveBitLength = sm2Curve.r.bitLength()
      if (point instanceof Array) {
        this._point = sm2Curve.fromBits(point)
      } else {
        this._point = point
      }

      this.serialize = function () {
        const curveName = sjcl.ecc.curveName(sm2Curve)
        return {
          type: this.getType(),
          secretKey: false,
          point: sjcl.codec.hex.fromBits(this._point.toBits()),
          curve: curveName
        }
      }

      /** get this keys point data
        * @return x and y as bitArrays
        */
      this.get = function () {
        const pointbits = this._point.toBits()
        const len = sjcl.bitArray.bitLength(pointbits)
        const x = sjcl.bitArray.bitSlice(pointbits, 0, len / 2)
        const y = sjcl.bitArray.bitSlice(pointbits, len / 2)
        return { x, y }
      }
    },
    /** sm2 secretKey
     * @constructor
     * @param {bn|bitArray} exponent The private key big number
     */
    secretKey: function (exponent) {
      if (exponent instanceof Array) {
        exponent = sjcl.bn.fromBits(exponent)
      }
      this._curve = sm2Curve
      this._curveBitLength = sm2Curve.r.bitLength()
      this._exponent = exponent

      this.serialize = function () {
        const exponent = this.get()
        const curveName = sjcl.ecc.curveName(sm2Curve)
        return {
          type: this.getType(),
          secretKey: true,
          exponent: sjcl.codec.hex.fromBits(exponent),
          curve: curveName
        }
      }

      /** get this keys exponent data
      * @return {bitArray} exponent
      */
      this.get = function () {
        return this._exponent.toBits()
      }
    },

    /**
     * Generate SM2 key pair
     * @param {bitArray|bn} sec
     * @param {int} paranoia Paranoia for generation (default 6)
     * @param {boolean} checkOrderMinus1 make sure the generated private key is in (0, n-1) or not (default true)
     * @returns
     */
    generateKeys: function (sec, paranoia = 6, checkOrderMinus1 = true) {
      if (sec instanceof Array) {
        sec = sjcl.bn.fromBits(sec)
      }
      sec =
        sec ||
        sjcl.bn.random(
          checkOrderMinus1 ? sm2Curve.r.sub(one) : sm2Curve.r,
          paranoia
        )
      const pub = sm2Curve.G.mult(sec)
      const SM2PublicKey = sjcl.ecc.sm2.publicKey
      const SM2PrivateKey = sjcl.ecc.sm2.secretKey
      return {
        pub: new SM2PublicKey(pub),
        sec: new SM2PrivateKey(sec)
      }
    }
  }

  sjcl.ecc.sm2.secretKey.prototype = {
    /** SM2 sign hash function
     * @param {bitArray} hash hash to sign.
     * @param {int} paranoia paranoia for random number generation
     */
    signHash: function (hash, paranoia = 6, fixedKForTesting) {
      if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
        hash = sjcl.bitArray.clamp(hash, this._curveBitLength)
      }
      const R = this._curve.r
      if (!this._dp1Inv) {
        this._dp1Inv = this._exponent.add(one).inverseMod(R)
      }
      const k = fixedKForTesting || sjcl.bn.random(R.sub(one), paranoia).add(1)
      let r = this._curve.G.mult(k).x.mod(R)
      r = sjcl.bn.fromBits(hash).add(r).mod(R)
      if (r.equals(0)) {
        throw new Error('sign failed, pls retry 1')
      }
      const t = r.add(k).mod(R)
      if (t.equals(0)) {
        throw new Error('sign failed, pls retry 2')
      }
      let s = r.mul(this._exponent)
      s = k.sub(s).mul(this._dp1Inv).mod(R)
      if (s.equals(0)) {
        throw new Error('sign failed, pls retry 3')
      }
      const l = R.bitLength()
      return sjcl.bitArray.concat(r.toBits(l), s.toBits(l))
    },

    /**
     * Decrypt the ciphertext
     * @param {bitArray} ciphertext The ciphertext to decrypt.
     */
    decrypt: function (ciphertext) {
      if (sjcl.bitArray.bitLength(ciphertext) <= (96 * 8)) {
        throw new Error('invalid ciphertext')
      }
      const c1 = sjcl.bitArray.bitSlice(ciphertext, 0, 64 * 8)
      const c3 = sjcl.bitArray.bitSlice(ciphertext, 64 * 8, 96 * 8)
      const c2 = sjcl.bitArray.bitSlice(ciphertext, 96 * 8)
      const msgLen = sjcl.bitArray.bitLength(c2)

      const point = this._curve.fromBits(c1).mult(this._exponent)

      let plaintext = sjcl.misc.kdf(msgLen, point.toBits())
      for (let i = 0; i < plaintext.length; i++) {
        plaintext[i] ^= c2[i]
      }
      plaintext = sjcl.bitArray.clamp(plaintext, msgLen)
      const SM3 = sjcl.hash.sm3
      const hash = new SM3()
      hash.update(point.x.toBits())
      hash.update(plaintext)
      hash.update(point.y.toBits())
      if (!sjcl.bitArray.equal(c3, hash.finalize())) {
        throw new Error('decryption error')
      }
      return plaintext
    },

    /**
     * SM2 Key Exchange, return the implicit signature
     * @param {sjcl.ecc.sm2.secretKey} ephemeralPrivateKey Generated ephemeral private key
     * @param {sjcl.ecc.sm2.publicKey} ephemeralPubKey Generated ephemeral public key
     * @returns {sjcl.bn}
     */
    implicitSig: function (ephemeralPrivateKey, ephemeralPubKey) {
      const R = this._curve.r
      return ephemeralPrivateKey._exponent.mul(ephemeralPubKey._avf()).add(this._exponent).mod(R)
    },

    getType: function () {
      return 'sm2'
    }
  }

  sjcl.ecc.sm2.publicKey.prototype = {
    /**
     * ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
     * @param {String|bitArray} uid The uid used for ZA
     * @return {bitArray} ZA.
     */
    za: function (uid = defaultUID) {
      if (typeof uid === 'string') {
        uid = sjcl.codec.utf8String.toBits(uid)
      }
      const entla = sjcl.bitArray.bitLength(uid)
      const Hash = sjcl.hash.sm3
      const hash = new Hash()
      hash.update([sjcl.bitArray.partial(16, entla)])
      hash.update(uid)
      hash.update(this._curve.a.toBits(this._curveBitLength))
      hash.update(this._curve.b.toBits(this._curveBitLength))
      hash.update(this._curve.G.toBits())
      hash.update(this._point.toBits())
      return hash.finalize()
    },

    _avf: function () {
      const bits = sjcl.bitArray.bitSlice(this._point.x.toBits(), 16 * 8)
      bits[0] &= 0x7fffffff
      bits[0] |= 0x80000000
      return sjcl.bn.fromBits(bits)
    },

    /**
     * SM2 Key Exchange, generate shared key material from shared secret key
     * @param {Number} keyLen The required key length in bits
     * @param {bitArray} za1 For initiator, this is own ZA; otherwise, it's peer's ZA
     * @param {bitArray} za2 For initiator, this is peer's ZA; otherwise, it's own ZA
     * @returns {bitArray} returns the agreed key material
     */
    agreedKey: function (keyLen, za1, za2) {
      const v = sjcl.bitArray.concat(sjcl.bitArray.concat(this._point.toBits(), za1), za2)
      return sjcl.misc.kdf(keyLen, v)
    },

    /**
     * SM2 Key Exchange, calculate the shared secret key
     * @param {sjcl.ecc.sm2.publicKey} ephemeralPub The peer's ephemeral public key
     * @param {sjcl.bn} t The implicitSig result
     * @returns {sjcl.ecc.sm2.publicKey} returns the shared secret key
     */
    sharedSecretKey: function (ephemeralPub, t) {
      const SM2PublicKey = sjcl.ecc.sm2.publicKey
      const x = ephemeralPub._avf()

      const jacPub = ephemeralPub._point.toJac()
      const p2 = jacPub.mult(x, ephemeralPub._point).add(this._point.toJac()).toAffine()
      return new SM2PublicKey(p2.mult(t))
    },

    /**
     * Calculate hash value of the data and uid.
     *
     * @param {String|bitArray} data The data used for hash
     * @param {String|bitArray} uid The uid used for ZA
     * @returns {bitArray} hash value.
     */
    hash: function (data, uid = defaultUID) {
      if (typeof data === 'string') {
        data = sjcl.codec.utf8String.toBits(data)
      }
      const Hash = sjcl.hash.sm3
      const hash = new Hash()
      const za = this.za(uid)
      hash.update(za)
      hash.update(data)
      return hash.finalize()
    },

    /** SM2 verify function
     * @param {String|bitArray} data The data used for hash
     * @param {bitArray} rs signature bitArray.
     * @param {String|bitArray} uid The uid used for ZA
     * @returns {Boolean} verify result
     */
    verify: function (msg, rs, uid) {
      return this.verifyHash(this.hash(msg, uid), rs)
    },

    /**
     * SM2 verify hash function
     * @param {bitArray} hashValue The hash value.
     * @param {bitArray} rs signature bitArray.
     * @returns {Boolean} verify result
     */
    verifyHash: function (hashValue, rs) {
      if (sjcl.bitArray.bitLength(hashValue) > this._curveBitLength) {
        hashValue = sjcl.bitArray.clamp(hashValue, this._curveBitLength)
      }
      const w = sjcl.bitArray
      const R = this._curve.r
      const l = this._curveBitLength
      const r = sjcl.bn.fromBits(w.bitSlice(rs, 0, l))
      const ss = sjcl.bn.fromBits(w.bitSlice(rs, l, 2 * l))
      if (r.equals(0) || ss.equals(0) || r.greaterEquals(R) || ss.greaterEquals(R)) {
        return false
      }
      const t = r.add(ss).mod(R)
      if (t.equals(0)) {
        return false
      }
      const e = sjcl.bn.fromBits(hashValue)
      const r2 = e.add(this._curve.G.mult2(ss, t, this._point).x).mod(R)
      return r.equals(r2)
    },

    /**
     * Encrypt message
     * @param {String|bitArray} msg The data used for encryption
     * @param {int} paranoia paranoia for random number generation
     */
    encrypt: function (msg, paranoia = 6, fixedKForTesting) {
      if (typeof msg === 'string') {
        msg = sjcl.codec.utf8String.toBits(msg)
      }
      const R = this._curve.r
      const msgLen = sjcl.bitArray.bitLength(msg)
      const k = fixedKForTesting || sjcl.bn.random(R.sub(one), paranoia).add(1)
      const c1 = this._curve.G.mult(k)
      const point = this._point.mult(k)

      let ciphertext = sjcl.misc.kdf(msgLen, point.toBits())
      for (let i = 0; i < ciphertext.length; i++) {
        ciphertext[i] ^= msg[i]
      }
      ciphertext = sjcl.bitArray.clamp(ciphertext, msgLen)
      if (sjcl.bitArray.equal(ciphertext, msg)) {
        throw new Error('encryption error, pls try again')
      }
      const SM3 = sjcl.hash.sm3
      const hash = new SM3()
      hash.update(point.x.toBits())
      hash.update(msg)
      hash.update(point.y.toBits())
      return sjcl.bitArray.concat(sjcl.bitArray.concat(c1.toBits(), hash.finalize()), ciphertext)
    },

    getType: function () {
      return 'sm2'
    }
  }
}

module.exports = {
  bindSM2
}
