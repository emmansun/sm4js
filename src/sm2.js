/** @fileOverview Low-level SM2 implementation.
 *  @author Emman Sun
 */
import { Builder, Parser } from './asn1.js'
import bindBytesCodecHex from './bytescodecHex.js'
import patchBN from './bn_patch.js'

export default function bindSM2 (sjcl) {
  if (sjcl.ecc.curves.sm2p256v1) return
  patchBN(sjcl)
  bindBytesCodecHex(sjcl)

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

  sjcl.ecc.curves.sm2p256v1.oid = '1.2.156.10197.1.301'

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

  /** sm2 keys
   * @namespace
   */
  sjcl.ecc.sm2 = {
    /** sm2 publicKey.
     * @constructor
     * @param {sjcl.BitArray|sjcl.SjclEllipticalPoint} point the point on the sm2 curve
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
          // @ts-ignore
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
     * @param {sjcl.BitArray|sjcl.BigNumber} exponent The private key big number
     */
    secretKey: function (exponent) {
      if (exponent instanceof Array) {
        this._exponent = sjcl.bn.fromBits(exponent)
      } else {
        this._exponent = exponent
      }
      this._curve = sm2Curve
      this._curveBitLength = sm2Curve.r.bitLength()

      this.serialize = function () {
        const exponent = this.get()
        const curveName = sjcl.ecc.curveName(sm2Curve)
        return {
          // @ts-ignore
          type: this.getType(),
          secretKey: true,
          exponent: sjcl.codec.hex.fromBits(exponent),
          curve: curveName
        }
      }

      /** get this keys exponent data
       * @return {sjcl.BitArray} exponent
       */
      this.get = function () {
        return this._exponent.toBits()
      }
    },

    /**
     * Generate SM2 key pair
     * @param {sjcl.BitArray|sjcl.BigNumber} sec
     * @param {number} paranoia Paranoia for generation (default 6)
     * @param {boolean} checkOrderMinus1 make sure the generated private key is in (0, n-1) or not (default true)
     * @returns {Object} the key pair
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
     * @param {sjcl.BitArray} hash hash to sign.
     * @param {number} paranoia paranoia for random number generation
     * @param {string} mode signature mode, default asn1, also can use rs which means r||s
     * @return {string} hex signature string
     */
    signHash: function (hash, paranoia = 6, mode = 'asn1') {
      const l = this._curve.r.bitLength()
      const rs = this._signHashInternal(hash, paranoia)
      if (mode === 'asn1') {
        const builder = new Builder()
        builder.addASN1Sequence((b) => {
          b.addASN1IntBytes(sjcl.codec.bytes.fromBits(rs.r.toBits(l)))
          b.addASN1IntBytes(sjcl.codec.bytes.fromBits(rs.s.toBits(l)))
        })
        return sjcl.bytescodec.hex.fromBytes(builder.bytes())
      }
      return sjcl.codec.hex.fromBits(
        sjcl.bitArray.concat(rs.r.toBits(l), rs.s.toBits(l))
      )
    },

    _signHashInternal: function (hash, paranoia = 6) {
      if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
        hash = sjcl.bitArray.clamp(hash, this._curveBitLength)
      }
      const R = this._curve.r
      if (!this._dp1Inv) {
        this._dp1Inv = this._exponent.add(one).inverseMod(R)
      }
      const k = sjcl.bn.random(R.sub(one), paranoia).add(1)
      let r = this._curve.G.mult(k).x.mod(R)
      r = sjcl.bn.fromBits(hash).add(r).mod(R)
      if (r.equals(0)) {
        throw new Error('sm2: sign failed, pls retry 1')
      }
      const t = r.add(k).mod(R)
      if (t.equals(0)) {
        throw new Error('sm2: sign failed, pls retry 2')
      }
      let s = r.mul(this._exponent)
      s = k.sub(s).mul(this._dp1Inv).mod(R)
      if (s.equals(0)) {
        throw new Error('sm2: sign failed, pls retry 3')
      }
      return { r, s }
    },

    /**
     * Decrypt the ciphertext
     * @param {string} ciphertext The hex ciphertext to decrypt.
     * @returns {sjcl.BitArray} The plaintext.
     * @throws {Error} If the decryption fails.
     */
    decrypt: function (ciphertext) {
      if (typeof ciphertext !== 'string') {
        throw new Error('sm2: invalid ciphertext')
      }
      const SM3 = sjcl.hash.sm3
      const hash = new SM3()
      let c2, c3, point
      if (ciphertext.startsWith('30')) {
        // asn1 type
        const input = new Parser(sjcl.bytescodec.hex.toBytes(ciphertext))
        const xstr = {}
        const ystr = {}
        const c3str = {}
        const c2str = {}
        const inner = {}
        const fail =
          !input.readASN1Sequence(inner) ||
          !input.isEmpty() ||
          !inner.out.readASN1IntBytes(xstr) ||
          !inner.out.readASN1IntBytes(ystr) ||
          !inner.out.readASN1OctetString(c3str) ||
          !inner.out.readASN1OctetString(c2str) ||
          !inner.out.isEmpty()
        if (fail) {
          throw new Error('sm2: decryption error')
        }
        c3 = sjcl.codec.bytes.toBits(c3str.out)
        c2 = sjcl.codec.bytes.toBits(c2str.out)
        const ECCPoint = sjcl.ecc.point
        const CorruptException = sjcl.exception.corrupt
        const BigInt = sjcl.bn
        point = new ECCPoint(
          this._curve,
          BigInt.fromBytes(xstr.out),
          BigInt.fromBytes(ystr.out)
        )
        if (!point.isValid()) {
          throw new CorruptException('sm2: not on the curve!')
        }
        point = point.mult(this._exponent)
      } else {
        if (ciphertext.startsWith('04')) {
          ciphertext = ciphertext.substring(2)
        }
        ciphertext = sjcl.codec.hex.toBits(ciphertext)
        const pointBitLen = this._curveBitLength << 1
        const c2start = pointBitLen + sjcl.bitArray.bitLength(hash._h)
        if (sjcl.bitArray.bitLength(ciphertext) <= c2start) {
          throw new Error('sm2: decryption error')
        }
        point = this._curve
          .fromBits(sjcl.bitArray.bitSlice(ciphertext, 0, pointBitLen))
          .mult(this._exponent)
        c3 = sjcl.bitArray.bitSlice(ciphertext, pointBitLen, c2start)
        c2 = sjcl.bitArray.bitSlice(ciphertext, c2start)
      }
      const msgLen = sjcl.bitArray.bitLength(c2)
      let plaintext = sjcl.misc.kdf(msgLen, point.toBits())
      for (let i = 0; i < plaintext.length; i++) {
        plaintext[i] ^= c2[i]
      }
      plaintext = sjcl.bitArray.clamp(plaintext, msgLen)

      hash.update(point.x.toBits())
      hash.update(plaintext)
      hash.update(point.y.toBits())
      if (!sjcl.bitArray.equal(c3, hash.finalize())) {
        throw new Error('sm2: decryption error')
      }
      return plaintext
    },

    /**
     * SM2 Key Exchange, return the implicit signature
     * @param {sjcl.ecc.sm2.secretKey} ephemeralPrivateKey Generated ephemeral private key
     * @param {sjcl.ecc.sm2.publicKey} ephemeralPubKey Generated ephemeral public key
     * @returns {sjcl.BigNumber} the big number of implicit signature
     */
    implicitSig: function (ephemeralPrivateKey, ephemeralPubKey) {
      const R = this._curve.r
      return ephemeralPrivateKey._exponent
        .mul(ephemeralPubKey._avf())
        .add(this._exponent)
        .mod(R)
    },

    getType: function () {
      return 'sm2'
    }
  }

  sjcl.ecc.sm2.publicKey.prototype = {
    /**
     * ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
     * @param {string|sjcl.BitArray} uid The uid used for ZA
     * @return {sjcl.BitArray} ZA.
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
     * @param {number} keyLen The required key length in bits
     * @param {sjcl.BitArray} za1 For initiator, this is own ZA; otherwise, it's peer's ZA
     * @param {sjcl.BitArray} za2 For initiator, this is peer's ZA; otherwise, it's own ZA
     * @returns {sjcl.BitArray} returns the agreed key material
     */
    agreedKey: function (keyLen, za1, za2) {
      const v = sjcl.bitArray.concat(
        sjcl.bitArray.concat(this._point.toBits(), za1),
        za2
      )
      return sjcl.misc.kdf(keyLen, v)
    },

    /**
     * SM2 Key Exchange, calculate the shared secret key
     * @param {sjcl.ecc.sm2.publicKey} ephemeralPub The peer's ephemeral public key
     * @param {sjcl.BigNumber} t The implicitSig result
     * @returns {sjcl.ecc.sm2.publicKey} returns the shared secret key
     */
    sharedSecretKey: function (ephemeralPub, t) {
      const SM2PublicKey = sjcl.ecc.sm2.publicKey
      const x = ephemeralPub._avf()

      const jacPub = ephemeralPub._point.toJac()
      const p2 = jacPub
        .mult(x, ephemeralPub._point)
        .add(this._point)
        .toAffine()
      return new SM2PublicKey(p2.mult(t))
    },

    /**
     * Calculate hash value of the data and uid.
     *
     * @param {string|sjcl.BitArray} data The data used for hash
     * @param {string|sjcl.BitArray} uid The uid used for ZA
     * @returns {sjcl.BitArray} hash value.
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
     * @param {string|sjcl.BitArray} msg The data used for hash
     * @param {string} signature the hex signature string
     * @param {string} mode the signature mode, default asn1, also can use rs which means r||s.
     * @param {string|sjcl.BitArray} uid The uid used for ZA
     * @returns {boolean} verify result
     */
    verify: function (msg, signature, mode = 'asn1', uid) {
      return this.verifyHash(this.hash(msg, uid), signature, mode)
    },

    /**
     * SM2 verify hash function
     * @param {sjcl.BitArray} hashValue The hash value.
     * @param {string} signature the hex signature string
     * @param {string} mode the signature mode, default asn1, also can use rs which means r||s.
     * @returns {boolean} verify result
     */
    verifyHash: function (hashValue, signature, mode = 'asn1') {
      if (typeof signature !== 'string') {
        return false
      }
      const BigInt = sjcl.bn
      let r, ss
      if (mode === 'asn1') {
        const input = new Parser(sjcl.bytescodec.hex.toBytes(signature))
        const c1 = {}
        const c2 = {}
        const inner = {}
        const fail =
          !input.readASN1Sequence(inner) ||
          !input.isEmpty() ||
          !inner.out.readASN1IntBytes(c1) ||
          !inner.out.readASN1IntBytes(c2) ||
          !inner.out.isEmpty()
        if (fail) {
          return false
        }
        r = BigInt.fromBytes(c1.out)
        ss = BigInt.fromBytes(c2.out)
      } else {
        if (this._curveBitLength !== signature.length << 1) {
          return false
        }
        const l = signature.length / 2
        r = new BigInt(`0x${signature.substring(0, l)}`)
        ss = new BigInt(`0x${signature.substring(l)}`)
      }
      const R = this._curve.r
      if (
        r.equals(0) ||
        ss.equals(0) ||
        r.greaterEquals(R) ||
        ss.greaterEquals(R)
      ) {
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
     * @param {string|sjcl.BitArray} msg The data used for encryption
     * @param {number} paranoia paranoia for random number generation
     * @param {string} outputMode the ciphertext mode, default is asn1, also support c1c3c2
     * @returns {string} hex string of ciphertext
     */
    encrypt: function (msg, paranoia = 6, outputMode = 'asn1') {
      if (typeof msg === 'string') {
        msg = sjcl.codec.utf8String.toBits(msg)
      }
      const R = this._curve.r
      const msgLen = sjcl.bitArray.bitLength(msg)
      const k = sjcl.bn.random(R.sub(one), paranoia).add(1)
      const c1 = this._curve.G.mult(k)
      const point = this._point.mult(k)

      let ciphertext = sjcl.misc.kdf(msgLen, point.toBits())
      for (let i = 0; i < ciphertext.length; i++) {
        // @ts-ignore
        ciphertext[i] ^= msg[i]
      }
      ciphertext = sjcl.bitArray.clamp(ciphertext, msgLen)
      if (sjcl.bitArray.equal(ciphertext, msg)) {
        throw new Error('sm2: encryption error, pls try again')
      }
      const SM3 = sjcl.hash.sm3
      const hash = new SM3()
      hash.update(point.x.toBits())
      hash.update(msg)
      hash.update(point.y.toBits())

      if (outputMode === 'asn1') {
        const builder = new Builder()
        builder.addASN1Sequence((b) => {
          b.addASN1IntBytes(c1.x.toBytes())
          b.addASN1IntBytes(c1.y.toBytes())
          b.addASN1OctetString(sjcl.codec.bytes.fromBits(hash.finalize()))
          b.addASN1OctetString(sjcl.codec.bytes.fromBits(ciphertext))
        })
        return sjcl.bytescodec.hex.fromBytes(builder.bytes())
      }
      return `04${sjcl.codec.hex.fromBits(
        sjcl.bitArray.concat(
          sjcl.bitArray.concat(c1.toBits(), hash.finalize()),
          ciphertext
        )
      )}`
    },

    getType: function () {
      return 'sm2'
    }
  }
}
