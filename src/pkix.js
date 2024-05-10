/** @fileOverview parse PKIX public key and SEC1 private key implementation.
 *  @author Emman Sun
 */
const { Builder, Parser } = require('./asn1')

const oidEccPublicKey = '1.2.840.10045.2.1'
function bindPKIX (sjcl) {
  if (sjcl.pkix) return
  require('./sm2').bindSM2(sjcl)
  if (!sjcl.ecc.curves.c256.oid) {
    sjcl.ecc.curves.c256.oid = '1.2.840.10045.3.1.7'
    sjcl.ecc.curves.c224.oid = '1.3.132.0.33'
    sjcl.ecc.curves.c384.oid = '1.3.132.0.34'
    sjcl.ecc.curves.c521.oid = '1.3.132.0.35'
    sjcl.ecc.curves.k256.oid = '1.3.132.0.10'
  }
  /**
   * @namespace
   * @description
   * <p>
   * PKIX EC public key handling & RFC 5915/SEC1 EC private key handling functions.
   * </p>
   */
  sjcl.pkix = {
  /**
   * parsePKIXPublicKey parses an EC public key from DER-encoded byte array
   * @param {Array} keyDer DER-encoded byte array
   * @returns {sjcl.ecc.sm2.publicKey|sjcl.ecc.ecdsa.publicKey}
   */
    parsePKIXPublicKey: function (keyDer) {
      const input = new Parser(keyDer)
      const inner = {}
      const algInner = {}
      const alg = {}
      const bitString = {}
      if (
        !input.readASN1Sequence(inner) ||
        !input.isEmpty() ||
        !inner.out.readASN1Sequence(algInner) ||
        !inner.out.readASN1BitString(bitString) ||
        !inner.out.isEmpty() ||
        !algInner.out.readASN1ObjectIdentifier(alg)

      ) {
        throw new Error('pkix: invalid PKIX public key asn1')
      }
      if (alg.out !== oidEccPublicKey) {
        throw new Error(`pkix: unsupported alg <${alg.out}>`)
      }
      if (bitString.out.bytes.length !== 65 && bitString.out.bytes[0] !== 4) {
        throw new Error('pkix: unsupported point format')
      }
      const curveOID = {}
      if (!algInner.out.readASN1ObjectIdentifier(curveOID) || !algInner.out.isEmpty()) {
        throw new Error('pkix: invalid PKIX public key asn1')
      }
      let publicKey
      for (const c in sjcl.ecc.curves) {
        const curcurve = sjcl.ecc.curves[c]
        if (curcurve.oid === curveOID.out) {
          if (c === 'sm2p256v1') {
            const KeyClazz = sjcl.ecc.sm2.publicKey
            publicKey = new KeyClazz(sjcl.codec.bytes.toBits(bitString.out.bytes.slice(1)))
          } else {
            const KeyClazz = sjcl.ecc.ecdsa.publicKey
            publicKey = new KeyClazz(curcurve, sjcl.codec.bytes.toBits(bitString.out.bytes.slice(1)))
          }
        }
      }
      if (!publicKey) {
        throw new Error(`pkix: unsupported curve <${curveOID.out}>`)
      }
      return publicKey
    },

    /**
     * marshalPKIXPublicKey marshals the given public key to the PKIX DER-encoded byte array
     * @param {sjcl.ecc.sm2.publicKey|sjcl.ecc.ecdsa.publicKey|sjcl.ecc.elGamal.publicKey} publicKey the public key object
     * @returns {Array} the DER-encoded byte array
     */
    marshalPKIXPublicKey: function (publicKey) {
      if (!(publicKey instanceof sjcl.ecc.sm2.publicKey) && !(publicKey instanceof sjcl.ecc.ecdsa.publicKey) && !(publicKey instanceof sjcl.ecc.elGamal.publicKey)) {
        throw new Error('pkix: invalid/unsupported public key')
      }
      const serialized = publicKey.serialize()
      const curveOID = sjcl.ecc.curves[serialized.curve].oid
      if (!curveOID) {
        throw new Error('pkix: unsupported curve')
      }
      const builder = new Builder()
      builder.addASN1Sequence((b) => {
        b.addASN1Sequence((b1) => {
          b1.addASN1ObjectIdentifier(oidEccPublicKey)
          b1.addASN1ObjectIdentifier(curveOID)
        })
        b.addASN1BitString(sjcl.bytescodec.hex.toBytes(`04${serialized.point}`))
      })
      return builder.bytes()
    },

    /**
     * parseECPrivateKey reads an EC private key from ASN.1 DER-encoded byte array.
     * Referneces: RFC 5915 & SEC1 - http://www.secg.org/sec1-v2.pdf
     * @param {Array} keyDer DER-encoded byte array
     * @param {string} [curveOID] the OID of the EC curve, if it is provided then use this instead of the OID that may exist in the EC private key structure.
     * @returns {sjcl.ecc.sm2.secretKey|sjcl.ecc.ecdsa.secretKey} the private key object
     */
    parseECPrivateKey: function (keyDer, curveOID) {
      const input = new Parser(keyDer)
      const inner = {}
      const version = {}
      const keyStr = {}
      const oid = {}
      const pkStr = {}
      if (
        !input.readASN1Sequence(inner) ||
          !input.isEmpty() ||
          !inner.out.readASN1Signed(version) ||
          !inner.out.readASN1OctetString(keyStr) ||
          !inner.out.readOptionalASN1ObjectIdentifier(oid, 0) ||
          !inner.out.readOptionalASN1BitString(pkStr, 1) ||
          !inner.out.isEmpty()) {
        throw new Error('sec1: invalid EC private key asn1')
      }
      if (version.out !== 1) {
        throw new Error('sec1: invalid EC private key version')
      }

      if (!oid.present && !curveOID) {
        throw new Error('sec1: without EC private key oid')
      }

      curveOID = curveOID || oid.out
      let prvKey
      for (const c in sjcl.ecc.curves) {
        const curcurve = sjcl.ecc.curves[c]
        if (curcurve.oid === curveOID) {
          if (c === 'sm2p256v1') {
            const KeyClazz = sjcl.ecc.sm2.secretKey
            prvKey = new KeyClazz(sjcl.bn.fromBytes(keyStr.out))
          } else {
            const KeyClazz = sjcl.ecc.ecdsa.secretKey
            prvKey = new KeyClazz(curcurve, sjcl.bn.fromBytes(keyStr.out))
          }
        }
      }
      if (!prvKey) {
        throw new Error(`sec1: unsupported curve <${curveOID}>`)
      }
      return prvKey
    },

    /**
     * marshalECPrivateKey marshals an EC private key into ASN.1, DER format
     * @param {sjcl.ecc.sm2.secretKey|sjcl.ecc.ecdsa.secretKey|sjcl.ecc.elGamal.secretKey} key the private key object
     * @param {boolean} [includePublicKey=true] if marshals the public key together, default value is true.
     * @returns {Array} byte array
     */
    marshalECPrivateKey: function (key, includePublicKey = true) {
      if (!(key instanceof sjcl.ecc.sm2.secretKey) && !(key instanceof sjcl.ecc.ecdsa.secretKey) && !(key instanceof sjcl.ecc.elGamal.secretKey)) {
        throw new Error('sec1: invalid/unsupported private key')
      }
      const serialized = key.serialize()
      const curve = sjcl.ecc.curves[serialized.curve]
      const curveOID = curve.oid
      if (!curveOID) {
        throw new Error('sec1: unsupported curve')
      }
      const d = sjcl.bn.fromBits(key.get())
      const point = includePublicKey ? curve.G.mult(d) : null

      const builder = new Builder()
      builder.addASN1Sequence((b) => {
        b.addASN1IntBytes([1])
        b.addASN1OctetString(sjcl.bytescodec.hex.toBytes(serialized.exponent))
        b.addASN1ExplicitTag(0, (b1) => {
          b1.addASN1ObjectIdentifier(curveOID)
        })
        if (includePublicKey) {
          b.addASN1ExplicitTag(1, (b1) => {
            b1.addASN1BitString(sjcl.bytescodec.hex.toBytes(`04${sjcl.codec.hex.fromBits(point.toBits())}`))
          })
        }
      })
      return builder.bytes()
    }
  }
}

module.exports = {
  bindPKIX
}
