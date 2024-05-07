/** @fileOverview parse pkcs8 implementation.
 *  @author Emman Sun
 */
const { Builder, Parser } = require('./asn1')

const oidEccPublicKey = '1.2.840.10045.2.1'
function bindPKCS8 (sjcl) {
  if (sjcl.pkcs8) return
  require('./pkix').bindPKIX(sjcl)
  sjcl.pkcs8 = {
    marshalPKCS8ECPrivateKey: function (key, includePublicKey = true) {
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

    parsePKCS8ECPrivateKey: function (keyDer) {
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
            !inner.out.readASN1IntBytes(version) ||
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
    }
  }
}

module.exports = {
  bindPKCS8
}
