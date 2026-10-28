import bindKDF from './kdf.js'
import bindSM3 from './sm3.js'
import bindBytesCodecHex from './bytescodecHex.js'
import * as asn1 from './asn1.js'
import bindSM4 from './sm4.js'
import bindSM2 from './sm2.js'
import bindPKCS8 from './pkcs8.js'
import bindPKIX from './pkix.js'

function initialize (sjcl) {
  bindBytesCodecHex(sjcl)
  bindSM2(sjcl)
  bindSM4(sjcl)
  bindPKIX(sjcl)
  bindPKCS8(sjcl)
  return sjcl
}

export {
  initialize,
  bindKDF,
  bindSM3,
  bindBytesCodecHex,
  asn1,
  bindSM4,
  bindSM2,
  bindPKCS8,
  bindPKIX
}
