const test = require('tape')
const sjcl = require('sjcl-with-all')
require('../src/bn_patch').patchBN(sjcl)
require('../src/bytescodecHex').bindBytesCodecHex(sjcl)
const BigInt = sjcl.bn

test('bn toBytes basic', function (t) {
  const b1 = new BigInt(
    '0x6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85'
  )
  t.deepEqual(
    sjcl.bytescodec.hex.fromBytes(b1.toBytes()),
    '6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85'
  )
  const b2 = new BigInt(
    '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
  )
  t.deepEqual(
    sjcl.bytescodec.hex.fromBytes(b2.toBytes()),
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
  )
  const b3 = new BigInt(
    'ffffffffffffffffffffffffffffffff'
  )
  t.deepEqual(
    sjcl.bytescodec.hex.fromBytes(b3.toBytes(32)),
    '00000000000000000000000000000000ffffffffffffffffffffffffffffffff'
  )
  const b4 = new BigInt(
    '00000000000000000000000000000000ffffffffffffffffffffffffffffffff'
  )
  t.deepEqual(
    sjcl.bytescodec.hex.fromBytes(b4.toBytes(16)),
    'ffffffffffffffffffffffffffffffff'
  )
  t.end()
})
