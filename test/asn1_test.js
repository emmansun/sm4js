const test = require('tape')
const { Builder, Parser } = require('../src/asn1')

/**
 * Convert byte array or Uint8Array to hex string
 * @param {Uint8Array|Array} bytes byte array or Uint8Array
 * @returns {string} hex string
 */
function toHex (bytes) {
  const isUint8Array = bytes instanceof Uint8Array
  if (!isUint8Array) {
    bytes = Uint8Array.from(bytes)
  }
  return Array.prototype.map
    .call(bytes, function (n) {
      return (n < 16 ? '0' : '') + n.toString(16)
    })
    .join('')
}

/**
 * Convert a hex string to a byte array.
 */
function hexToBytes (hexStr) {
  if (typeof hexStr !== 'string' || hexStr.length % 2 === 1) {
    throw new Error('Invalid hex string')
  }
  const bytes = []
  for (let i = 0; i < hexStr.length; i += 2) {
    bytes.push(0xff & parseInt(hexStr.substring(i, i + 2), 16))
  }
  return bytes
}

test('ASN1 builder basic', function (t) {
  const builder = new Builder()
  builder.addASN1Sequence((b) => {
    b.addASN1OctetString([1, 2, 3])
    b.addASN1OctetString([4, 5, 6])
    b.addASN1IntBytes([0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    b.addASN1IntBytes([0x00, 0xf1, 0x02, 0x03, 0x04, 0x05, 0x06])
    b.addASN1BitString([7, 8, 9])
    b.addASN1Boolean(true)
    b.addASN1Boolean(false)
    b.addASN1NULL()
    b.addASN1Sequence((b1) => {
      b1.addASN1IntBytes([0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
      b1.addASN1IntBytes([0x00, 0xf1, 0x02, 0x03, 0x04, 0x05, 0x06])
    })
  })
  t.equal(
    toHex(builder.bytes()),
    '303c040301020304030405060206010203040506020700f102030405060304000708090101ff010100050030110206010203040506020700f10203040506'
  )
  t.end()
})

test('ASN1 parser basic', function (t) {
  const input = new Parser(hexToBytes('303c040301020304030405060206010203040506020700f102030405060304000708090101ff010100050030110206010203040506020700f10203040506'))
  const c1 = {}
  const c2 = {}
  const c3 = {}
  const c4 = {}
  const c5 = {}
  const c6 = {}
  const c7 = {}
  const c8 = {}
  const c9 = {}
  const inner = {}
  const input1 = {}
  const fail = !input.readASN1Sequence(inner) ||
               !input.isEmpty() ||
               !inner.out.readASN1OctetString(c1) ||
               !inner.out.readASN1OctetString(c2) ||
               !inner.out.readASN1IntBytes(c3) ||
               !inner.out.readASN1IntBytes(c4) ||
               !inner.out.readASN1BitString(c5) ||
               !inner.out.readASN1Boolean(c6) ||
               !inner.out.readASN1Boolean(c7) ||
               !inner.out.skipASN1NULL() ||
               !inner.out.readASN1Sequence(input1) ||
               !inner.out.isEmpty() ||
               !input1.out.readASN1IntBytes(c8) ||
               !input1.out.readASN1IntBytes(c9) ||
               !input1.out.isEmpty()


  t.notOk(fail)
  t.deepEqual(c1.out, [1, 2, 3])
  t.deepEqual(c2.out, [4, 5, 6])
  t.deepEqual(c3.out, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
  t.deepEqual(c4.out, [0x00, 0xf1, 0x02, 0x03, 0x04, 0x05, 0x06])
  t.deepEqual(c5.out.bytes, [7, 8, 9])
  t.equal(c5.out.bitLength, 24)
  t.ok(c6.out)
  t.notOk(c7.out)
  t.deepEqual(c8.out, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
  t.deepEqual(c9.out, [0x00, 0xf1, 0x02, 0x03, 0x04, 0x05, 0x06])  
  t.end()
})
