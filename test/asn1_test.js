const test = require('tape')
const sjcl = require('sjcl-with-all')
require('../src/bytescodecHex').bindBytesCodecHex(sjcl)
const { Builder, Parser } = require('../src/asn1')

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
    sjcl.bytescodec.hex.fromBytes(builder.bytes()),
    '303c040301020304030405060206010203040506020700f102030405060304000708090101ff010100050030110206010203040506020700f10203040506'
  )
  t.end()
})

test('ASN1 explicit tag builder', function (t) {
  const builder = new Builder()
  builder.addASN1Sequence((b) => {
    b.addASN1ExplicitTag(0, (b1) => {
      b1.addASN1OctetString([1, 2, 3])
    })
    b.addASN1ExplicitTag(1, (b1) => {
      b1.addASN1BitString([7, 8, 9])
    })
    b.addASN1ExplicitTag(2, (b1) => {
      b1.addASN1ObjectIdentifier('2.5.4.6')
    })
  })
  t.equal(
    sjcl.bytescodec.hex.fromBytes(builder.bytes()),
    '3016a0050403010203a106030400070809a2050603550406'
  )
  t.end()
})

test('ASN1 builder OID', function (t) {
  const builder = new Builder()
  builder.addASN1Sequence((b) => {
    b.addASN1ObjectIdentifier('2.5.4.6')
    b.addASN1ObjectIdentifier('1.2.840.10045.3.1.7')
  })
  t.equal(
    sjcl.bytescodec.hex.fromBytes(builder.bytes()),
    '300f060355040606082a8648ce3d030107'
  )
  t.end()
})

test('ASN1 parser OID', function (t) {
  let input = new Parser(sjcl.bytescodec.hex.toBytes('300f060355040606082a8648ce3d030107'))
  const c1 = {}
  const c2 = {}
  const inner = {}
  const fail = !input.readASN1Sequence(inner) ||
               !input.isEmpty() ||
               !inner.out.readASN1ObjectIdentifier(c1) ||
               !inner.out.readASN1ObjectIdentifier(c2) ||
               !inner.out.isEmpty()
  t.notOk(fail)
  t.equal(c1.out, '2.5.4.6')
  t.equal(c2.out, '1.2.840.10045.3.1.7')
  // leading 0x80 octet
  input = new Parser([6, 3, 85, 0x80, 0x02])
  t.notOk(input.readASN1ObjectIdentifier({}))
  // 2**31
  input = new Parser([6, 7, 0x55, 0x02, 0x88, 0x80, 0x80, 0x80, 0x00])
  t.notOk(input.readASN1ObjectIdentifier({}))
  // 2**31-1
  input = new Parser([6, 7, 0x55, 0x02, 0x87, 0xff, 0xff, 0xff, 0x7f])
  const c3 = {}
  t.ok(input.readASN1ObjectIdentifier(c3))
  t.equal(c3.out, '2.5.2.2147483647')
  t.end()
})

test('ASN1 explicit tag parser', function (t) {
  const input = new Parser(sjcl.bytescodec.hex.toBytes('3016a0050403010203a106030400070809a2050603550406'))
  const c1 = {}
  const c2 = {}
  const c3 = {}
  const inner = {}
  const fail = !input.readASN1Sequence(inner) ||
               !input.isEmpty() ||
               !inner.out.readOptionalASN1OctetString(c1, 0) ||
               !inner.out.readOptionalASN1BitString(c2, 1) ||
               !inner.out.readOptionalASN1ObjectIdentifier(c3, 2) ||
              !inner.out.isEmpty()
  t.notOk(fail)
  t.ok(c1.present)
  t.deepEqual(c1.out, [1, 2, 3])
  t.ok(c2.present)
  t.deepEqual(c2.out.bytes, [7, 8, 9])
  t.ok(c3.present)
  t.equal(c3.out, '2.5.4.6')
  t.end()
})

test('ASN1 explicit tag parser other cases', function (t) {
  // empty
  let input = new Parser()
  t.ok(input.readOptionalASN1OctetString({}, 0))

  // invalid
  let output = {}
  input = new Parser([0xa1, 3, 0x4, 2, 1])
  t.notOk(input.readOptionalASN1OctetString(output, 1))
  t.ok(output.present)

  // missing
  output = {}
  input = new Parser([0xa1, 3, 0x4, 1, 1])
  t.ok(input.readOptionalASN1OctetString(output, 0))
  t.notOk(output.present)

  // present
  output = {}
  input = new Parser([0xa1, 3, 0x4, 1, 1])
  t.ok(input.readOptionalASN1OctetString(output, 1))
  t.ok(output.present)

  t.end()
})

test('ASN1 parser basic', function (t) {
  const input = new Parser(sjcl.bytescodec.hex.toBytes('303c040301020304030405060206010203040506020700f102030405060304000708090101ff010100050030110206010203040506020700f10203040506'))
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
