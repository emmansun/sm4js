/** @fileOverview Low-level asn1 encoder/decoder implementation.
 * Port from golang golang.org/x/crypto/cryptobyte.
 *  @author Emman Sun
 */

const classConstructed = 0x20
const classContextSpecific = 0x80
const DERBOOLEAN = 0x01
const DERINTEGER = 0x02
const DERBITSTRING = 0x03
const DEROCTETSTRING = 0x04
const DERNULL = 0x05
const DEROBJECTIDENTIFIER = 0x06
const DERSequence = 0x10 | classConstructed

function constructedTag (tag) {
  return tag | classConstructed
}

function contextSpecificTag (tag) {
  return tag | classContextSpecific
}

class Builder {
  constructor (buffer) {
    this.result = buffer || []
    this.offset = 0
  }

  bytes () {
    return this.result.slice(this.offset)
  }

  addByte (byte) {
    this._add([byte & 0xff])
  }

  addBytes (bytes) {
    this._add(bytes)
  }

  /**
   *
   * @param {boolean} v
   */
  addASN1Boolean (v) {
    if (typeof v !== 'boolean') {
      throw new Error('ASN1Boolean must be a boolean')
    }
    this.addASN1(DERBOOLEAN, (builder) => {
      builder.addByte(v ? 0xff : 0x00)
    })
  }

  addASN1NULL () {
    this.addBytes([DERNULL, 0])
  }

  addASN1Sequence (builderContinuation) {
    this.addASN1(DERSequence, (builder) => {
      this.callContinuation(builderContinuation, builder)
    })
  }

  addASN1ExplicitTag (tag, builderContinuation) {
    this.addASN1(contextSpecificTag(constructedTag(tag)), (builder) => {
      this.callContinuation(builderContinuation, builder)
    })
  }

  addASN1OctetString (bytes) {
    this.addASN1(DEROCTETSTRING, (builder) => {
      builder.addBytes(bytes)
    })
  }

  /**
   * addASN1BitString appends a DER-encoded ASN.1 BIT STRING. This does not
   * support BIT STRINGs that are not a whole number of bytes.
   * @param {Array} bytes
   */
  addASN1BitString (bytes) {
    this.addASN1(DERBITSTRING, (builder) => {
      builder.addByte(0)
      builder.addBytes(bytes)
    })
  }

  _addBase128Int (n) {
    let length = 0
    if (n === 0) {
      length = 1
    } else {
      for (let i = n; i > 0; i >>= 7) {
        length++
      }
    }
    for (let i = length - 1; i >= 0; i--) {
      let o = (n >>> (7 * i)) & 0xff
      o &= 0x7f
      if (i !== 0) {
        o |= 0x80
      }
      this.addByte(o)
    }
  }

  addASN1ObjectIdentifier (oidString) {
    if (typeof oidString !== 'string' || !/^[0-9.]+$/.test(oidString)) {
      throw new Error(`invalid OID: ${oidString}`)
    }
    const oids = oidString.split('.').map(Number)
    if (oids.length < 2 || oids[0] > 2 || (oids[0] <= 1 && oids[1] >= 40)) {
      throw new Error(`invalid OID: ${oidString}`)
    }
    for (let i = 0; i < oids.length; i++) {
      if (oids[i] < 0) {
        throw new Error(`invalid OID: ${oidString}`)
      }
    }
    this.addASN1(DEROBJECTIDENTIFIER, (builder) => {
      builder._addBase128Int(oids[0] * 40 + oids[1])
      for (let i = 2; i < oids.length; i++) {
        builder._addBase128Int(oids[i])
      }
    })
  }

  /**
   * addASN1IntBytes encodes in ASN.1 a positive integer represented as
   * a big-endian byte slice with zero or more leading zeroes.
   * @param {Array} bytes the byte array of integer
   */
  addASN1IntBytes (bytes) {
    for (; bytes.length > 0 && bytes[0] === 0;) {
      bytes.splice(0, 1)
    }
    if (bytes.length === 0) {
      throw new Error('invalid integer')
    }
    this.addASN1(DERINTEGER, (builder) => {
      if (bytes[0] & 0x80) {
        bytes = [0].concat(bytes)
      }
      builder.addBytes(bytes)
    })
  }

  _add (bytes) {
    if (this.child) {
      throw new Error('attempted write while child is pending')
    }
    if (this.result.length + bytes.length < bytes.length) {
      throw new Error(' length overflow')
    }
    this.result.push(...bytes)
  }

  callContinuation (builderContinuation, builder) {
    const targetRoot = this._getRoot()
    if (!targetRoot.inContinuation) {
      targetRoot.inContinuation = true
    }
    try {
      builderContinuation(builder)
    } finally {
      targetRoot.inContinuation = false
    }
  }

  flushChild () {
    if (!this.child) {
      return
    }
    this.child.flushChild()
    const child = this.child
    this.child = null

    let length = child.result.length - child.pendingLenLen - child.offset
    if (length < 0) {
      throw new Error('internal error')
    }

    if (child.pendingIsASN1) {
      if (child.pendingLenLen !== 1) {
        throw new Error('internal error')
      }
      let lenLen, lenByte
      if (length > 0x00fffffffe) {
        throw new Error('pending ASN.1 child too long')
      } else if (length >= 0x1000000) {
        lenLen = 5
        lenByte = 0x80 | 0x04
      } else if (length >= 0x10000) {
        lenLen = 4
        lenByte = 0x80 | 0x03
      } else if (length >= 0x100) {
        lenLen = 3
        lenByte = 0x80 | 0x02
      } else if (length >= 0x80) {
        lenLen = 2
        lenByte = 0x80 | 0x01
      } else {
        lenLen = 1
        lenByte = length
        length = 0
      }
      child.result[child.offset] = lenByte
      child.offset++
      child.pendingLenLen = lenLen - 1
    }

    let l = length
    for (let i = child.pendingLenLen - 1; i >= 0; i--) {
      child.result.splice(child.offset, 0, l & 0xff)
      l = l >>> 8
    }
    if (l !== 0) {
      throw new Error(
        `pending child length ${length} exceeds ${child.pendingLenLen}-byte length profix`
      )
    }
    this.result = child.result
  }

  _getRoot () {
    return this.root || this
  }

  addLengthPrefixed (lenLen, isASN1, builderContinuation) {
    const offset = this.result.length

    for (let i = 0; i < lenLen; i++) {
      this.addByte(0)
    }
    const targetRoot = this._getRoot()
    if (typeof targetRoot.inContinuation === 'undefined') {
      targetRoot.inContinuation = false
    }
    this.child = new Builder()
    this.child.root = this.root || this
    this.child.result = this.result
    this.child.offset = offset
    this.child.pendingLenLen = lenLen
    this.child.pendingIsASN1 = isASN1

    this.callContinuation(builderContinuation, this.child)
    this.flushChild()
    if (this.child) {
      throw new Error('internal error')
    }
  }

  addASN1 (tag, builderContinuation) {
    if ((tag & 0x1f) === 0x1f) {
      throw new Error(
        'high-tag number identifier octects not supported: 0x' +
          tag.toString(16)
      )
    }
    this.addByte(tag)
    this.addLengthPrefixed(1, true, builderContinuation)
  }
}

class Parser {
  constructor (bytes) {
    this.bytes = bytes
  }

  length () {
    return this.bytes ? this.bytes.length : 0
  }

  peekASN1Tag (tag) {
    if (this.isEmpty()) {
      return false
    }
    return this.bytes[0] === tag
  }

  skipASN1NULL () {
    return this.skipASN1(DERNULL)
  }

  skipASN1 (tag) {
    return this.readASN1({}, tag)
  }

  readASN1Sequence (output) {
    return this.readASN1(output, DERSequence)
  }

  readASN1IntBytes (output) {
    return this.readASN1Bytes(output, DERINTEGER)
  }

  readASN1OctetString (output) {
    return this.readASN1Bytes(output, DEROCTETSTRING)
  }

  _readBase128Int (output) {
    let ret = 0
    const len = this.length()
    for (let i = 0; i < len; i++) {
      if (i === 5) {
        return false
      }
      // Avoid overflowing int on a 32-bit platform.
      // We don't want different behavior based on the architecture.
      if (ret >= 1 << (31 - 7)) {
        return false
      }
      ret <<= 7
      const b = (this._read(1))[0]
      // ITU-T X.690, section 8.19.2:
      // The subidentifier shall be encoded in the fewest possible octets,
      // that is, the leading octet of the subidentifier shall not have the value 0x80.
      if (i === 0 && b === 0x80) {
        return false
      }
      ret |= b & 0x7f
      if ((b & 0x80) === 0) {
        output.out = ret
        return true
      }
    }
    return false
  }

  readASN1ObjectIdentifier (output) {
    const ois = {}
    if (!this.readASN1(ois, DEROBJECTIDENTIFIER) || ois.out.length() === 0) {
      return false
    }

    const v = {}
    const components = []
    if (!ois.out._readBase128Int(v)) {
      return false
    }
    if (v.out < 80) {
      components.push(parseInt(v.out / 40))
      components.push(v.out % 40)
    } else {
      components.push(2)
      components.push(v.out - 80)
    }

    for (; ois.out.length() > 0;) {
      if (!ois.out._readBase128Int(v)) {
        return false
      }
      components.push(v.out)
    }
    output.out = components.join('.')
    return true
  }

  readASN1BitString (output) {
    if (
      !this.readASN1(output, DERBITSTRING) ||
      output.out.isEmpty() ||
      (output.out.length() * 8) / 8 !== output.out.length()
    ) {
      return false
    }
    const paddingBits = output.out.bytes[0]
    const bytes = output.out.bytes.slice(1)
    if (
      paddingBits > 7 ||
      (bytes.length === 0 && paddingBits !== 0) ||
      (bytes.length > 0 &&
        (bytes[bytes.length - 1] & (1 << (paddingBits - 1))) !== 0)
    ) {
      return false
    }
    output.out = {
      bytes,
      bitLength: bytes.length * 8 - paddingBits
    }
    return true
  }

  readASN1Boolean (output) {
    if (!this.readASN1(output, DERBOOLEAN) || output.out.length() !== 1) {
      return false
    }

    output.out = output.out.bytes[0] === 0xff
    return true
  }

  readASN1Bytes (output, tag) {
    const result = this.readASN1(output, tag)
    if (!result) {
      return false
    }
    output.out = output.out.bytes
    return true
  }

  readASN1 (output, tag) {
    const result = this.readAnyASN1(output)
    if (!result || tag !== output.tag) {
      return false
    }
    return true
  }

  /**
   * readOptionalASN1ObjectIdentifier attempts to read an optional OBJECT IDENTIFIER
   * explicitly tagged with tag into out and advances. If no element with a matching
   * tag is present, it sets ouput.present to false.
   * @param {Object} output
   * @param {Number} tag
   * @returns {Boolean} It reports whether the read was successful.
   */
  readOptionalASN1ObjectIdentifier (output, tag) {
    const child = {}
    if (!this.readOptionalASN1(child, contextSpecificTag(constructedTag(tag)))) {
      return false
    }
    output.present = child.present
    if (child.present) {
      const oid = {}
      if (!child.out.readASN1ObjectIdentifier(oid) || !child.out.isEmpty()) {
        return false
      }
      output.out = oid.out
    }
    return true
  }

  /**
   * readOptionalASN1OctetString attempts to read an optional ASN.1 OCTET STRING
   * explicitly tagged with tag into out and advances. If no element with a matching
   * tag is present, it sets ouput.present to false.
   * @param {Object} output
   * @param {Number} tag
   * @returns {Boolean} It reports whether the read was successful.
   */
  readOptionalASN1OctetString (output, tag) {
    const child = {}
    if (!this.readOptionalASN1(child, contextSpecificTag(constructedTag(tag)))) {
      return false
    }
    output.present = child.present
    if (child.present) {
      const octString = {}
      if (!child.out.readASN1OctetString(octString) || !child.out.isEmpty()) {
        return false
      }
      output.out = octString.out
    }
    return true
  }

  /**
   * readOptionalASN1BitString attempts to read an optional ASN.1 BIT STRING
   * explicitly tagged with tag into out and advances. If no element with a matching
   * tag is present, it sets ouput.present to false.
   * @param {Object} output
   * @param {Number} tag
   * @returns {Boolean} It reports whether the read was successful.
   */
  readOptionalASN1BitString (output, tag) {
    const child = {}
    if (!this.readOptionalASN1(child, contextSpecificTag(constructedTag(tag)))) {
      return false
    }
    output.present = child.present
    if (child.present) {
      const bitString = {}
      if (!child.out.readASN1BitString(bitString) || !child.out.isEmpty()) {
        return false
      }
      output.out = bitString.out
    }
    return true
  }

  readOptionalASN1 (output, tag) {
    const present = this.peekASN1Tag(tag)
    if (present) {
      const ret = this.readASN1(output, tag)
      output.present = present
      return ret
    } else {
      output.present = false
    }
    return true
  }

  skipOptionalASN1 (tag) {
    if (!this.peekASN1Tag(tag)) {
      return true
    }
    return this.skipASN1(tag)
  }

  readAnyASN1 (output) {
    return this._readASN1(output, true)
  }

  readAnyASN1Element (output) {
    return this._readASN1(output, false)
  }

  _readASN1 (output, skipHeader = false) {
    if (!(output instanceof Object) || Object.keys(output).length > 0) {
      throw new Error('please provide an empty object as output')
    }
    if (!this.bytes || this.bytes.length < 2) {
      return false
    }
    const tag = this.bytes[0]
    const lenBytes = this.bytes[1]
    if ((tag & 0x1f) === 0x1f) {
      // ITU-T X.690 section 8.1.2
      //
      // An identifier octet with a tag part of 0x1f indicates a high-tag-number
      // form identifier with two or more octets. We only support tags less than
      // 31 (i.e. low-tag-number form, single octet identifier).
      return false
    }

    let length = 0
    let headerLen = 0
    // ITU-T X.690 section 8.1.3
    //
    // Bit 8 of the first length byte indicates whether the length is short- or
    // long-form.
    if ((lenBytes & 0x80) === 0) {
      // Short-form length (section 8.1.3.4), encoded in bits 1-7.
      length = lenBytes + 2
      headerLen = 2
    } else {
      // Long-form length (section 8.1.3.5). Bits 1-7 encode the number of octets
      // used to encode the length.
      const lenLen = lenBytes & 0x7f
      if (lenLen === 0 || lenLen > 4 || this.length < lenLen + 2) {
        return false
      }
      const lenBytesParser = new Parser(this.bytes.slice(2, lenLen + 2))
      const len = lenBytesParser._readUnsigned(lenLen)
      if (!len.success) {
        return false
      }
      const len32 = len.value
      // ITU-T X.690 section 10.1 (DER length forms) requires encoding the length
      // with the minimum number of octets.
      if (len32 < 128) {
        // Length should have used short-form encoding.
        return false
      }
      if (len32 >>> ((lenLen - 1) * 8) === 0) {
        // Leading octet is 0. Length should have been at least one byte shorter.
        return false
      }
      headerLen = lenLen + 2
      if (headerLen + len32 < len32) {
        // Overflow.
        return false
      }
      length = headerLen + len32
    }

    if (length < 0) {
      return false
    }
    const v = this.readBytes(length)
    if (!v.success) {
      return false
    }
    const out = new Parser(v.value)
    if (skipHeader && !out._skip(headerLen)) {
      throw new Error('internal error')
    }

    output.tag = tag
    output.out = out
    return true
  }

  readUint8 () {
    const v = this._read(1)
    if (v === undefined) {
      return { success: false }
    }
    return { success: true, value: v[0] & 0xff }
  }

  readUint6 () {
    const v = this._read(2)
    if (v === undefined) {
      return { success: false }
    }
    return { success: true, value: ((v[0] << 8) | v[1]) >>> 0 }
  }

  readUint24 () {
    const v = this._read(3)
    if (v === undefined) {
      return { success: false }
    }
    return { success: true, value: ((v[0] << 16) | (v[1] << 8) | v[2]) >>> 0 }
  }

  readUint32 () {
    const v = this._read(4)
    if (v === undefined) {
      return { success: false }
    }
    return {
      success: true,
      value: ((v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3]) >>> 0
    }
  }

  _readUnsigned (length) {
    const v = this._read(length)
    if (v === undefined) {
      return { success: false }
    }
    let value = 0
    for (let i = 0; i < length; i++) {
      value = (value << 8) | v[i]
    }
    return { success: true, value: value >>> 0 }
  }

  _readLengthPrefixed (lenLen) {
    let v = this._read(lenLen)
    if (v === undefined) {
      return { success: false }
    }
    let length = 0
    for (let i = 0; i < lenLen; i++) {
      length = (length << 8) | v[i]
    }
    v = this._read(length)
    if (v === undefined) {
      return { success: false }
    }
    return { success: true, value: new Parser(v) }
  }

  readBytes (n) {
    const v = this._read(n)
    if (v === undefined) {
      return { success: false }
    }
    return { success: true, value: v }
  }

  isEmpty () {
    return this.length() === 0
  }

  _read (n) {
    if (this.bytes.length < n || n < 0) {
      return
    }
    const result = this.bytes.slice(0, n)
    this.bytes = this.bytes.slice(n)
    return result
  }

  _skip (n) {
    return this._read(n) !== undefined
  }
}

module.exports = {
  constructedTag,
  contextSpecificTag,
  Builder,
  Parser
}
