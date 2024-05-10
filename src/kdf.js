/** @fileOverview Low-level kdf implementation.
 *  @author Emman Sun
 */

function bindKDF (sjcl) {
  /** KDF with the specified hash function.
   * @param {number} keyBitLength The output key length, in bits.
   * @param {string|bitArray} z The z for KDF.
   * @param {Object} [Hash=sjcl.hash.sm3] The hash function to use.
   * @return {bitArray} derived key.
   */
  sjcl.misc.kdf = sjcl.misc.kdf || function (keyBitLength, z, Hash) {
    Hash = Hash || sjcl.hash.sm3
    if (typeof z === 'string') {
      z = sjcl.codec.utf8String.toBits(z)
    }
    let count = 1
    const hash = new Hash()
    hash.update(z)
    hash.update([count])
    let ret = hash.finalize()
    const hashLen = sjcl.bitArray.bitLength(ret)
    const loops = Math.ceil(keyBitLength / hashLen)
    const InvalidError = sjcl.exception.invalid
    if (loops > 255) {
      throw new InvalidError('key bit length is too large for kdf')
    }
    for (let i = 1; i < loops; i++) {
      count++
      hash.update(z)
      hash.update([count])
      ret = sjcl.bitArray.concat(ret, hash.finalize())
    }
    return sjcl.bitArray.clamp(ret, keyBitLength)
  }
}

module.exports = {
  bindKDF
}
