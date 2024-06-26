/** @fileOverview Low-level kdf implementation.
 *  @author Emman Sun
 */

export default function bindKDF (sjcl) {
  /** KDF with the specified hash function.
   * @param {number} keyBitLength The output key length, in bits.
   * @param {string|Array} z The z for KDF.
   * @param {Object} [Hash=sjcl.hash.sm3] The hash function to use.
   * @return {Array} derived key.
   */
  sjcl.misc.kdf = sjcl.misc.kdf || function (keyBitLength, z, Hash) {
    Hash = Hash || sjcl.hash.sm3
    if (typeof z === 'string') {
      z = sjcl.codec.utf8String.toBits(z)
    }
    let count = 1
    const basehash = new Hash()
    basehash.update(z)
    let hash = new Hash(basehash)
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
      hash = new Hash(basehash)
      hash.update([count])
      ret = sjcl.bitArray.concat(ret, hash.finalize())
    }
    return sjcl.bitArray.clamp(ret, keyBitLength)
  }
}
