/** @fileOverview some bytes codec functions.
 *  @author Emman Sun
 */

export default function bindBytesCodecHex (sjcl) {
  if (sjcl.bytescodec) {
    return
  }
  /**
   * Byte array encoders and decoders.
   * @namespace
   */
  sjcl.bytescodec = {}
  /**
   * Hexadecimal
   * @namespace
   */
  sjcl.bytescodec.hex = {
    /** Convert from a byte array to a hex string.
     * @param {Array} arr The byte array to convert.
     */
    fromBytes: function (arr) {
      let res = ''
      for (let i = 0; i < arr.length; i++) {
        let hex = (arr[i] & 0xff).toString(16)
        if (hex.length === 1) {
          hex = '0' + hex
        }
        res += hex
      }
      return res
    },
    /** Convert from a hex string to a byte array.
     * @param {string} hexStr The hex string to convert.
     */
    toBytes: function (hexStr) {
      if (typeof hexStr !== 'string' || hexStr.length % 2 === 1) {
        throw new Error('Invalid hex string')
      }
      const res = []
      for (let i = 0; i < hexStr.length; i += 2) {
        res.push(parseInt(hexStr.substring(i, i + 2), 16))
      }
      return res
    }
  }
}
