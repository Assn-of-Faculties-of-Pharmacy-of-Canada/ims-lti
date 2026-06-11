const HMAC_SHA1 = require('./hmac-sha1');

// OAuth 1.0a HMAC-SHA256 signing (oauth_signature_method: 'HMAC-SHA256').
// The signature base string is built exactly as for HMAC-SHA1 — only the
// HMAC digest algorithm differs. Brightspace (D2L) signs LTI 1.1 launches
// with HMAC-SHA256 by default since ~20.24 releases.
class HMAC_SHA256 extends HMAC_SHA1 {
  constructor (withDetailsCallback) {
    super(withDetailsCallback);
    this.algorithm = 'sha256';
  }
  toString() {
    return 'HMAC_SHA256';
  }
}

module.exports = HMAC_SHA256;
