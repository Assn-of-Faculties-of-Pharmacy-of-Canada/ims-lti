const extensions = require('./extensions');

// Export the main object
module.exports = {
  // Version of the library this is
  version: require('../package.json').version,

  // Provider and Consumer classes
  Provider: require('./provider'),
  Consumer: require('./consumer'),
  OutcomeService: extensions.Outcomes.OutcomeService,
  Errors: require('./errors'),

  // Signature methods. Provider defaults to HMAC_SHA1; pass an instance of
  // HMAC_SHA256 as the 4th Provider argument to verify launches signed with
  // oauth_signature_method 'HMAC-SHA256' (e.g. D2L Brightspace).
  HMAC_SHA1: require('./hmac-sha1'),
  HMAC_SHA256: require('./hmac-sha256'),

  Stores: {
    RedisStore: require('./redis-nonce-store'),
    MemoryStore: require('./memory-nonce-store'),
    NonceStore: require('./nonce-store'),
  },

  Extensions: extensions,

  // Which version of the LTI standard are accepted
  supported_versions: ['LTI-1p0'],
};
