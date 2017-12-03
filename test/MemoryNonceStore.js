const MemoryNonceStore = require('../src/memory-nonce-store');
const shared = require('./shared');

describe('MemoryNonceStore', () =>
  shared.shouldBehaveLikeNonce(() => {
    return new MemoryNonceStore();
  }));
