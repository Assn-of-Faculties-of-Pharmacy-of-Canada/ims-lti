const lti = require('../');
const should = require('should');

describe('LTI', function() {
  before(() => {
    this.lti = lti;
  });

  describe('.Provider', () => {
    it('should exist', () => {
      should.exist(this.lti.Provider);
    });

    it('should be an instance of Provider', () => {
      this.lti.Provider.should.be.an.instanceOf(Object);
      this.lti.Provider.should.equal(require('../src/provider'));
    });
  });

  describe('.Consumer', () => {
    it('should exist', () => {
      should.exist(this.lti.Consumer);
    });

    it('should be an instance of Consumer', () => {
      this.lti.Consumer.should.be.an.instanceOf(Object);
      this.lti.Consumer.should.equal(require('../src/consumer'));
    });
  });

  describe('.Stores', () => {
    it('should not be empty', () => {
      should.exist(this.lti.Stores);
    });
    it('should include NonceStore', () => {
      should.exist(this.lti.Stores.NonceStore);
    });
  });
});
