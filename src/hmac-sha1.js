const crypto = require('crypto');
const url = require('url');
const utils = require('./utils');

// Cleaning invloves:
//   stripping the oauth_signature from the params
//   encoding the values ( yes this double encodes them )
//   sorting the key/value pairs
//   joining them with &
//   encoding them again
//
// Returns a string representing the request
const _clean_request_body = function(body, query) {
  const out = [];

  const encodeParam = (key, val) => `${key}=${utils.special_encode(val)}`;

  const cleanParams = function(params) {
    if (typeof params !== 'object') {
      return;
    }

    for (let key in params) {
      const vals = params[key];
      if (key === 'oauth_signature') {
        continue;
      }
      if (Array.isArray(vals) === true) {
        for (let val of vals) {
          out.push(encodeParam(key, val));
        }
      } else {
        out.push(encodeParam(key, vals));
      }
    }
  };

  cleanParams(body);
  cleanParams(query);

  return utils.special_encode(out.sort().join('&'));
};

class HMAC_SHA1 {
  constructor (withDetailsCallback) {
    this.withDetailsCallback = typeof withDetailsCallback === "function" ? withDetailsCallback : undefined;
  }
  toString() {
    return 'HMAC_SHA1';
  }

  build_signature_raw(
    req_url,
    parsed_url,
    method,
    params,
    consumer_secret,
    token
  ) {
    const sig = [
      method.toUpperCase(),
      utils.special_encode(req_url),
      _clean_request_body(params, parsed_url.query),
    ];

    return this.sign_string(sig.join('&'), consumer_secret, token);
  }

  build_signature(req, body, consumer_secret, token) {
    const hapiRawReq = req.raw && req.raw.req;
    if (hapiRawReq) {
      req = hapiRawReq;
    }

    let originalUrl = req.originalUrl || req.url;
    let { protocol } = req;

    // Since canvas includes query parameters in the body we can omit the query string
    if (body.tool_consumer_info_product_family_code === 'canvas') {
      originalUrl = url.parse(originalUrl).pathname;
    }

    // When an incoming https request is proxied: the protocol (scheme) is changed to http
    // In this case allow the proxy to send in the true scheme via the standard x-forwarded-proto header
    // In a nginx configuration the line to add is:
    //       proxy_set_header X-Forwarded-Proto $scheme;
    if (req.headers['x-forwarded-proto'] ==='https') {
      protocol = 'https'
    }

    if (protocol === undefined) {
      const { encrypted } = req.connection;
      protocol = (encrypted && 'https') || 'http';
    }

    const parsedUrl = url.parse(originalUrl, true);
    const hitUrl = protocol + '://' + req.headers.host + parsedUrl.pathname;
    const signature =  this.build_signature_raw(
      hitUrl,
      parsedUrl,
      req.method,
      body,
      consumer_secret,
      token
    );

    if (this.withDetailsCallback) {
      let details = {};
      details.class='HMAC_SHA1';
      details.method='build_signature';
      details.hapiRawReq = hapiRawReq;
      details.originalUrl = req.originalUrl;
      details.url = req.url;
      details.familyCode = body.tool_consumer_info_product_family_code;
      details.headersXForwardedProto = req.headers['x-forwarded-proto'];
      details.encrypted = req.connection.encrypted;
      details.protocol = protocol;
      details.hitUrl = hitUrl;
      details.method = req.method;
      details.token = token;
      details.consumer_secret = consumer_secret;
      details.signature = signature;
      this.withDetailsCallback(details)
    }
    return signature
  }

  sign_string(str, key, token) {
    key = `${key}&`;
    if (token) {
      key += token;
    }
    if (this.withDetailsCallback) {
      let details = {};
      details.class='HMAC_SHA1';
      details.method='sign_string';
      details.key = key;
      details.str = str;
      this.withDetailsCallback(details)
    }

    return crypto
      .createHmac('sha1', key)
      .update(str)
      .digest('base64');
  }
}

module.exports = HMAC_SHA1;
