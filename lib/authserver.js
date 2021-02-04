'use strict';

const bns = require('bns');
const {AuthServer, dnssec, constants, tlsa} = bns;
const {types} = constants;
const {keyFlags} = dnssec;
const {KSK, ZONE} = keyFlags;
const {encoding} = require('bcrypto');
const {pem} = encoding;
const Path = require('path');
const fs = require('fs');

class AuthNS {
  constructor(options) {
    if (options.logger)
      this.logger = options.logger.context('authns');

    this.domain = options.domain;
    this.host = options.host;
    // this.zskkey = options.zskkey;
    // this.zskpriv = options.zskpriv;
    // this.kskkey = options.kskkey;
    // this.kskpriv = options.kskpriv;
    this.port = options.test ? 53530 : 53;

    this.server = new AuthServer({
      tcp: true,
      edns: true,
      // dnssec: true
    });
  }

  init() {
    this.server.setOrigin(this.domain);
    const zone = this.server.zone;

    // Create SOA
    zone.fromString(
      `${this.domain} 21600 IN SOA ns.${this.domain} email.${this.domain} ` +
      parseInt(Date.now() / 1000) + ' 86400 7200 604800 300'
    );

    // Create self-referencing NS and glue
    zone.fromString(
      `${this.domain} 21600 IN NS ns.${this.domain}`
    );
    zone.fromString(
      `ns.${this.domain} 21600 IN A ${this.host}`
    );

    // Create A records for TLD and all subdomains
    zone.fromString(
      `${this.domain} 21600 IN A ${this.host}`
    );
    zone.fromString(
      `*.${this.domain} 21600 IN A ${this.host}`
    );
  }

  open() {
    // Answer questions and log
    this.server.on('query', (req, res, rinfo) => {
      this.logger.debug(`${rinfo.address} req: ${req.question}`);
    });

    // Start
    this.server.bind(this.port, this.host);
    this.logger.debug(
      `Authoritative Nameserver opened for domain ${this.domain}`
    );
  }
}

/*
 * Expose
 */

module.exports = AuthNS;
