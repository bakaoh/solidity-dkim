const fs = require("fs");
const path = require("path");
const { BN } = require('@openzeppelin/test-helpers');
const DKIM = artifacts.require("DKIM");

const STATE_SUCCESS = new BN(0);

contract("DKIM", function([creator]) {
  before(async function() {
    this.dkim = await DKIM.new({ from: creator });
  });

  it("verify raw Gmail", async function() {
    let message = fs.readFileSync(path.join(__dirname, "data", "test-gmail.eml"));
    let verification = await this.dkim.verify(message.toString());
    verification.state.should.be.bignumber.equal(STATE_SUCCESS);
    verification.rs.should.be.equal("gmail.com");
  });

  it("verify raw YahooMail", async function() {
    let message = fs.readFileSync(path.join(__dirname, "data", "test-yahoo.eml"));
    let verification = await this.dkim.verify(message.toString());
    verification.state.should.be.bignumber.equal(STATE_SUCCESS);
    verification.rs.should.be.equal("yahoo.com");
  });

  it("verify raw ProtonMail", async function() {
    let message = fs.readFileSync(path.join(__dirname, "data", "test-proton.eml"));
    let verification = await this.dkim.verify(message.toString());
    verification.state.should.be.bignumber.equal(STATE_SUCCESS);
    verification.rs.should.be.equal("protonmail.com");
  });
});
