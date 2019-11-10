const fs = require("fs");
const path = require("path");
const { BN } = require('@openzeppelin/test-helpers');
const DKIM = artifacts.require("DKIM");

const rawFile = process.env.RAW_EMAIL;
if (rawFile) {
  contract("DKIM", function([creator]) {
    before(async function() {
      this.dkim = await DKIM.new({ from: creator });
    });
  
    it(`verify ${rawFile}`, async function() {
      let message = fs.readFileSync(path.resolve(__dirname, "../", rawFile));
      let verification = await this.dkim.verify(message.toString());
      let successCount = verification.success.toString();
      console.log("Total success:", successCount);
      console.log(successCount == "0" ? "Last fail" : "Last domain:", verification.domain);
    });
  });

  return;
}

contract("DKIM", function([creator]) {
  before(async function() {
    this.dkim = await DKIM.new({ from: creator });
  });

  it("verify raw Gmail", async function() {
    let message = fs.readFileSync(path.join(__dirname, "data", "test-gmail.eml"));
    let verification = await this.dkim.verify(message.toString());
    verification.success.should.be.bignumber.equal(new BN(1));
    verification.domain.should.be.equal("gmail.com");
  });

  it("verify raw YahooMail", async function() {
    let message = fs.readFileSync(path.join(__dirname, "data", "test-yahoo.eml"));
    let verification = await this.dkim.verify(message.toString());
    verification.success.should.be.bignumber.equal(new BN(1));
    verification.domain.should.be.equal("yahoo.com");
  });

  it("verify raw ProtonMail", async function() {
    let message = fs.readFileSync(path.join(__dirname, "data", "test-proton.eml"));
    let verification = await this.dkim.verify(message.toString());
    verification.success.should.be.bignumber.equal(new BN(1));
    verification.domain.should.be.equal("protonmail.com");
  });

  it("verify Gmail with utf-8, whitespace sequences", async function() {
    let message = fs.readFileSync(path.join(__dirname, "data", "test-utf8.eml"));
    let verification = await this.dkim.verify(message.toString());
    verification.success.should.be.bignumber.equal(new BN(1));
    verification.domain.should.be.equal("gmail.com");
  });

});
