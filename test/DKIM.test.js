const fs = require("fs");
const path = require("path");

const DKIM = artifacts.require("DKIM");

contract("DKIM", function([creator]) {
  before(async function() {
    this.dkim = await DKIM.new({ from: creator });
  });

  it("verify raw Gmail", async function() {
    let message = fs.readFileSync(path.join(__dirname, "data", "test-gmail.eml"));
    let v = await this.dkim.verify(message.toString());
    v.should.be.equal(true);
  });

  it("verify raw YahooMail", async function() {
    let message = fs.readFileSync(path.join(__dirname, "data", "test-yahoo.eml"));
    let v = await this.dkim.verify(message.toString());
    v.should.be.equal(true);
  });

  it("verify raw ProtonMail", async function() {
    let message = fs.readFileSync(path.join(__dirname, "data", "test-proton.eml"));
    let v = await this.dkim.verify(message.toString());
    v.should.be.equal(true);
  });
});
