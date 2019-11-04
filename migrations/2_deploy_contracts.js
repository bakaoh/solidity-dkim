const DKIM = artifacts.require('DKIM');

module.exports = async function (deployer) {
  await deployer.deploy(DKIM);
};