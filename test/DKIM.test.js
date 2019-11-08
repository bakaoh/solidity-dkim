const { BN, expectEvent } = require("@openzeppelin/test-helpers");
const DKIM = artifacts.require("DKIM");

var fs = require("fs");
var path = require("path");

var message = fs.readFileSync(path.join(__dirname, "data", "gmail-raw.txt"));

contract("DKIM", function([_, registryFunder, creator, operator]) {
  beforeEach(async function() {
    this.dkim = await DKIM.new({ from: creator });
  });

  it("return len", async function() {
    // let x = await this.dkim.decode(
    //   "iPc3RHh9oXL6+dvuPM0hYt1vdj6U4hN83BFxhumWsSXnFDFmbSG4OtXHPF823HoZAA" +
    //     "4MbFQu5VgfvAQ+FmnKyfON2WdJrAYicyslVXlcA6l0UKSGIH/0NHSqi/kX+4KEKaClY7" +
    //     "jZkXZZ8EIl5IUBdRRUWSsySFOtrQ/9IeAb6YM="
    // );
    // console.log(JSON.stringify(x));
    // x.should.be.equal("228");

    // await this.dkim.set(
    //   "0x9157daff5eb845df246f5e315144ff112ac4f7caa555ad9185620b0a2e5ffb7b14492417c804f23e9d1ce90b5a6ee5719465a85e1ad8ff9b558353d4eb14ae3022f2ef2b25fae5e78fc37c0db1431524fefa6da783b62950694939e623caab7873a110cff9bb848f43e58afcfcb14de54af4f1fd3939e2472c6b9514f174e955",
    //   "0x10001",
    // );
    let x = await this.dkim.getLen.call(message.toString());
    console.log(JSON.stringify(x));
    x.should.be.equal("228");

    // let x = (await this.dkim.verify(
    //   '0x9157daff5eb845df246f5e315144ff112ac4f7caa555ad9185620b0a2e5ffb7b14492417c804f23e9d1ce90b5a6ee5719465a85e1ad8ff9b558353d4eb14ae3022f2ef2b25fae5e78fc37c0db1431524fefa6da783b62950694939e623caab7873a110cff9bb848f43e58afcfcb14de54af4f1fd3939e2472c6b9514f174e955',
    //   '0x10001',
    //   '0x6d696d652d76657273696f6e3a312e300d0a66726f6d3a4d617263656c6c696e204e7368696d6979696d616e61203c6d61727340667573656d616368696e65732e636f6d3e0d0a646174653a53756e2c203232204f637420323031372031393a34353a3030202b303534350d0a6d6573736167652d69643a3c43414f77704d692d63714d67595a34427146655032514153645335346f7151366469466646516e2b6556415668484543347977406d61696c2e676d61696c2e636f6d3e0d0a7375626a6563743a5465737420656d61696c0d0a746f3a4d6172732d737072696e74203c6e6d617263656c6c696e3240676d61696c2e636f6d3e0d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20633d72656c617865642f72656c617865643b20643d667573656d616368696e65732e636f6d3b20733d676f6f676c653b20683d6d696d652d76657273696f6e3a66726f6d3a646174653a6d6573736167652d69643a7375626a6563743a746f3b2062683d3977324838756366463177332b5a7175396770506348675455394748506a77374532485948486c5a456b773d3b20623d',
    //   '0x88f73744787da172faf9dbee3ccd2162dd6f763e94e2137cdc117186e996b125e71431666d21b83ad5c73c5f36dc7a19000e0c6c542ee5581fbc043e1669cac9f38dd96749ac0622732b2555795c03a97450a486207ff43474aa8bf917fb828429a0a563b8d9917659f04225e48501751454592b324853adad0ffd21e01be983'
    // ));
    // console.log(JSON.stringify(x));
    // x.should.be.equal("228");
  });

  // it('has a symbol', async function () {
  //   (await this.token.symbol()).should.equal('WETC');
  // });

  // it('increase total supply and balance when deposit', async function () {
  //   const value = new BN(10000000);
  //   const deposit = await this.token.deposit({ from: creator, value });

  //   const totalSupply = await this.token.totalSupply();
  //   const creatorBalance = await this.token.balanceOf(creator);

  //   totalSupply.should.be.bignumber.equal(value);
  //   creatorBalance.should.be.bignumber.equal(value);

  //   await expectEvent(deposit, 'Deposit', {
  //     _owner: creator,
  //     _value: value,
  //   });
  // });

  // it('decrease total supply and balance when withdraw', async function () {
  //   const value = new BN(3000000);
  //   await this.token.deposit({ from: creator, value: new BN(10000000) });
  //   const withdraw = await this.token.withdraw(value, { from: creator });

  //   const totalSupply = await this.token.totalSupply();
  //   const creatorBalance = await this.token.balanceOf(creator);

  //   totalSupply.should.be.bignumber.equal(new BN(7000000));
  //   creatorBalance.should.be.bignumber.equal(new BN(7000000));

  //   await expectEvent(withdraw, 'Withdrawal', {
  //     _owner: creator,
  //     _value: value,
  //   });
  // });
});
