# Solidity DKIM

A Solidity library to verify [DKIM signatures](https://tools.ietf.org/html/rfc6376):

- Support `rsa-sha1` and `rsa-sha256` signature algorithms
- Implement both canonicalization algorithms (`simple`, `relaxed`)
- Support the signature schemes by Gmail, Yahoo, ProtonMail, Outlook
- Gas cost under 3 million gas

The contract receive raw email as input and return number of success verifications along with the last success domain or the last fail status (if there's no success).

## Getting Started

Clone and install dependencies

```
$ git clone https://github.com/bakaoh/solidity-dkim
$ cd solidity-dkim
$ npm install
```

Start [ganache](https://www.trufflesuite.com/docs/ganache/quickstart)

Download email from your inbox

![download](/Screenshot.png)

Test with raw email

```
$ RAW_EMAIL=<path to your email file> npm run test
# example
$ RAW_EMAIL=test/data/gmail-raw.txt npm run test
```

## 3rd party Smart Contracts

- [https://github.com/Arachnid/solidity-stringutils](https://github.com/Arachnid/solidity-stringutils)
- [https://github.com/ensdomains/buffer](https://github.com/ensdomains/buffer)
- [https://github.com/ensdomains/solsha1](https://github.com/ensdomains/solsha1)

## Troubleshoot

**no header boundary found**: The raw email must be in "network normal" format (text is ASCII encoded, lines are separated with CRLF characters, etc.). The downloaded files should work just fine, but if you copy the email content to your text editor, you may need to replace `\n` with `\r\n`, e.g. `input = input.replace(new RegExp("\n", 'g'), "\r\n")`

**dns query error**: The library is using hardcode `_domainkey` records and your email domain is not in the current list. In the future, we'll need a proper oracle that can read the `_domainkey` record for any arbitrary domain.