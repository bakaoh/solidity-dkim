var dns = require("dns");
var crypto = require("crypto");

// let domain = "google._domainkey.fusemachines.com";
// dns.resolve( domain, 'TXT', function( error, records ) {
//     console.log(error, records);
// });

var fs = require("fs");
var message = fs.readFileSync("test/data/gmail-raw.txt");

var boundary = message.indexOf("\r\n\r\n");
var header = message.toString("utf8", 0, boundary);
var body = message.slice(boundary + 4);

header = header.replace(/\x20\x09/g, " ");

var results = [];
var signatures = [];

function filterSignatureHeaders(headers, signatureHeader) {
  return headers.filter(function(header) {
    return (
      header === signatureHeader ||
      !/^(DKIM-Signature|X-Google-DKIM-Signature)/i.test(header)
    );
  });
}

header.split(/\r\n(?=[^\x20\x09]|$)/g).forEach(function(h, i, headers) {
  // ISSUE: executing line below, may result in including a different 'DKIM-Signature' header
  // signatures.push( headers.slice( i ) )
  // FIX: after slicing, remove any included 'DKIM-Signature' header that differ from "oneHeader"
  if (/^(DKIM-Signature|X-Google-DKIM-Signature)/i.test(h)) {
    var sigHeaders = filterSignatureHeaders(headers.slice(i), h);
    signatures.push(sigHeaders);
  }
});

// console.log(signatures)

function processBody(message, method) {
  method = method || "simple";

  if (method !== "simple" && method !== "relaxed") {
    throw new Error('Canonicalization method "' + method + '" not supported');
  }

  // @see https://tools.ietf.org/html/rfc6376#section-3.4.3
  if (method === "simple") {
    return message.toString("ascii").replace(/(\r\n)+$/m, "") + "\r\n";
  }

  // @see https://tools.ietf.org/html/rfc6376#section-3.4.4
  if (method === "relaxed") {
    return (
      message
        .toString("ascii")
        // Ignore all whitespace at the end of lines.
        .replace(/[\x20\x09]+(?=\r\n)/g, "")
        // Reduce all sequences of WSP within a line to a single SP
        .replace(/[\x20\x09]+/g, " ")
        // Ignore all empty lines at the end of the message body.
        .replace(/(\r\n)+$/, "\r\n")
    );
  }
}

function processHeader(headers, signHeaders, method) {
  if (typeof signHeaders === "string") {
    method = signHeaders;
    signHeaders = null;
  }

  method = method || "simple";

  if (method !== "simple" && method !== "relaxed") {
    throw new Error('Canonicalization method "' + method + '" not supported');
  }

  if (signHeaders != null) {
    // Clone this array so that newely added headers don't show up outsite this "processHeader" function
    // See https://tools.ietf.org/html/rfc5322#section-3.6
    signHeaders = signHeaders.slice();
    signHeaders.push("DKIM-Signature");
    signHeaders.push("X-Google-DKIM-Signature");

    signHeaders = signHeaders.map(function(header) {
      return header.toLowerCase();
    });

    // Remove duplicates
    // signHeaders = signHeaders.reduce((ac, val) => [...ac, ...ac.includes(val) ? [] : [val]], [])
    signHeaders = signHeaders.reduce(function(ac, val) {
      if (ac.indexOf(val) < 0) {
        ac.push(val);
      }
      return ac;
    }, []);

    // Sort elements of headers array using the "signHeaders" order
    var indexedHeaders = headers.map(function(header) {
      var key = header
        .slice(0, header.indexOf(":"))
        .trim()
        .toLowerCase();
      var idx = signHeaders.indexOf(key);
      return { idx, header };
    });

    headers = indexedHeaders
      .filter(function(h) {
        return h.idx > -1;
      })
      .sort(function(h1, h2) {
        return h1.idx - h2.idx;
      })
      .map(function(h) {
        return h.header;
      });

    // headers = headers.filter( function( header ) {
    //   var key = header.slice( 0, header.indexOf( ':' ) ).trim().toLowerCase()
    //   return signHeaders.indexOf( key ) !== -1
    // })
  }

  if (method === "simple") {
    return headers.join("\r\n");
  }

  // TODO: Something's not right here...
  // relaxed signatures still don't verify
  if (method === "relaxed") {
    return headers
      .map(function(line) {
        var lines = {};
        var colon = line.indexOf(":");
        var value = line.slice(colon);

        // Convert all header field names to lowercase
        var key = line.slice(0, colon).toLowerCase();

        // Unfold all header field continuation lines
        value = value.replace(/\r\n(?=[\x20\x09])/g, "");
        // Convert all sequences of one or more WSP characters to a single SP
        value = value.replace(/[\x20\x09]+/g, " ");
        // Devare all WSP characters at the end of each unfolded header field
        value = value.replace(/[\x20\x09]+$/g, "");

        // Remove signature value for "dkim-signature" header
        if (/^(dkim-signature|x-google-dkim-signature)/i.test(key)) {
          value = value.replace(/ b=([^;]*)/, " b=");
        }

        if (key === "x-google-dkim-signature") {
          key = key.replace("x-google-dkim-signature", "dkim-signature");
        }

        // Remove any WSP characters remaining before and after the colon
        return (key + value).replace(/[\x20\x09]*[:][\x20\x09]*/, ":");
      })
      .join("\r\n");
  }
}

var digest = crypto
  .createHash("sha256")
  .update(processBody(body, "relaxed"))
  .digest();
// console.log("digest", digest.toString("hex"));

var processedHeader = processHeader(
  signatures[0],
  ["mime-version", "from", "date", "message-id", "subject", "to"],
  "relaxed"
);
console.log(processedHeader);

var pubKey =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRV9r/XrhF3yRvXjFRRP8RKsT3yqVVrZGFYgsKLl/7exRJJBfIBPI+nRzpC1pu5XGUZaheGtj/m1WDU9TrFK4wIvLvKyX65eePw3wNsUMVJP76baeDtilQaUk55iPKq3hzoRDP+buEj0Plivz8sU3lSvTx/Tk54kcsa5UU8XTpVQIDAQAB" +
  "\n-----END PUBLIC KEY-----";

var verified = crypto
  .createVerify("RSA-SHA256")
  .update(processedHeader)
  .verify(
    pubKey,
    Buffer.from("iPc3RHh9oXL6+dvuPM0hYt1vdj6U4hN83BFxhumWsSXnFDFmbSG4OtXHPF823HoZAA" +
      "4MbFQu5VgfvAQ+FmnKyfON2WdJrAYicyslVXlcA6l0UKSGIH/0NHSqi/kX+4KEKaClY7" +
      "jZkXZZ8EIl5IUBdRRUWSsySFOtrQ/9IeAb6YM=",'base64')
  );

console.log("verified", verified);
