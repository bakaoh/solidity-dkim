var dns = require("dns");
var crypto = require( 'crypto' );

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

function processBody( message, method ) {

    method = method || 'simple'
  
    if( method !== 'simple' && method !== 'relaxed' ) {
      throw new Error( 'Canonicalization method "' + method + '" not supported' )
    }
  
    // @see https://tools.ietf.org/html/rfc6376#section-3.4.3
    if( method === 'simple' ) {
      return message.toString( 'ascii' )
        .replace( /(\r\n)+$/m, '' ) + '\r\n'
    }
  
    // @see https://tools.ietf.org/html/rfc6376#section-3.4.4
    if( method === 'relaxed' ) {
      return message.toString( 'ascii' )
        // Ignore all whitespace at the end of lines.
        .replace( /[\x20\x09]+(?=\r\n)/g, '' )
        // Reduce all sequences of WSP within a line to a single SP
        .replace( /[\x20\x09]+/g, ' ' )
        // Ignore all empty lines at the end of the message body.
        .replace( /(\r\n)+$/, '\r\n' )
    }
  
  }

var digest = crypto.createHash( "sha256" )
      .update( processBody(body, 'relaxed') )
      .digest();
console.log("digest", digest.toString('hex'));