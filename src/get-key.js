var dns = require( 'dns' )
var DKIM = require( './dkim' )

/**
 * Retrieve a domain key
 * @memberOf DKIM
 * @todo DNS seems to FORMERR on unregistered / expired domains,
 * which maybe should be a TEMPFAIL (?)
 * @todo make this `public_key = dkim_find_key(q_val, d_val, s_val)`,
 * where `*_val` are the signature's attribute values
 * @todo Throw error if the public key is not a Buffer
 * @param {String} domain
 * @param {String} [selector]
 * @param {Function} callback
 */
function getKey( domain, selector, callback ) {

  if( typeof selector === 'function' ) {
    callback = selector
    selector = null
  } else {
    domain = selector + '._domainkey.' + domain
  }

  dns.resolve( domain, 'TXT', function( error, records ) {

    var key = null

    if( error == null ) {

      var keys = records.map(( record ) => {
        try { return DKIM.Key.parse( record.join( '' ) ) }
        catch( e ) { return null }
      }).filter(( value ) => {
        return value != null
      })

      if( !keys.length ) {
        error = new Error( 'No key for signature' )
        error.code = DKIM.PERMFAIL
        return void callback( error, key )
      }

      if( keys.length > 1 ) {
        error = new Error( 'Ambiguous key selection' )
        error.code = DKIM.TEMPFAIL
        return void callback( error, key )
      }

      key = keys.shift()

      // If the result returned from the query does not adhere to the
      // format defined in this specification, the Verifier MUST ignore
      // the key record and return PERMFAIL (key syntax error).
      if( key == null || !Buffer.isBuffer( key.key ) ) {
        error = new Error( 'No public key found' )
        error.code = DKIM.PERMFAIL
      }

    } else {
      switch( error.code ) {
        // If the query for the public key fails because the corresponding
        // key record does not exist, the Verifier MUST immediately return
        // PERMFAIL (no key for signature).
        case dns.NOTFOUND:
        case dns.NODATA:
        case dns.FORMERR:
        case dns.REFUSED:
          error.code = DKIM.PERMFAIL
          break
        // If the query for the public key fails to respond, the Verifier
        // MAY seek a later verification attempt by returning TEMPFAIL
        // (key unavailable).
        default:
          error.code = DKIM.TEMPFAIL
          break
      }
    }

    callback( error, key )

  })

}

module.exports = getKey