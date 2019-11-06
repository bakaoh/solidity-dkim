pragma solidity ^0.4.14;

import "./strings.sol";

contract RSASHA256Algorithm {
    using BytesUtils for *;

    function verify(bytes key, bytes data, bytes sig) external view returns (bool) {
        bytes memory exponent;
        bytes memory modulus;

        uint16 exponentLen = uint16(key.readUint8(4));
        if (exponentLen != 0) {
            exponent = key.substring(5, exponentLen);
            modulus = key.substring(exponentLen + 5, key.length - exponentLen - 5);
        } else {
            exponentLen = key.readUint16(5);
            exponent = key.substring(7, exponentLen);
            modulus = key.substring(exponentLen + 7, key.length - exponentLen - 7);
        }

        // Recover the message from the signature
        bool ok;
        bytes memory result;
        (ok, result) = RSAVerify.rsarecover(modulus, exponent, sig);

        // Verify it ends with the hash of our data
        return ok && sha256(data) == result.readBytes32(result.length - 32);
    }
}

contract DKIM {
    using strings for *;

    mapping(bytes32 => strings.slice) public headers;
    strings.slice public body;

    function DKIM() public {
    }

    function getKey(strings.slice selector, strings.slice domain) private pure returns (
        strings.slice
    ) {
        return 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRV9r/XrhF3yRvXjFRRP8RKsT3yqVVrZGFYgsKLl/7exRJJBfIBPI+nRzpC1pu5XGUZaheGtj/m1WDU9TrFK4wIvLvKyX65eePw3wNsUMVJP76baeDtilQaUk55iPKq3hzoRDP+buEj0Plivz8sU3lSvTx/Tk54kcsa5UU8XTpVQIDAQAB'.toSlice();
    }

    function parseSignature(strings.slice signature) private pure returns (
        strings.slice domain,
        strings.slice selector,
        strings.slice canonicalHeader,
        strings.slice canonicalBody,
        strings.slice hashAlgorithm,
        strings.slice verifyAlgorithm,
        strings.slice signatureHeaders
    ) {
        signature.split(": ".toSlice());
        var sdelim = ";".toSlice();
        var scount = signature.count(sdelim) + 1;

        for (uint j = 0; j < scount; j++) {
            var spart = signature.split(sdelim);
            var tagname = spart.split("=".toSlice());
            if (tagname.endsWith("d".toSlice())) {
                domain = spart;
            } else if (tagname.endsWith("s".toSlice())) {
                selector = spart;
            } else if (tagname.endsWith("c".toSlice())) {
                canonicalHeader = spart.split("/".toSlice());
                canonicalBody = spart;
            } else if (tagname.endsWith("a".toSlice())) {
                verifyAlgorithm = spart.split("-".toSlice());
                hashAlgorithm = spart;
            } else if (tagname.endsWith("bh".toSlice())) {
            } else if (tagname.endsWith("h".toSlice())) {
                signatureHeaders = spart;
            }
        }
    }

    function parseTagHeader(strings.slice value) private pure returns (strings.slice[]) {
        var delim = ":".toSlice();
        var tagheaders = new strings.slice[](value.count(delim) + 2);
        for(uint i = 0; i < tagheaders.length; i++) {
            tagheaders[i] = value.split(delim);
        }
        tagheaders[tagheaders.length - 1] = "dkim-signature".toSlice();
        return tagheaders;
    }

    function processBody(strings.slice message, strings.slice method) internal pure returns (
        string
    ) {
        var crlf = "\r\n".toSlice();
        if (method.equals("relaxed".toSlice())) {
            // Ignore all whitespace at the end of lines.
            while (message.contains("\x20\r\n".toSlice())) {
                message = message.split("\x20\r\n".toSlice()).concat(crlf).toSlice().concat(message).toSlice();
            }

            // Reduce all sequences of WSP within a line to a single SP
            while (message.contains("\x20\x20".toSlice())) {
                message = message.split("\x20\x20".toSlice()).concat("\x20".toSlice()).toSlice().concat(message).toSlice();
            }
        }

        // Ignore all empty lines at the end of the message body.
        var emptyLines = "\r\n\r\n".toSlice();
        while (message.endsWith(emptyLines)) {
            message._len -= crlf._len;
        }
        return message.toString();
    }

    function processHeader(strings.slice signatureHeaders, strings.slice method) internal view returns (
        string
    ) {
        var crlf = "\r\n".toSlice();
        var colon = ":".toSlice();
        var tagHeader = parseTagHeader(signatureHeaders);
        var processedHeader = new strings.slice[](tagHeader.length);

        for (uint j = 0; j < tagHeader.length; j++) {
            var value = headers[keccak256(tagHeader[j].toString())].copy();
            var name = _toLower(value.split(colon).toString()).toSlice();

            // Unfold all header field continuation lines
            while (value.contains(crlf)) {
                value = value.split(crlf).concat(value).toSlice();
            }
            // Convert all sequences of one or more WSP characters to a single SP
            while (value.contains("\x20\x20".toSlice())) {
                var line = value.split("\x20\x20".toSlice());
                value = line.concat("\x20".toSlice()).toSlice().concat(value).toSlice();
            }
            // Remove any WSP characters remaining before and after the colon
            while (value.startsWith("\x20".toSlice())) {
                value._len -= 1;
                value._ptr += 1;
            }

            // Remove signature value for "dkim-signature" header
            var p1 = value.split("b=".toSlice());
            if (value.empty()) {
                value = p1;
            } else {
                p1._len += 2;
                value.split(";".toSlice());
                value = p1.concat(value).toSlice();
            }

            var h = new strings.slice[](2);
            h[0] = name;
            h[1] = value;
            processedHeader[j] = colon.join(h).toSlice();
        }

        return crlf.join(processedHeader);
    }

    function getLen(string memory text) public returns (string) {
        body = text.toSlice();
        var allHeaders = body.split("\r\n\r\n".toSlice());

        var delim = "\r\n".toSlice();
        var colon = ":".toSlice();
        var sp = "\x20".toSlice();
        // var tab = "\x09".toSlice();

        var count = allHeaders.count(delim) + 1;
        var headerName = "".toSlice();
        var headerValue = headerName.copy();
        for(uint i = 0; i < count; i++) {
            var part = allHeaders.split(delim);
            if (part.startsWith(sp)) {
                // headerValue = headerValue.concat(delim).toSlice().concat(part).toSlice();
                headerValue._len += delim._len + part._len;
            } else {
                if (!headerName.empty()) {
                    headers[keccak256(_toLower(headerName.toString()))] = headerValue;
                }
                headerName = part.copy().split(colon);
                headerValue = part;
            }
        }

        var (,,,,,,signatureHeaders) = parseSignature(headers[keccak256("dkim-signature")]);

        // bytes32 h = sha256(bytes(processBody(body, body)));
        var processedHeader = processHeader(signatureHeaders, signatureHeaders);

        return processedHeader;
    }

    function mLower(bytes bStr, uint len) internal pure {
		for (uint i = 0; i < len; i++) {
			// Uppercase character...
			if ((bStr[i] >= 65) && (bStr[i] <= 90)) {
				// So we add 32 to make it lowercase
				bStr[i] = bytes1(int(bStr[i]) + 32);
			}
		}
	}

    function _toLower(string str) internal pure returns (string) {
		bytes memory bStr = bytes(str);
		bytes memory bLower = new bytes(bStr.length);
		for (uint i = 0; i < bStr.length; i++) {
			// Uppercase character...
			if ((bStr[i] >= 65) && (bStr[i] <= 90)) {
				// So we add 32 to make it lowercase
				bLower[i] = bytes1(int(bStr[i]) + 32);
			} else {
				bLower[i] = bStr[i];
			}
		}
		return string(bLower);
	}
}
