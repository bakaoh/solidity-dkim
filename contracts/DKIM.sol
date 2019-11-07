pragma solidity ^0.4.24;

import "./utils/Strings.sol";
import "./utils/BytesUtils.sol";
import "./utils/Buffer.sol";
import "./utils/Base64.sol";

contract RSASHA256Algorithm {
    using BytesUtils for *;
    using Buffer for *;

    /**
    * @dev Computes (base ^ exponent) % modulus over big numbers.
    */
    function modexp(bytes memory base, bytes memory exponent, bytes memory modulus) internal view returns (bool success, bytes memory output) {
        uint size = (32 * 3) + base.length + exponent.length + modulus.length;

        Buffer.buffer memory input;
        input.init(size);

        input.appendBytes32(bytes32(base.length));
        input.appendBytes32(bytes32(exponent.length));
        input.appendBytes32(bytes32(modulus.length));
        input.append(base);
        input.append(exponent);
        input.append(modulus);

        output = new bytes(modulus.length);

        assembly {
            success := staticcall(gas(), 5, add(mload(input), 32), size, add(output, 32), mload(modulus))
        }
    }

    function rsarecover(bytes memory N, bytes memory E, bytes memory S) internal view returns (bool, bytes memory) {
        return modexp(S, E, N);
    }

    function verify(bytes modulus, bytes exponent, bytes data, bytes sig) internal view returns (bool) {
        // Recover the message from the signature
        bool ok;
        bytes memory result;
        (ok, result) = rsarecover(modulus, exponent, sig);

        // Verify it ends with the hash of our data
        return ok && sha256(data) == result.readBytes32(result.length - 32);
    }
}

contract DKIM is RSASHA256Algorithm{
    using strings for *;

    mapping(bytes32 => strings.slice) public headers;

    function DKIM() public {
    }

    function getKey(strings.slice selector, strings.slice domain) private pure returns (
        strings.slice
    ) {
        return 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRV9r/XrhF3yRvXjFRRP8RKsT3yqVVrZGFYgsKLl/7exRJJBfIBPI+nRzpC1pu5XGUZaheGtj/m1WDU9TrFK4wIvLvKyX65eePw3wNsUMVJP76baeDtilQaUk55iPKq3hzoRDP+buEj0Plivz8sU3lSvTx/Tk54kcsa5UU8XTpVQIDAQAB'.toSlice();
    }

    function parseSignature(strings.slice signature) private pure returns (
        strings.slice d,
        strings.slice s,
        strings.slice c,
        strings.slice a,
        strings.slice h,
        strings.slice b,
        strings.slice bh
    ) {
        signature.split(": ".toSlice());
        var sdelim = ";".toSlice();
        while (!signature.empty()) {
            var spart = signature.split(sdelim);
            var tagname = spart.split("=".toSlice());
            if (tagname.endsWith("d".toSlice())) {
                d = spart;
            } else if (tagname.endsWith("s".toSlice())) {
                s = spart;
            } else if (tagname.endsWith("c".toSlice())) {
                c = spart;
            } else if (tagname.endsWith("a".toSlice())) {
                a = spart;
            } else if (tagname.endsWith("bh".toSlice())) {
                bh = spart;
            } else if (tagname.endsWith("h".toSlice())) {
                h = spart;
            } else if (tagname.endsWith("b".toSlice())) {
                b = spart;
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
        var spsp = "\x20\x20".toSlice();
        if (method.equals("relaxed".toSlice())) {
            // Ignore all whitespace at the end of lines.
            while (message.contains("\x20\r\n".toSlice())) {
                message = message.split("\x20\r\n".toSlice()).concat(crlf).toSlice().concat(message).toSlice();
            }

            // Reduce all sequences of WSP within a line to a single SP
            while (message.contains(spsp)) {
                message = message.split(spsp).concat("\x20".toSlice()).toSlice().concat(message).toSlice();
            }
        }

        // Ignore all empty lines at the end of the message body.
        var emptyLines = "\r\n\r\n".toSlice();
        while (message.endsWith(emptyLines)) {
            message._len -= crlf._len;
        }
        return message.toString();
    }

    function processHeader(H[] memory newH, strings.slice signatureHeaders, strings.slice method) internal view returns (
        string
    ) {
        var crlf = "\r\n".toSlice();
        var colon = ":".toSlice();
        var tagHeader = parseTagHeader(signatureHeaders);
        var processedHeader = new strings.slice[](tagHeader.length);

        for (uint j = 0; j < tagHeader.length; j++) {
            var value = getH(newH, tagHeader[j].toString()).copy();
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

    bytes public modulus;
    bytes public exponent;
    function set(bytes m, bytes e) public {
        modulus = m;
        exponent = e;
    }

    struct H {
        strings.slice name;
        strings.slice all;
    }

    function parse(strings.slice memory allHeaders) internal returns (H[]) {
        var delim = "\r\n".toSlice();
        var colon = ":".toSlice();
        var sp = "\x20".toSlice();
        // var tab = "\x09".toSlice();

        var headerName = "".toSlice();
        var headerValue = headerName.copy();
        H[] memory newH = new H[](30);
        uint i = 0;
        while (!allHeaders.empty()) {
            var part = allHeaders.split(delim);
            if (part.startsWith(sp)) {
                // headerValue = headerValue.concat(delim).toSlice().concat(part).toSlice();
                headerValue._len += delim._len + part._len;
            } else {
                if (!headerName.empty()) {
                    newH[i] = H(_toLower(headerName.toString()).toSlice(), headerValue);
                    i++;
                    // headers[keccak256(_toLower(headerName.toString()))] = headerValue;
                }
                headerName = part.copy().split(colon);
                headerValue = part;
            }
        }
        return newH;
    }

    function getH(H[] memory newH, string memory name) internal returns (strings.slice) {
        var hn = _toLower(name).toSlice();
        for (uint i = 0; i < newH.length; i++) {
            if (newH[i].name.equals(hn)) return newH[i].all;
        }
        return "".toSlice();
    }

    function getLen(string memory text) public returns (bool) {
        var body = text.toSlice();
        var allHeaders = body.split("\r\n\r\n".toSlice());
        H[] memory newH = parse(allHeaders);
        // return true;
        var (d, s, c, a, h, b, bh) = parseSignature(getH(newH, "dkim-signature").copy());
        bytes32 digest = sha256(bytes(processBody(body, c)));
        if (Base64.decode(bh.toString()).readBytes32(0) != digest) return false;

        var processedHeader = processHeader(newH, h, c);
        var crlf = "\r\n".toSlice();
        
        while (b.contains(crlf)) {
            b = b.split(crlf).concat(b).toSlice();
        }
        while (b.contains("\x20".toSlice())) {
            b = b.split("\x20".toSlice()).concat(b).toSlice();
        }
        return verify(modulus, exponent, bytes(processedHeader), Base64.decode(b.toString()));
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
