pragma solidity ^0.4.14;

import "./strings.sol";

contract DKIM {
    using strings for *;

    function DKIM() public {
    }

    function getKey(strings.slice selector, strings.slice domain) private pure returns (
        strings.slice
    ) {
        return 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRV9r/XrhF3yRvXjFRRP8RKsT3yqVVrZGFYgsKLl/7exRJJBfIBPI+nRzpC1pu5XGUZaheGtj/m1WDU9TrFK4wIvLvKyX65eePw3wNsUMVJP76baeDtilQaUk55iPKq3hzoRDP+buEj0Plivz8sU3lSvTx/Tk54kcsa5UU8XTpVQIDAQAB'.toSlice();
    }

    function parse(strings.slice signature) private pure returns (
        strings.slice domain,
        strings.slice selector,
        strings.slice canonicalHeader,
        strings.slice canonicalBody,
        strings.slice hashAlgorithm,
        strings.slice verifyAlgorithm,
        strings.slice headers
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
                headers = spart;
            }
        }
    }

    function parseHeader(strings.slice value) private pure returns (strings.slice[]) {
        var delim = ":".toSlice();
        var headers = new strings.slice[](value.count(delim) + 1);
        for(uint i = 0; i < headers.length; i++) {
            headers[i] = value.split(delim);
        }
        return headers;
    }

    function processBody(strings.slice message, strings.slice method) internal pure returns (
        string
    ) {
        var crlf = "\r\n".toSlice();
        if (method.equals("relaxed".toSlice())) {
            // Ignore all whitespace at the end of lines.
            while (message.contains("\x20\r\n".toSlice())) {
                var h = message.split("\x20\r\n".toSlice());
                message = h.concat(crlf).toSlice().concat(message).toSlice();
            }

            // Reduce all sequences of WSP within a line to a single SP
        }

        // Ignore all empty lines at the end of the message body.
        var emptyLines = "\r\n\r\n".toSlice();
        while (message.endsWith(emptyLines)) {
            message._len -= crlf._len;
        }
        return message.toString();
    }

    function getHeader(strings.slice allHeaders, strings.slice name) internal pure returns (
        strings.slice
    ) {
        var delim = "\r\n".toSlice();
        var count = allHeaders.count(delim) + 1;
        for(uint i = 0; i < count; i++) {
            var part = allHeaders.split(delim);
            var lowercase = _toLower(part.toString()).toSlice();
            if (lowercase.startsWith(name)) {
                var value = part;
                for (i = i + 1; i < count; i++) {
                    var part2 = allHeaders.split(delim);
                    if (part2.startsWith("\x20".toSlice())) {
                        value = value.concat(delim).toSlice().concat(part2).toSlice();
                    } else {
                        return value;
                    }
                }
            }
        }
        return "".toSlice();
    }

    function getLen(string memory value) public returns (bytes32) {
        var body = value.toSlice();
        var header = body.split("\r\n\r\n".toSlice());
        var allHeader = header.copy();
        // return getHeader(allHeader, _toLower("DKIM-Signature").toSlice()).toString();
        var delim = "\r\n".toSlice();
        var count = header.count(delim) + 1;
        for(uint i = 0; i < count; i++) {
            var part = header.split(delim);
            if (part.startsWith("DKIM-Signature".toSlice())) {
                var signature = part;
                for (i = i + 1; i < count; i++) {
                    var part2 = header.split(delim);
                    if (part2.startsWith("\x20".toSlice())) {
                        signature = signature.concat(part2).toSlice();
                    } else {
                        var (,,,,,,ha) = parse(signature);

                        // hash
                        bytes32 h = sha256(bytes(processBody(body, body)));
                        return h;
                        
                        // var headers = parseHeader(h);
                        // for (uint j = 0; j < headers.length; j++) {
                        //     headers[j] = getHeader(allHeader.copy(), headers[j]);
                        // }
                        // return headers[0].toString();
                        // var count3 = header3.count(delim) + 1;
                        // for(uint i3 = 0; i3 < count; i3++) {
                        //     var part3 = header3.split(delim);
                        //     var headerName = _toLower(part3.split(":".toSlice()).toString());
                        //     for (uint j3 = 0; j3 < headers.length; j3++) {
                        //         if (headers[j3].equals(headerName.toSlice())) {
                        //             headers[j3] = part3;
                        //         }
                        //     }

                        // }
                    }
                }
            }
        }
        return "notfound";
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
