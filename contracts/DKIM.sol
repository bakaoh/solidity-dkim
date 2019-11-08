pragma solidity ^0.4.24;

import "./utils/Strings.sol";
import "./utils/BytesUtils.sol";
import "./utils/Buffer.sol";
import "./utils/Base64.sol";
import "@ensdomains/solsha1/contracts/SHA1.sol";

library Algorithm {
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

    function checkSHA256(bytes memory data, string memory bodyHash) internal view returns (bool) {
        bytes32 digest = sha256(data);
        return Base64.decode(bodyHash).readBytes32(0) == digest;
    }

    function checkSHA1(bytes memory data, string memory bodyHash) internal view returns (bool) {
        bytes20 digest = SHA1.sha1(data);
        return Base64.decode(bodyHash).readBytes20(0) == digest;
    }

    function verifyRSASHA256(bytes modulus, bytes exponent, bytes data, bytes sig) internal view returns (bool) {
        // Recover the message from the signature
        bool ok;
        bytes memory result;
        (ok, result) = rsarecover(modulus, exponent, sig);

        // Verify it ends with the hash of our data
        return ok && sha256(data) == result.readBytes32(result.length - 32);
    }

    function verifyRSASHA1(bytes modulus, bytes exponent, bytes data, bytes sig) internal view returns (bool) {
        // Recover the message from the signature
        bool ok;
        bytes memory result;
        (ok, result) = rsarecover(modulus, exponent, sig);

        // Verify it ends with the hash of our data
        return ok && SHA1.sha1(data) == result.readBytes20(result.length - 20);
    }
}

contract DKIM {
    using strings for *;

    struct H {
        strings.slice name;
        strings.slice all;
    }

    function getH(H[] memory headers, string memory name) internal pure returns (strings.slice memory) {
        strings.slice memory headerName = toLowercase(name).toSlice();
        for (uint i = 0; i < headers.length; i++) {
            if (headers[i].name.equals(headerName)) return headers[i].all.copy();
        }
        revert("Header not found");
    }

    function getLen(string memory raw) public returns (bool) {
        (H[] memory headers, strings.slice memory body) = parse(raw.toSlice());
        (strings.slice memory d,
        strings.slice memory s,
        strings.slice memory c,
        strings.slice memory a,
        strings.slice memory h,
        strings.slice memory b,
        strings.slice memory bh) = parseHeaderParams(headers);
                
        if (!checkHash(body, c, a, bh)) return false;
        return verifyKey(headers, h, c, a, b);   
    }

    function checkHash(strings.slice body, strings.slice c, strings.slice a, strings.slice bh) internal view returns (bool) {
        strings.slice memory bodyCan = c.copy();
        bodyCan.split("/".toSlice());
        if (bodyCan.empty()) bodyCan = "simple".toSlice();

        string memory processedBody = processBody(body, bodyCan);
        a = a.copy();
        a.split("-".toSlice());
        if (a.equals("sha256".toSlice())) {
            if (!Algorithm.checkSHA256(bytes(processedBody), bh.toString())) return false;
        } else if (a.equals("sha1".toSlice())) {
            if (!Algorithm.checkSHA1(bytes(processedBody), bh.toString())) return false;
        } else {
            revert("Unsupported hash algorithm");
        }
        return true;
    }

    function getKey() internal pure returns (bytes memory modulus1, bytes memory exponent1) {
        modulus1 = hex"9157daff5eb845df246f5e315144ff112ac4f7caa555ad9185620b0a2e5ffb7b14492417c804f23e9d1ce90b5a6ee5719465a85e1ad8ff9b558353d4eb14ae3022f2ef2b25fae5e78fc37c0db1431524fefa6da783b62950694939e623caab7873a110cff9bb848f43e58afcfcb14de54af4f1fd3939e2472c6b9514f174e955";
        exponent1 = hex"010001";
    }

    function verifyKey(H[] memory headers, strings.slice h, strings.slice c, strings.slice a, strings.slice b) internal view returns (bool) {
        string memory processedHeader = processHeader(headers, h, c.split("/".toSlice()));
        a = a.copy();
        strings.slice memory keyAlgo = a.split("-".toSlice());
        if (!keyAlgo.equals("rsa".toSlice())) {
            revert("Unsupported key algorithm");
        }

        var (modulus1, exponent1) = getKey();
        if (a.equals("sha256".toSlice())) {
            return Algorithm.verifyRSASHA256(modulus1, exponent1, bytes(processedHeader), Base64.decode(b.toString()));
        } else {
            return Algorithm.verifyRSASHA1(modulus1, exponent1, bytes(processedHeader), Base64.decode(b.toString()));
        }
        return true;
    }

    function parse(strings.slice memory all) internal pure returns (H[] memory, strings.slice) {
        strings.slice memory crlf = "\r\n".toSlice();
        strings.slice memory colon = ":".toSlice();
        strings.slice memory sp = "\x20".toSlice();
        strings.slice memory tab = "\x09".toSlice();

        H[] memory headers = new H[](30);
        uint i = 0;
        strings.slice memory headerName = strings.slice(0, 0);
        strings.slice memory headerValue = strings.slice(0, 0);
        while (!all.empty()) {
            var part = all.split(crlf);
            if (part.startsWith(sp) || part.startsWith(tab)) {
                headerValue._len += crlf._len + part._len;
            } else {
                if (!headerName.empty()) {
                    headers[i] = H(toLowercase(headerName.toString()).toSlice(), headerValue);
                    i++;
                }
                headerName = part.copy().split(colon);
                headerValue = part;
            }

            if (all.startsWith(crlf)) {
                all._len -= 2;
                all._ptr += 2;
                return (headers, all);
            }
        }
        revert("No header boundary found");
    }

    function parseHeaderParams(H[] memory headers) internal pure returns (
        strings.slice d,
        strings.slice s,
        strings.slice c,
        strings.slice a,
        strings.slice h,
        strings.slice b,
        strings.slice bh
    ) {
        strings.slice memory signature = getH(headers, "dkim-signature");
        strings.slice memory sc = ";".toSlice();
        strings.slice memory eq = "=".toSlice();

        signature.split(":".toSlice());
        while (!signature.empty()) {
            strings.slice memory value = signature.split(sc);
            strings.slice memory name = trim(value.split(eq));
            value = trim(value);
            if (name.equals("d".toSlice())) {
                d = value;
            } else if (name.equals("s".toSlice())) {
                s = value;
            } else if (name.equals("c".toSlice())) {
                c = value;
            } else if (name.equals("a".toSlice())) {
                a = value;
            } else if (name.equals("bh".toSlice())) {
                bh = value;
            } else if (name.equals("h".toSlice())) {
                h = value;
            } else if (name.equals("b".toSlice())) {
                b = unfoldContinuationLines(value, true);
            }
        }
    }

    function processBody(strings.slice message, strings.slice method) internal pure returns (string) {
        if (method.equals("relaxed".toSlice())) {
            message = removeSPAtEndOfLines(message);
            message = removeWSPSequences(message);
        }
        message = ignoreEmptyLineAtEnd(message);
        return message.toString();
    }

    function processHeader(H[] memory headers, strings.slice memory h, strings.slice memory method) internal pure returns (string) {
        strings.slice memory crlf = "\r\n".toSlice();
        strings.slice memory colon = ":".toSlice();
        strings.slice[] memory tags = parseTagList(h);
        strings.slice[] memory processedHeader = new strings.slice[](tags.length);
        bool isSimple = method.equals("simple".toSlice());

        for (uint j = 0; j < tags.length; j++) {
            strings.slice memory value = getH(headers, tags[j].toString());
            if (isSimple) {
                processedHeader[j] = value;
                continue;
            }

            // Convert all header field names to lowercase
            strings.slice memory name = toLowercase(trim(value.split(colon)).toString()).toSlice();

            // Remove signature value for "dkim-signature" header
            if (name.equals("dkim-signature".toSlice())) {
                var part1 = value.split("b=".toSlice());
                if (value.empty()) {
                    value = part1;
                } else {
                    part1._len += 2;
                    value.split(";".toSlice());
                    value = part1.concat(value).toSlice();
                }
            }

            value = unfoldContinuationLines(value, false);
            value = removeWSPSequences(value);
            value = trim(value);

            strings.slice[] memory parts = new strings.slice[](2);
            parts[0] = name;
            parts[1] = value;
            processedHeader[j] = colon.join(parts).toSlice();
        }

        return crlf.join(processedHeader);
    }

    function parseTagList(strings.slice memory value) internal pure returns (strings.slice[]) {
        strings.slice memory colon = ":".toSlice();
        strings.slice[] memory list = new strings.slice[](value.count(colon) + 2);
        for(uint i = 0; i < list.length; i++) {
            list[i] = trim(value.split(colon));
        }
        list[list.length - 1] = "dkim-signature".toSlice();
        return list;
    }

    // utils
    function toLowercase(string str) internal pure returns (string) {
		bytes memory bStr = bytes(str);
		for (uint i = 0; i < bStr.length; i++) {
			if ((bStr[i] >= 65) && (bStr[i] <= 90)) {
				bStr[i] = bytes1(int(bStr[i]) + 32);
			}
		}
		return string(bStr);
	}

    function trim(strings.slice memory self) internal pure returns (strings.slice) {
        strings.slice memory sp = "\x20".toSlice();
        strings.slice memory tab = "\x09".toSlice();
        strings.slice memory crlf = "\r\n".toSlice();
        if (self.startsWith(crlf)) {
            self._len -= 2;
            self._ptr += 2;
        }
        while (self.startsWith(sp) || self.startsWith(tab)) {
            self._len -= 1;
            self._ptr += 1;
        }
        if (self.endsWith(crlf)) {
            self._len -= 2;
        }
        while (self.endsWith(sp) || self.endsWith(tab)) {
            self._len -= 1;
        }
        return self;
    }

    function removeSPAtEndOfLines(strings.slice memory value) internal pure returns (strings.slice) {
        strings.slice memory sp = "\x20".toSlice();
        strings.slice memory crlf = "\r\n".toSlice();
        uint count = value.count(crlf);
        if (count == 0) return value;
        strings.slice[] memory parts = new strings.slice[](count + 1);
        for(uint j = 0; j < parts.length; j++) {
            parts[j] = value.split(crlf);
            while (parts[j].endsWith(sp)) {
                parts[j]._len -= 1;
            }
        }
        return crlf.join(parts).toSlice();
    }

    function removeWSPSequences(strings.slice memory value) internal pure returns (strings.slice) {
        strings.slice memory sp = "\x20".toSlice();
        uint count = value.count(sp);
        if (count == 0) return value;
        strings.slice[] memory parts = new strings.slice[](count + 1);
        for(uint j = 0; j < parts.length; j++) {
            parts[j] = value.split(sp);
        }
        return sp.joinNoEmpty(parts).toSlice();
    }

    function ignoreEmptyLineAtEnd(strings.slice memory value) internal pure returns (strings.slice) {
        strings.slice memory emptyLines = "\r\n\r\n".toSlice();
        while (value.endsWith(emptyLines)) {
            value._len -= 2;
        }
        return value;
    }

    function unfoldContinuationLines(strings.slice memory value, bool isTrim) internal pure returns (strings.slice) {
        strings.slice memory crlf = "\r\n".toSlice();
        uint count = value.count(crlf);
        if (count == 0) return value;
        strings.slice[] memory parts = new strings.slice[](count + 1);
        for(uint i = 0; i < parts.length; i++) {
            parts[i] = value.split(crlf);
            if (isTrim) parts[i] = trim(parts[i]);
        }
        return "".toSlice().join(parts).toSlice();
    }
}
