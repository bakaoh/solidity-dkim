pragma solidity ^0.4.24;

import "./utils/Strings.sol";
import "./Algorithm.sol";

library Hardcode {
    using strings for *;

    function getRSAKey(strings.slice memory domain, strings.slice memory selector) internal pure returns (bytes memory modulus, bytes memory exponent) {
        if ("fusemachines.com".toSlice().equals(domain) && "google".toSlice().equals(selector)) {
            modulus = hex"9157daff5eb845df246f5e315144ff112ac4f7caa555ad9185620b0a2e5ffb7b14492417c804f23e9d1ce90b5a6ee5719465a85e1ad8ff9b558353d4eb14ae3022f2ef2b25fae5e78fc37c0db1431524fefa6da783b62950694939e623caab7873a110cff9bb848f43e58afcfcb14de54af4f1fd3939e2472c6b9514f174e955";
            exponent = hex"010001";
            return;
        }
        if ("gmail.com".toSlice().equals(domain) && "20161025".toSlice().equals(selector)) {
            modulus = hex"be23c6064e1907ae147d2a96c8089c751ee5a1d872b5a7be11845056d28384cfb59978c4a91b4ffe90d3dec0616b3926038f27da4e4d254c8c1283bc9dcdabeac500fbf0e89b98d1059a7aa832893b08c9e51fcea476a69511be611250a91b6a1204a22561bb87b79f1985a687851184533d93dfab986fc2c02830c7b12df9cf0e3259e068b974e3f6cf99fa63744c8b5b23629a4efad425fa2b29b3622443373d4c389389ececc5692e0f15b54b9f49b999fd0754db41a4fc16b8236f68555f9546311326e56c1ea1fe858e3c66f3a1282d440e3b487579dd2c198c8b15a5bab82f1516f48c4013063319c4a06789f943c5fc4e7768c2c0d4ce871c3c51a177";
            exponent = hex"010001";
            return;
        }
        if ("protonmail.com".toSlice().equals(domain) && "default".toSlice().equals(selector)) {
            modulus = hex"ca678aeacca0caadf24728d7d3821d41ff736da07ad1f13e185d3b8796da4526585cf867230c4a5fdadbf31e747b47b11b84e762c32e122e0097a8421141eeecc0e4fcbeae733d9ebf239d28f22b31cf9d10964bcda085b27a2350aa50cf40b41ecb441749f2f39d063f6c7c6f280a808b7dc2087c12fce3eeb96707abc0c2a9";
            exponent = hex"010001";
            return;
        }
        if ("yahoo.com".toSlice().equals(domain) && "s2048".toSlice().equals(selector)) {
            modulus = hex"ba85ae7e06d6c39f0c7335066ccbf5efa45ac5d64638c9109a7f0e389fc71a843a75a95231688b6a3f0831c1c2d5cb9b271da0ce200f40754fb4561acb22c0e1ac89512364d74feea9f072894f2a88f084e09485ae9c5f961308295e1bb7e835b87c3bc0bce0b827f8600a11e97c54291b00a07ba817b33ebfa6cc67f5f51bebe258790197851f80943a3bc17572428aa19e4aa949091f9a436aa6e0b3e1773e9ca201441f07a104cce03528c3d15891a9ce03ed2a8ba40dc42e294c3d180ba5ee4488c84722ceaadb69428d2c6026cf47a592a467cc8b15a73ea3753d7f615e518ba614390e6c3796ea37367c4f1a109646d5472e9e28e8d49e84924e648087";
            exponent = hex"010001";
            return;
        }
        revert("unknown hardcode DNS record");
    }
}

contract DKIM {
    using strings for *;

    struct Headers {
        uint len;
        strings.slice[] name;
        strings.slice[] value;
    }

    struct SigTags {
        strings.slice d;
        strings.slice s;
        strings.slice cHeader;
        strings.slice cBody;
        strings.slice aHash;
        strings.slice aKey;
        strings.slice h;
        strings.slice b;
        strings.slice bh;
    }

    function getLen(string memory raw) public view returns (bool) {
        (Headers memory headers, strings.slice memory body) = parse(raw.toSlice());

        strings.slice memory dkimSig = getHeader(headers, "dkim-signature");
        SigTags memory sigTags = parseSigTags(dkimSig);
                
        require(verifyBodyHash(body, sigTags), "body hash did not verify");
        require(verifySignature(headers, sigTags), "signature did not verify");
        
        return true;
    }

    function verifyBodyHash(strings.slice memory body, SigTags memory sigTags) internal pure returns (bool) {
        string memory processedBody = processBody(body, sigTags.cBody);
        if (sigTags.aHash.equals("sha256".toSlice())) {
            return Algorithm.checkSHA256(bytes(processedBody), sigTags.bh.toString());
        } else if (sigTags.aHash.equals("sha1".toSlice())) {
            return Algorithm.checkSHA1(bytes(processedBody), sigTags.bh.toString());
        } else {
            revert("unsupported hash algorithm");
        }
    }

    function verifySignature(Headers memory headers, SigTags memory sigTags) internal view returns (bool) {
        string memory processedHeader = processHeader(headers, sigTags.h, sigTags.cHeader);
        if (!sigTags.aKey.equals("rsa".toSlice())) {
            revert("unsupported key algorithm");
        }

        (bytes memory modulus, bytes memory exponent) = Hardcode.getRSAKey(sigTags.d, sigTags.s);
        if (sigTags.aHash.equals("sha256".toSlice())) {
            return Algorithm.verifyRSASHA256(modulus, exponent, bytes(processedHeader), sigTags.b.toString());
        } else {
            return Algorithm.verifyRSASHA1(modulus, exponent, bytes(processedHeader), sigTags.b.toString());
        }
    }

    function parse(strings.slice memory all) internal pure returns (Headers memory, strings.slice memory) {
        strings.slice memory crlf = "\r\n".toSlice();
        strings.slice memory colon = ":".toSlice();
        strings.slice memory sp = "\x20".toSlice();
        strings.slice memory tab = "\x09".toSlice();

        Headers memory headers = Headers(0, new strings.slice[](30), new strings.slice[](30));
        strings.slice memory headerName = strings.slice(0, 0);
        strings.slice memory headerValue = strings.slice(0, 0);
        while (!all.empty()) {
            strings.slice memory part = all.split(crlf);
            if (part.startsWith(sp) || part.startsWith(tab)) {
                headerValue._len += crlf._len + part._len;
            } else {
                if (!headerName.empty()) {
                    headers.name[headers.len] = toLowercase(headerName.toString()).toSlice();
                    headers.value[headers.len] = headerValue;
                    headers.len++;
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
        revert("no header boundary found");
    }

    // @dev https://tools.ietf.org/html/rfc6376#section-3.5
    function parseSigTags(strings.slice memory signature) internal pure returns (SigTags memory sigTags) {
        strings.slice memory sc = ";".toSlice();
        strings.slice memory eq = "=".toSlice();

        signature.split(":".toSlice());
        while (!signature.empty()) {
            strings.slice memory value = signature.split(sc);
            strings.slice memory name = trim(value.split(eq));
            value = unfoldContinuationLines(trim(value), true);

            if (name.equals("v".toSlice()) && !value.equals("1".toSlice())) {
                revert("incompatible signature version");
            } else if (name.equals("d".toSlice())) {
                sigTags.d = value;
            } else if (name.equals("s".toSlice())) {
                sigTags.s = value;
            } else if (name.equals("c".toSlice())) {
                sigTags.cHeader = value.split("/".toSlice());
                sigTags.cBody = value;
                if (sigTags.cBody.empty()) {
                    sigTags.cBody = "simple".toSlice();
                }
            } else if (name.equals("a".toSlice())) {
                sigTags.aKey = value.split("-".toSlice());
                sigTags.aHash = value;
                if (sigTags.aHash.empty()) {
                    revert("malformed algorithm name");
                }
            } else if (name.equals("bh".toSlice())) {
                sigTags.bh = value;
            } else if (name.equals("h".toSlice())) {
                sigTags.h = value;
            } else if (name.equals("b".toSlice())) {
                sigTags.b = value;
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

    function processHeader(Headers memory headers, strings.slice memory h, strings.slice memory method) internal pure returns (string) {
        strings.slice memory crlf = "\r\n".toSlice();
        strings.slice memory colon = ":".toSlice();
        strings.slice[] memory tags = parseTagList(h);
        strings.slice[] memory processedHeader = new strings.slice[](tags.length);
        bool isSimple = method.equals("simple".toSlice());

        for (uint j = 0; j < tags.length; j++) {
            strings.slice memory value = getHeader(headers, tags[j].toString());
            if (isSimple) {
                processedHeader[j] = value;
                continue;
            }

            // Convert all header field names to lowercase
            strings.slice memory name = toLowercase(trim(value.split(colon)).toString()).toSlice();

            // Remove signature value for "dkim-signature" header
            if (name.equals("dkim-signature".toSlice())) {
                strings.slice memory part1 = value.split("b=".toSlice());
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
    function getHeader(Headers memory headers, string memory name) internal pure returns (strings.slice memory) {
        strings.slice memory headerName = toLowercase(name).toSlice();
        for (uint i = 0; i < headers.len; i++) {
            if (headers.name[i].equals(headerName)) return headers.value[i].copy();
        }
        revert("Header not found");
    }

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
        return joinNoEmpty(sp, parts).toSlice();
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

    function joinNoEmpty(strings.slice memory self, strings.slice[] memory parts) internal pure returns (string memory) {
        if (parts.length == 0)
            return "";

        uint length = 0;
        for(uint i = 0; i < parts.length; i++)
            if (parts[i]._len > 0) {
                length += self._len + parts[i]._len;
            }
        length -= self._len;

        string memory ret = new string(length);
        uint retptr;
        assembly { retptr := add(ret, 32) }

        for(i = 0; i < parts.length; i++) {
            if (parts[i]._len == 0) continue;
            memcpy(retptr, parts[i]._ptr, parts[i]._len);
            retptr += parts[i]._len;
            if (i < parts.length - 1) {
                memcpy(retptr, self._ptr, self._len);
                retptr += self._len;
            }
        }

        return ret;
    }

    function memcpy(uint dest, uint src, uint len) private pure {
        // Copy word-length chunks while possible
        for(; len >= 32; len -= 32) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += 32;
            src += 32;
        }

        // Copy remaining bytes
        uint mask = 256 ** (32 - len) - 1;
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }
}
