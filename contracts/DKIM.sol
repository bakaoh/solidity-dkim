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
        strings.slice verifyAlgorithm
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
            } 
        }
    }

    function processBody(strings.slice message, strings.slice method) internal pure returns (
        string
    ) {

    }

    function getLen(string memory value) public pure returns (bytes32) {
        var body = value.toSlice();
        var header = body.split("\r\n\r\n".toSlice());

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
                        // // parse signature
                        // signature.split(": ".toSlice());
                        // var sdelim = ";".toSlice();
                        // var scount = signature.count(sdelim) + 1;

                        // var domain; 
                        // var selector;
                        // for (uint j = 0; j < scount; j++) {
                        //     var spart = signature.split(sdelim);
                        //     var tagname = spart.split("=".toSlice());
                        //     if (tagname.endsWith("d".toSlice())) {
                        //         return spart.toString();
                        //     }
                        // }

                        var (, selector) = parse(signature);
                        bytes32 h = sha256(bytes(body.toString()));
                        return h;
                    }
                }
            }
        }
        return "notfound";
    }
}
