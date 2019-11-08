pragma solidity ^0.4.24;

import "@ensdomains/solsha1/contracts/SHA1.sol";
import "@ensdomains/buffer/contracts/Buffer.sol";

library Algorithm {
    using Buffer for *;

    function checkSHA256(bytes memory data, string memory bodyHash) internal pure returns (bool) {
        bytes32 digest = sha256(data);
        return readBytes32(base64decode(bodyHash), 0) == digest;
    }

    function checkSHA1(bytes memory data, string memory bodyHash) internal pure returns (bool) {
        bytes20 digest = SHA1.sha1(data);
        return readBytes20(base64decode(bodyHash), 0) == digest;
    }

    function verifyRSASHA256(bytes modulus, bytes exponent, bytes data, string memory sig) internal view returns (bool) {
        // Recover the message from the signature
        bool ok;
        bytes memory result;
        (ok, result) = modexp(base64decode(sig), exponent, modulus);

        // Verify it ends with the hash of our data
        return ok && sha256(data) == readBytes32(result, result.length - 32);
    }

    function verifyRSASHA1(bytes modulus, bytes exponent, bytes data, string memory sig) internal view returns (bool) {
        // Recover the message from the signature
        bool ok;
        bytes memory result;
        (ok, result) = modexp(base64decode(sig), exponent, modulus);

        // Verify it ends with the hash of our data
        return ok && SHA1.sha1(data) == readBytes20(result, result.length - 20);
    }


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

    /*
    * @dev Returns the 32 byte value at the specified index of self.
    * @param self The byte string.
    * @param idx The index into the bytes
    * @return The specified 32 bytes of the string.
    */
    function readBytes32(bytes memory self, uint idx) internal pure returns (bytes32 ret) {
        require(idx + 32 <= self.length);
        assembly {
            ret := mload(add(add(self, 32), idx))
        }
    }

    /*
    * @dev Returns the 32 byte value at the specified index of self.
    * @param self The byte string.
    * @param idx The index into the bytes
    * @return The specified 32 bytes of the string.
    */
    function readBytes20(bytes memory self, uint idx) internal pure returns (bytes20 ret) {
        require(idx + 20 <= self.length);
        assembly {
            ret := and(mload(add(add(self, 32), idx)), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000)
        }
    }

    bytes constant private base64stdchars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    function base64decode(string memory str) internal pure returns (bytes) {
        bytes memory data = bytes(str);
        uint8[] memory decoding_table = new uint8[](256);

        for (uint8 t = 0; t < 64; t++) {
            decoding_table[uint(base64stdchars[t])] = t;
        }

        if (data.length % 4 != 0) return "";
        uint output_length = data.length / 4 * 3;
        if (data[data.length - 1] == '=') output_length--;
        if (data[data.length - 2] == '=') output_length--;

        bytes memory decoded_data = new bytes(output_length);

        uint j = 0;
        for (uint i = 0; i < data.length;) {
            uint sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[uint(data[i++])];
            uint sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[uint(data[i++])];
            uint sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[uint(data[i++])];
            uint sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[uint(data[i++])];

            uint triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

            if (j < output_length) decoded_data[j++] = bytes1((triple >> 2 * 8) & 0xFF);
            if (j < output_length) decoded_data[j++] = bytes1((triple >> 1 * 8) & 0xFF);
            if (j < output_length) decoded_data[j++] = bytes1((triple >> 0 * 8) & 0xFF);
        }
        return decoded_data;
    }
}