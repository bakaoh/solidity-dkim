pragma solidity ^0.4.14;

library Base64 {

    bytes constant private base64stdchars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    function decode(string memory str) internal pure returns (bytes) {
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