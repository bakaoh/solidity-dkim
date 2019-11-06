// contract DKIMParser {
//     using strings for *;

//     mapping(bytes32 => strings.slice) public headers;
//     strings.slice public body;

//     function DKIMParser(string memory text) public {
//         body = text.toSlice();
//         var allHeaders = body.split("\r\n\r\n".toSlice());

//         var delim = "\r\n".toSlice();
//         var colon = ":".toSlice();
//         var sp = "\x20".toSlice();
//         // var tab = "\x09".toSlice();

//         var count = allHeaders.count(delim) + 1;
//         var headerName = "".toSlice();
//         var headerValue = headerName.copy();
//         for(uint i = 0; i < count; i++) {
//             var part = allHeaders.split(delim);
//             if (part.startsWith(sp)) {
//                 // headerValue = headerValue.concat(delim).toSlice().concat(part).toSlice();
//                 headerValue._len += delim._len + part._len;
//             } else {
//                 if (!headerName.empty()) {
//                     headers[keccak256(_toLower(headerName.toString()))] = headerValue;
//                 }
//                 headerName = part.split(colon);
//                 headerValue = part;
//             }
//         }
//     }

//     function getHeader(string memory name) public view returns (uint) {
//         return headers[keccak256(name)]._len;
//     }

//     function _toLower(string str) internal pure returns (string) {
// 		bytes memory bStr = bytes(str);
// 		bytes memory bLower = new bytes(bStr.length);
// 		for (uint i = 0; i < bStr.length; i++) {
// 			if ((bStr[i] >= 65) && (bStr[i] <= 90)) {
// 				bLower[i] = bytes1(int(bStr[i]) + 32);
// 			} else {
// 				bLower[i] = bStr[i];
// 			}
// 		}
// 		return string(bLower);
// 	}
// }