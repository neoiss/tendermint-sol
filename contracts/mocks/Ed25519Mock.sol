// SPDX-License-Identifier: TBD

pragma solidity ^0.8.2;

import "../utils/crypto/Ed25519.sol";
import "../utils/Bytes.sol";
import {BytesLib} from "solidity-bytes-utils/contracts/BytesLib.sol";

contract Ed25519Mock {
    using Bytes for bytes;

    function verify(
        bytes memory message,
        bytes memory publicKey,
        bytes memory sig
    ) public pure returns (bool) {
        require(sig.length == 64, "siganture length != 64");
        require(publicKey.length == 32, "pubkey length != 32");
        return
            Ed25519.check(
                publicKey.toBytes32(),
                BytesLib.slice(sig, 0, 32).toBytes32(),
                BytesLib.slice(sig, 32, 64).toBytes32(),
                message
            );
    }
}
