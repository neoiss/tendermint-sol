// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.9;

//import "./types/Client.sol";
import "@hyperledger-labs/yui-ibc-solidity/contracts/core/IBCHeight.sol";

library Identifier {
    using IBCHeight for Height.Data;

    bytes constant clientPrefix = "client";
    bytes constant clientState = "clientState";
    bytes constant consensusPrefix = "consensusStates";
    bytes constant connectionPrefix = "connections";
    bytes constant channelEndPrefix = "channelEnds";
    bytes constant channelPrefix = "channels";
    bytes constant portPrefix = "ports";
    bytes constant packetPrefix = "commitments";
    bytes constant packetAckPrefix = "acks";
    bytes constant sequencePrefix = "sequences";

    // constant values

    function clientStateKey(string memory clientId) public pure returns (bytes memory) {
        return abi.encodePacked(clientPrefix, "/", clientId, "/", clientState);
    }

    function consensusStateKey(string memory clientId, Height.Data memory height) public pure returns (bytes memory) {
        return abi.encodePacked(clientPrefix, "/", clientId, "/", consensusPrefix, "/", height.toUint128());
    }

    function connectionKey(string memory connectionId) public pure returns (bytes memory) {
        return abi.encodePacked(connectionPrefix, "/", connectionId);
    }

    function channelKey(string memory portId, string memory channelId) public pure returns (bytes memory) {
        return abi.encodePacked(channelEndPrefix, "/", portPrefix, "/", portId, "/", channelPrefix, "/", channelId);
    }

    function packetCommitmentKey(string memory portId, string memory channelId, uint64 sequence) public pure returns (bytes memory) {
        return abi.encodePacked(packetPrefix, "/", portPrefix, "/", portId, "/", channelPrefix, "/", channelId, "/", sequencePrefix, "/", sequence);
    }

    function packetAcknowledgementCommitmentKey(string memory portId, string memory channelId, uint64 sequence) public pure returns (bytes memory) {
        return abi.encodePacked(packetAckPrefix, "/", portPrefix, "/", portId, "/", channelPrefix, "/", channelId, "/", sequencePrefix, "/", sequence);
    }
}
