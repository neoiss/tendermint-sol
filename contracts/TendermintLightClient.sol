// SPDX-License-Identifier: TBD
pragma solidity ^0.8.2;

import {
    LightHeader,
    ValidatorSet,
    ClientState,
    ConsensusState,
    TmHeader,
    MerkleProof
} from "./proto/TendermintLight.sol";
import {
    PROOFS_PROTO_GLOBAL_ENUMS,
    CommitmentProof,
    ProofSpec,
    InnerSpec,
    LeafOp,
    InnerOp
} from "./proto/proofs.sol";
import "./proto/TendermintHelper.sol";
import {GoogleProtobufAny as Any} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/types/GoogleProtobufAny.sol";
import "@hyperledger-labs/yui-ibc-solidity/contracts/core/IClient.sol";
import "@hyperledger-labs/yui-ibc-solidity/contracts/core/IBCHost.sol";
import "@hyperledger-labs/yui-ibc-solidity/contracts/core/IBCMsgs.sol";
import "@hyperledger-labs/yui-ibc-solidity/contracts/core/IBCHeight.sol";
import "@hyperledger-labs/yui-ibc-solidity/contracts/core/types/Client.sol";
import "./utils/Bytes.sol";
import "./utils/Tendermint.sol";
import "./ics23/ics23.sol";
import {Proof}  from "./ics23/ics23Proof.sol";
import "./Identifier.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

contract TendermintLightClient is IClient {
    using Bytes for bytes;
    using Bytes for bytes32;
    using TendermintHelper for TmHeader.Data;
    using TendermintHelper for ConsensusState.Data;
    using TendermintHelper for ValidatorSet.Data;
    using IBCHeight for Height.Data;

    struct ProtoTypes {
        bytes32 clientState;
        bytes32 consensusState;
        bytes32 tmHeader;
    }

    ProtoTypes private _pts;

    constructor() {
        _pts = ProtoTypes({
            clientState: keccak256(abi.encodePacked("/ibc.lightclients.tendermint.v1.ClientState")),
            consensusState: keccak256(abi.encodePacked("/ibc.lightclients.tendermint.v1.ClientState")),
            tmHeader: keccak256(abi.encodePacked("/tendermint.light.TmHeader"))
        });
    }

    /**
     * @dev getTimestampAtHeight returns the timestamp of the consensus state at the given height.
     */
    function getTimestampAtHeight(
        IBCHost host,
        string memory clientId,
        Height.Data memory height
    ) public override view returns (uint64, bool) {
        (ConsensusState.Data memory consensusState, bool found) = getConsensusState(host, clientId, height);
        if (!found) {
            return (0, false);
        }
        // TODO: Timestamp is a sum of nanoseconds and seconds, this method requires return type update or not? (solidity doesn't support nanoseconds)
        return (uint64(consensusState.timestamp.Seconds), true);
    }

	/**
	* @dev getLatestHeight returs latest height stored in the given client state
	*/
    function getLatestHeight(
        IBCHost host,
        string memory clientId
    ) public override view returns (Height.Data memory, bool) {
        (ClientState.Data memory clientState, bool found) = getClientState(host, clientId);
        if (!found) {
            return (Height.Data(0, 0), false);
        }
        return (clientState.latest_height, true);
    }

    /**
     * @dev checkHeaderAndUpdateState validates the header
     */
    function checkHeaderAndUpdateState(
        IBCHost host,
        string memory clientId,
        bytes memory clientStateBytes,
        bytes memory headerBytes
    ) public override view returns (bytes memory newClientStateBytes, bytes memory newConsensusStateBytes, Height.Data memory height) {
        TmHeader.Data memory tmHeader;
        ClientState.Data memory clientState;
        ConsensusState.Data memory trustedConsensusState;
        ConsensusState.Data memory prevConsState;
        bool ok;
        bool conflictingHeader;

        (tmHeader, ok) = unmarshalTmHeader(headerBytes);
        require(ok, "LC: light block is invalid");

        // Check if the Client store already has a consensus state for the header's height
        // If the consensus state exists, and it matches the header then we return early
        // since header has already been submitted in a previous UpdateClient.
	    (prevConsState, ok) = getConsensusState(host, clientId, tmHeader.getHeight());
	    if (ok) {
            // This header has already been submitted and the necessary state is already stored
            // in client store, thus we can return early without further validation.
            if (prevConsState.isEqual(tmHeader.toConsensusState())) {
				return (clientStateBytes, marshalConsensusState(prevConsState), tmHeader.getHeight());
            }
            // A consensus state already exists for this height, but it does not match the provided header.
            // Thus, we must check that this header is valid, and if so we will freeze the client.
            conflictingHeader = true;
	    }

        (trustedConsensusState, ok) = getConsensusState(host, clientId, tmHeader.trusted_height);
        require(ok, "LC: consensusState not found at trusted height");

        (clientState, ok) = unmarshalClientState(clientStateBytes);
        require(ok, "LC: client state is invalid");

        checkValidity(clientState, trustedConsensusState, tmHeader, Duration.Data({Seconds: SafeCast.toInt64(int256(block.timestamp)), nanos: 0}));

	    // Header is different from existing consensus state and also valid, so freeze the client and return
	    if (conflictingHeader) {
            clientState.frozen_height = tmHeader.getHeight();
            return (
                marshalClientState(clientState),
                marshalConsensusState(tmHeader.toConsensusState()),
                tmHeader.getHeight()
            );
	    }

        // TODO: check consensus state monotonicity

        // update the consensus state from a new header and set processed time metadata
        if (tmHeader.getHeight().gt(clientState.latest_height)) {
            clientState.latest_height = tmHeader.getHeight();
        }

        return (marshalClientState(clientState), marshalConsensusState(tmHeader.toConsensusState()), clientState.latest_height);
    }

    // checkValidity checks if the Tendermint header is valid.
    function checkValidity(
        ClientState.Data memory clientState,
        ConsensusState.Data memory trustedConsensusState,
        TmHeader.Data memory tmHeader,
        Duration.Data memory currentTime
    ) private view {
	    // assert header height is newer than consensus state
        require(
            tmHeader.getHeight().gt(tmHeader.trusted_height),
            "LC: header height consensus state height"
        );

        LightHeader.Data memory lc;
        lc.chain_id = clientState.chain_id;
        lc.height = int64(tmHeader.trusted_height.revision_height);
        lc.time = trustedConsensusState.timestamp;
        lc.next_validators_hash = trustedConsensusState.next_validators_hash;

        ValidatorSet.Data memory trustedVals = tmHeader.trusted_validators;
        SignedHeader.Data memory trustedHeader;
        trustedHeader.header = lc;

        SignedHeader.Data memory untrustedHeader = tmHeader.signed_header;
        ValidatorSet.Data memory untrustedVals = tmHeader.validator_set;

        bool ok = Tendermint.verify(
			clientState.trusting_period,
			clientState.max_clock_drift,
			clientState.trust_level,
            trustedHeader,
            trustedVals,
            untrustedHeader,
            untrustedVals,
            currentTime
        );

        require(ok, "LC: failed to verify header");
    }

    function verifyConnectionState(
        IBCHost host,
        string memory clientId,
        Height.Data memory height,
        bytes memory prefix,
        bytes memory proof,
        string memory connectionId,
        bytes memory connectionBytes // serialized with pb
    ) public override view returns (bool) {
        ClientState.Data memory clientState;
        ConsensusState.Data memory consensusState;
        bool found;

        (clientState, found) = getClientState(host, clientId);
        if (!found) {
            return false;
        }
        if (!validateArgs(clientState, height, prefix, proof)) {
            return false;
        }
        (consensusState, found) = getConsensusState(host, clientId, height);
        if (!found) {
            return false;
        }
        bytes[] memory path = applyPrefix(prefix, Identifier.connectionKey(connectionId));
        return verifyMembership(clientState.proof_specs, proof, consensusState.root.hash, path, connectionBytes);
    }

    function verifyChannelState(
        IBCHost host,
        string memory clientId,
        Height.Data memory height,
        bytes memory prefix,
        bytes memory proof,
        string memory portId,
        string memory channelId,
        bytes memory channelBytes // serialized with pb
    ) public override view returns (bool) {
        ClientState.Data memory clientState;
        ConsensusState.Data memory consensusState;
        bool found;

        (clientState, found) = getClientState(host, clientId);
        if (!found) {
            return false;
        }
        if (!validateArgs(clientState, height, prefix, proof)) {
            return false;
        }
        (consensusState, found) = getConsensusState(host, clientId, height);
        if (!found) {
            return false;
        }
        bytes[] memory path = applyPrefix(prefix, Identifier.channelKey(portId, channelId));
        return verifyMembership(clientState.proof_specs, proof, consensusState.root.hash, path, channelBytes);
    }

    function verifyPacketCommitment(
        IBCHost host,
        string memory clientId,
        Height.Data memory height,
        uint64 delayPeriodTime,
        uint64 delayPeriodBlocks,
        bytes memory prefix,
        bytes memory proof,
        string memory portId,
        string memory channelId,
        uint64 sequence,
        bytes32 commitmentBytes
    ) public override returns (bool) {
        ClientState.Data memory clientState;
        ConsensusState.Data memory consensusState;
        bool found;

        (clientState, found) = getClientState(host, clientId);
        if (!found) {
            return false;
        }
        if (!validateArgs(clientState, height, prefix, proof)) {
            return false;
        }
        if (!validateDelayPeriod(host, clientId, height, delayPeriodTime, delayPeriodBlocks)) {
            return false;
        }
        (consensusState, found) = getConsensusState(host, clientId, height);
        if (!found) {
            return false;
        }
        bytes[] memory path = applyPrefix(prefix, Identifier.packetCommitmentKey(portId, channelId, sequence));
        return verifyMembership(clientState.proof_specs, proof, consensusState.root.hash, path, commitmentBytes.toBytes());
    }

    function verifyPacketAcknowledgement(
        IBCHost host,
        string memory clientId,
        Height.Data memory height,
        uint64 delayPeriodTime,
        uint64 delayPeriodBlocks,
        bytes memory prefix,
        bytes memory proof,
        string memory portId,
        string memory channelId,
        uint64 sequence,
        bytes memory acknowledgement
    ) public override returns (bool) {
        ClientState.Data memory clientState = mustGetClientState(host, clientId);
        if (!validateArgs(clientState, height, prefix, proof)) {
            return false;
        }
        if (!validateDelayPeriod(host, clientId, height, delayPeriodTime, delayPeriodBlocks)) {
            return false;
        }
        bytes memory stateRoot = mustGetConsensusState(host, clientId, height).root.hash;
        bytes[] memory path = applyPrefix(prefix, Identifier.packetAcknowledgementCommitmentKey(portId, channelId, sequence));
        bytes32 ackCommitment = host.makePacketAcknowledgementCommitment(acknowledgement);
        return verifyMembership(clientState.proof_specs, proof, stateRoot, path, ackCommitment.toBytes());
    }

    function verifyClientState(
        IBCHost host,
        string memory clientId,
        Height.Data memory height,
        bytes memory prefix,
        string memory counterpartyClientIdentifier,
        bytes memory proof,
        bytes memory clientStateBytes
    ) public override view returns (bool) {
        ClientState.Data memory clientState;
        ConsensusState.Data memory consensusState;
        bool found;

        (clientState, found) = getClientState(host, clientId);
        if (!found) {
            return false;
        }
        if (!validateArgs(clientState, height, prefix, proof)) {
            return false;
        }
        (consensusState, found) = getConsensusState(host, clientId, height);
        if (!found) {
            return false;
        }
        bytes[] memory path = applyPrefix(prefix, Identifier.clientStateKey(counterpartyClientIdentifier));
        return verifyMembership(clientState.proof_specs, proof, consensusState.root.hash, path, clientStateBytes);
    }

    function verifyClientConsensusState(
        IBCHost host,
        string memory clientId,
        Height.Data memory height,
        string memory counterpartyClientIdentifier,
        Height.Data memory consensusHeight,
        bytes memory prefix,
        bytes memory proof,
        bytes memory consensusStateBytes // serialized with pb
    ) public override view returns (bool) {
        ClientState.Data memory clientState;
        ConsensusState.Data memory consensusState;
        bool found;

        (clientState, found) = getClientState(host, clientId);
        if (!found) {
            return false;
        }
        if (!validateArgs(clientState, height, prefix, proof)) {
            return false;
        }
        (consensusState, found) = getConsensusState(host, clientId, height);
        if (!found) {
            return false;
        }
        bytes[] memory path = applyPrefix(prefix, Identifier.consensusStateKey(counterpartyClientIdentifier, consensusHeight));
        return verifyMembership(clientState.proof_specs, proof, consensusState.root.hash, path, consensusStateBytes);
    }

    function validateArgs(ClientState.Data memory cs, Height.Data memory height, bytes memory prefix, bytes memory proof) internal pure returns (bool) {
        if (cs.latest_height.lt(height)) {
            return false;
        } else if (prefix.length == 0) {
            return false;
        } else if (proof.length == 0) {
            return false;
        }
        return true;
    }

    function validateDelayPeriod(IBCHost host, string memory clientId, Height.Data memory height, uint64 delayPeriodTime, uint64 delayPeriodBlocks) private view returns (bool) {
        uint64 currentTime = uint64(block.timestamp * 1000 * 1000 * 1000);
        uint64 validTime = mustGetProcessedTime(host, clientId, height) + delayPeriodTime;
        if (currentTime < validTime) {
            return false;
        }
        uint64 currentHeight = uint64(block.number);
        uint64 validHeight = mustGetProcessedHeight(host, clientId, height) + delayPeriodBlocks;
        if (currentHeight < validHeight) {
            return false;
        }
        return true;
    }

    // NOTE: this is a workaround to avoid the error `Stack too deep` in caller side
    function mustGetClientState(IBCHost host, string memory clientId) internal view returns (ClientState.Data memory) {
        (ClientState.Data memory clientState, bool found) = getClientState(host, clientId);
        require(found, "LC: client state not found");
        return clientState;
    }

    // NOTE: this is a workaround to avoid the error `Stack too deep` in caller side
    function mustGetConsensusState(IBCHost host, string memory clientId, Height.Data memory height) internal view returns (ConsensusState.Data memory) {
        (ConsensusState.Data memory consensusState, bool found) = getConsensusState(host, clientId, height);
        require(found, "LC: consensus state not found");
        return consensusState;
    }

    function mustGetProcessedTime(IBCHost host, string memory clientId, Height.Data memory height) internal view returns (uint64) {
        (uint256 processedTime, bool found) = host.getProcessedTime(clientId, height);
        require(found, "LC: processed time not found");
        return uint64(processedTime) * 1000 * 1000 * 1000;
    }

    function mustGetProcessedHeight(IBCHost host, string memory clientId, Height.Data memory height) internal view returns (uint64) {
        (uint256 processedHeight, bool found) = host.getProcessedHeight(clientId, height);
        require(found, "LC: processed height not found");
        return uint64(processedHeight);
    }

    function getClientState(IBCHost host, string memory clientId) public view returns (ClientState.Data memory clientState, bool found) {
        bytes memory clientStateBytes;
        (clientStateBytes, found) = host.getClientState(clientId);
        if (!found) {
            return (clientState, false);
        }
        return (ClientState.decode(Any.decode(clientStateBytes).value), true);
    }

    function getConsensusState(IBCHost host, string memory clientId, Height.Data memory height) public view returns (ConsensusState.Data memory consensusState, bool found) {
        bytes memory consensusStateBytes;
        (consensusStateBytes, found) = host.getConsensusState(clientId, height);
        if (!found) {
            return (consensusState, false);
        }
        return (ConsensusState.decode(Any.decode(consensusStateBytes).value), true);
    }

    function marshalClientState(ClientState.Data memory clientState) internal pure returns (bytes memory) {
        Any.Data memory anyClientState;
        anyClientState.type_url = "/ibc.lightclients.tendermint.v1.ClientState";
        anyClientState.value = ClientState.encode(clientState);
        return Any.encode(anyClientState);
    }

    function marshalConsensusState(ConsensusState.Data memory consensusState) internal pure returns (bytes memory) {
        Any.Data memory anyConsensusState;
        anyConsensusState.type_url = "/ibc.lightclients.tendermint.v1.ConsensusState";
        anyConsensusState.value = ConsensusState.encode(consensusState);
        return Any.encode(anyConsensusState);
    }

    function unmarshalClientState(bytes memory bz) internal view returns (ClientState.Data memory clientState, bool ok) {
        Any.Data memory anyClientState = Any.decode(bz);
        if (keccak256(abi.encodePacked(anyClientState.type_url)) != _pts.clientState) {
            return (clientState, false);
        }
        return (ClientState.decode(anyClientState.value), true);
    }

    function unmarshalConsensusState(bytes memory bz) internal view returns (ConsensusState.Data memory consensusState, bool ok) {
        Any.Data memory anyConsensusState = Any.decode(bz);
        if (keccak256(abi.encodePacked(anyConsensusState.type_url)) != _pts.consensusState) {
            return (consensusState, false);
        }
        return (ConsensusState.decode(anyConsensusState.value), true);
    }

    function unmarshalTmHeader(bytes memory bz) internal view returns (TmHeader.Data memory header, bool ok) {
        Any.Data memory anyHeader = Any.decode(bz);
        if (keccak256(abi.encodePacked(anyHeader.type_url)) != _pts.tmHeader) {
            return (header, false);
        }
        return (TmHeader.decode(anyHeader.value), true);
    }

    function getTmChildOrder() internal pure returns (int32[] memory) {
        int32[] memory childOrder = new int32[](2);
        childOrder[0] = 0;
        childOrder[1] = 1;

        return childOrder;
    }

    function verifyMembership(
        ProofSpec.Data[] memory proofSpecs,
        bytes memory proof,
        bytes memory root,
        bytes[] memory keys,
        bytes memory expectedValue
    ) internal view returns (bool) {
        MerkleProof.Data memory merkleProof = MerkleProof.decode(proof);
        // proof cannot be empty
        if (merkleProof.proofs.length == 0) {
            return false;
        }
        if (proofSpecs.length != merkleProof.proofs.length) {
            return false;
        }
        if (keys.length < proofSpecs.length) {
            return false;
        }

        bytes memory subRoot;
        bytes memory value = expectedValue;
        for (uint i = 0; i < proofSpecs.length; i++) {
            bool ok;
            (subRoot, ok) = calculateRoot(merkleProof.proofs[i]);
            if (!ok) {
                return false;
            }
            Ics23.VerifyMembershipError vCode = Ics23.verifyMembership(proofSpecs[i], subRoot, merkleProof.proofs[i], keys[keys.length - 1 - i], value);
            if (vCode != Ics23.VerifyMembershipError.None) {
                return false;
            }
            value = subRoot;
        }
        return keccak256(root) == keccak256(subRoot);
    }

    function calculateRoot(
        CommitmentProof.Data memory proof
    ) internal pure returns (bytes memory, bool) {
        (bytes memory res, Proof.CalculateRootError eCode) = Proof.calculateRoot(proof);
        return (res, eCode == Proof.CalculateRootError.None);
    }

    function applyPrefix(
        bytes memory prefix,
        bytes memory path
    ) internal pure returns (bytes[] memory) {
        bytes[] memory arr = new bytes[](2);
        arr[0] = prefix;
        arr[1] = path;
        return arr;
    }
}
