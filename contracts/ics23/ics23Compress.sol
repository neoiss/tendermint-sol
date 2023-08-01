// Source: https://github.com/ChorusOne/ics23/tree/giulio/solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.9;

import {InnerOp, ExistenceProof, NonExistenceProof, CommitmentProof, CompressedBatchEntry, CompressedBatchProof, CompressedExistenceProof, BatchEntry, BatchProof} from "../proto/proofs.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

library Compress {
    /**
      @notice will return a BatchProof if the input is CompressedBatchProof. Otherwise it will return the input.
      This is safe to call multiple times (idempotent)
    */
    function decompress(
        CommitmentProof.Data memory proof
    ) internal pure returns(CommitmentProof.Data memory, DecompressEntryError) {
        //CompressedBatchProof.isNil() does not work
        if (CompressedBatchProof._empty(proof.compressed) == true){
            revert("CompressedBatchProof is empty");
            return (proof, DecompressEntryError.None);
        }
        (BatchEntry.Data[] memory entries, DecompressEntryError erCode) = decompress(proof.compressed);
        if (erCode != DecompressEntryError.None) return (CommitmentProof.nil(), erCode);
        CommitmentProof.Data memory retVal;
        retVal.exist = ExistenceProof.nil();
        retVal.nonexist = NonExistenceProof.nil();
        retVal.compressed = CompressedBatchProof.nil();
        retVal.batch.entries = entries;
        return (retVal, DecompressEntryError.None);
    }

    function decompress(
        CompressedBatchProof.Data memory proof
    ) private pure returns(BatchEntry.Data[] memory, DecompressEntryError) {
        BatchEntry.Data[] memory entries = new BatchEntry.Data[](proof.entries.length);
        for(uint i = 0; i < proof.entries.length; i++) {
            (BatchEntry.Data memory entry, DecompressEntryError erCode) = decompressEntry(proof.entries[i], proof.lookup_inners);
            if (erCode != DecompressEntryError.None) return (entries, erCode);
            entries[i] = entry;
        }
        return (entries, DecompressEntryError.None);
    }

    enum DecompressEntryError{
        None,
        ExistDecompress,
        LeftDecompress,
        RightDecompress
    }
    function decompressEntry(
        CompressedBatchEntry.Data memory entry,
        InnerOp.Data[] memory lookup
    ) private pure returns(BatchEntry.Data memory, DecompressEntryError) {
        //CompressedExistenceProof.isNil does not work
        if (CompressedExistenceProof._empty(entry.exist) == false) {
            (ExistenceProof.Data memory exist, DecompressExistError existErCode) = decompressExist(entry.exist, lookup);
            if (existErCode != DecompressExistError.None) return(BatchEntry.nil(), DecompressEntryError.ExistDecompress);
            return (BatchEntry.Data({
                exist: exist,
                nonexist: NonExistenceProof.nil()
            }), DecompressEntryError.None);
        }
        (ExistenceProof.Data memory left, DecompressExistError leftErCode) = decompressExist(entry.nonexist.left, lookup);
        if (leftErCode != DecompressExistError.None) return(BatchEntry.nil(), DecompressEntryError.LeftDecompress);
        (ExistenceProof.Data memory right, DecompressExistError rightErCode) = decompressExist(entry.nonexist.right, lookup);
        if (rightErCode != DecompressExistError.None) return(BatchEntry.nil(), DecompressEntryError.RightDecompress);
        return (BatchEntry.Data({
            exist: ExistenceProof.nil(),
            nonexist: NonExistenceProof.Data({
                key: entry.nonexist.key,
                left: left,
                right: right
            })
        }), DecompressEntryError.None);
    }

    enum DecompressExistError{
        None,
        PathLessThanZero,
        StepGreaterOrEqualToLength
    }
    function decompressExist(
        CompressedExistenceProof.Data memory proof,
        InnerOp.Data[] memory lookup
    ) private pure returns(ExistenceProof.Data memory, DecompressExistError) {
        if (CompressedExistenceProof._empty(proof)) {
            return (ExistenceProof.nil(), DecompressExistError.None);
        }
        ExistenceProof.Data memory decoProof = ExistenceProof.Data({
            key: proof.key,
            value: proof.value,
            leaf: proof.leaf,
            path : new InnerOp.Data[](proof.path.length)
        });
        for (uint i = 0; i < proof.path.length; i++) {
            //require(proof.path[i] >= 0); // dev: proof.path < 0
            if (proof.path[i] < 0) return (ExistenceProof.nil(), DecompressExistError.PathLessThanZero);
            uint step = SafeCast.toUint256(proof.path[i]);
            //require(step < lookup.length); // dev: step >= lookup.length
            if (step >= lookup.length) return (ExistenceProof.nil(), DecompressExistError.StepGreaterOrEqualToLength);
            decoProof.path[i] = lookup[step];
        }
        return (decoProof, DecompressExistError.None);
    }
}
