// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PaxiomRootRegistry
/// @notice Minimal, immutable, ownerless/adminless Base Mainnet anchor for Paxiom v0.4
///         block root attestations (paxiom.root.v0). Callers may append an ERC-8021
///         Builder Code suffix (`0x80218021802180218021802180218021`) to any call;
///         Solidity ABI decoding ignores trailing calldata bytes automatically.
contract PaxiomRootRegistry {
    struct RootRecord {
        bytes32 blockHash;
        bytes32 stateRoot;
        bytes32 receiptsRoot;
        uint64 anchoredAt;
        uint8 finalityTier; // 1 = l2-sequencer-attested, 2 = l1-sync-finalized, 3 = bft-finalized
    }

    address public immutable attester;
    uint256 public latestAnchoredBlock;
    mapping(uint256 => RootRecord) public rootsByBlock;

    event RootAnchored(
        uint256 indexed blockNumber,
        bytes32 indexed receiptsRoot,
        bytes32 indexed stateRoot,
        bytes32 blockHash,
        uint8 finalityTier,
        address attester
    );

    error UnauthorizedAttester();
    error ZeroRoot();

    constructor(address initialAttester) {
        if (initialAttester == address(0)) revert UnauthorizedAttester();
        attester = initialAttester;
    }

    function anchorBlockRoots(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot,
        bytes32 receiptsRoot,
        uint8 finalityTier
    ) external {
        if (msg.sender != attester) revert UnauthorizedAttester();
        if (blockHash == bytes32(0) || (stateRoot == bytes32(0) && receiptsRoot == bytes32(0))) {
            revert ZeroRoot();
        }

        rootsByBlock[blockNumber] = RootRecord({
            blockHash: blockHash,
            stateRoot: stateRoot,
            receiptsRoot: receiptsRoot,
            anchoredAt: uint64(block.timestamp),
            finalityTier: finalityTier
        });

        if (blockNumber > latestAnchoredBlock) {
            latestAnchoredBlock = blockNumber;
        }

        emit RootAnchored(blockNumber, receiptsRoot, stateRoot, blockHash, finalityTier, msg.sender);
    }
}
