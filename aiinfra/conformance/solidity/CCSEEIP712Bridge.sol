// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.20 <0.9.0;

/// @notice Solidity-facing authorization profile for a verified CCSE-v1 record.
/// @dev This profile does not verify the CCSE Ed25519 signature. An authorized
///      bridge signer signs this EIP-712 authorization only after the complete
///      CCSE record has passed off-chain verification and policy admission.
library CCSEEIP712BridgeV1 {
    bytes32 internal constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
    );

    bytes32 internal constant AUTHORIZATION_TYPEHASH = keccak256(
        "CPHFinancialAuthorizationV1(bytes32 ccseRecordDigest,bytes32 financialOperationId,bytes32 leaseId,bytes32 receiptId,bytes32 settlementId,bytes32 assetId,address payer,address payee,uint256 amountSmallestUnit,uint64 expectedGeneration,uint64 validAfterUnix,uint64 validBeforeUnix)"
    );

    // secp256k1n / 2. Rejecting larger s values prevents signature malleability.
    uint256 private constant SECP256K1_HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct FinancialAuthorization {
        bytes32 ccseRecordDigest;
        bytes32 financialOperationId;
        bytes32 leaseId;
        bytes32 receiptId;
        bytes32 settlementId;
        bytes32 assetId;
        address payer;
        address payee;
        uint256 amountSmallestUnit;
        uint64 expectedGeneration;
        uint64 validAfterUnix;
        uint64 validBeforeUnix;
    }

    error InvalidDomain();
    error InvalidAuthorization();
    error InvalidSignature();
    error UnexpectedSigner(address recovered, address expected);

    function domainSeparator(
        string memory protocolName,
        string memory protocolVersion,
        uint256 chainId,
        address verifyingContract,
        bytes32 genesisHash
    ) internal pure returns (bytes32) {
        if (
            bytes(protocolName).length == 0 || bytes(protocolVersion).length == 0
                || chainId == 0 || verifyingContract == address(0) || genesisHash == bytes32(0)
        ) {
            revert InvalidDomain();
        }
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(protocolName)),
                keccak256(bytes(protocolVersion)),
                chainId,
                verifyingContract,
                genesisHash
            )
        );
    }

    function authorizationStructHash(FinancialAuthorization memory authorization)
        internal
        pure
        returns (bytes32)
    {
        validateAuthorization(authorization, 0, false);
        return keccak256(
            abi.encode(
                AUTHORIZATION_TYPEHASH,
                authorization.ccseRecordDigest,
                authorization.financialOperationId,
                authorization.leaseId,
                authorization.receiptId,
                authorization.settlementId,
                authorization.assetId,
                authorization.payer,
                authorization.payee,
                authorization.amountSmallestUnit,
                authorization.expectedGeneration,
                authorization.validAfterUnix,
                authorization.validBeforeUnix
            )
        );
    }

    function typedDataDigest(
        string memory protocolName,
        string memory protocolVersion,
        uint256 chainId,
        address verifyingContract,
        bytes32 genesisHash,
        FinancialAuthorization memory authorization
    ) internal pure returns (bytes32) {
        bytes32 separator = domainSeparator(
            protocolName, protocolVersion, chainId, verifyingContract, genesisHash
        );
        return keccak256(
            abi.encodePacked("\x19\x01", separator, authorizationStructHash(authorization))
        );
    }

    function recoverSigner(bytes32 digest, bytes memory signature)
        internal
        pure
        returns (address signer)
    {
        if (signature.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (uint256(r) == 0 || uint256(s) == 0 || uint256(s) > SECP256K1_HALF_N) {
            revert InvalidSignature();
        }
        if (v != 27 && v != 28) revert InvalidSignature();

        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
    }

    function verifySigner(bytes32 digest, bytes memory signature, address expectedSigner)
        internal
        pure
    {
        if (expectedSigner == address(0)) revert InvalidSignature();
        address recovered = recoverSigner(digest, signature);
        if (recovered != expectedSigner) revert UnexpectedSigner(recovered, expectedSigner);
    }

    /// @dev Set enforceTime to false only while computing deterministic vectors.
    function validateAuthorization(
        FinancialAuthorization memory authorization,
        uint64 currentUnix,
        bool enforceTime
    ) internal pure {
        if (
            authorization.ccseRecordDigest == bytes32(0)
                || authorization.financialOperationId == bytes32(0)
                || authorization.leaseId == bytes32(0) || authorization.receiptId == bytes32(0)
                || authorization.settlementId == bytes32(0) || authorization.assetId == bytes32(0)
                || authorization.payer == address(0) || authorization.payee == address(0)
                || authorization.amountSmallestUnit == 0
                || authorization.validBeforeUnix <= authorization.validAfterUnix
        ) {
            revert InvalidAuthorization();
        }
        if (
            enforceTime
                && (currentUnix < authorization.validAfterUnix
                    || currentUnix >= authorization.validBeforeUnix)
        ) {
            revert InvalidAuthorization();
        }
    }
}

/// @notice Domain-binding base for a future financial consumer contract.
/// @dev A state-changing consumer must additionally authorize `expectedSigner`
///      by role/policy and atomically consume `financialOperationId` exactly once.
abstract contract CCSEEIP712VerifierV1 {
    string private _ccseProtocolName;
    string private _ccseProtocolVersion;
    bytes32 private immutable _ccseGenesisHash;

    constructor(
        string memory protocolName,
        string memory protocolVersion,
        bytes32 genesisHash
    ) {
        if (
            bytes(protocolName).length == 0 || bytes(protocolVersion).length == 0
                || genesisHash == bytes32(0)
        ) {
            revert CCSEEIP712BridgeV1.InvalidDomain();
        }
        _ccseProtocolName = protocolName;
        _ccseProtocolVersion = protocolVersion;
        _ccseGenesisHash = genesisHash;
    }

    function ccseEIP712DomainSeparatorV1() public view returns (bytes32) {
        return CCSEEIP712BridgeV1.domainSeparator(
            _ccseProtocolName,
            _ccseProtocolVersion,
            block.chainid,
            address(this),
            _ccseGenesisHash
        );
    }

    function ccseFinancialAuthorizationDigestV1(
        CCSEEIP712BridgeV1.FinancialAuthorization calldata authorization
    ) public view returns (bytes32) {
        if (block.timestamp > type(uint64).max) {
            revert CCSEEIP712BridgeV1.InvalidAuthorization();
        }
        CCSEEIP712BridgeV1.validateAuthorization(
            authorization, uint64(block.timestamp), true
        );
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                ccseEIP712DomainSeparatorV1(),
                CCSEEIP712BridgeV1.authorizationStructHash(authorization)
            )
        );
    }

    function _verifyCCSEFinancialAuthorizationV1(
        CCSEEIP712BridgeV1.FinancialAuthorization calldata authorization,
        bytes calldata signature,
        address expectedSigner
    ) internal view returns (bytes32 digest) {
        digest = ccseFinancialAuthorizationDigestV1(authorization);
        CCSEEIP712BridgeV1.verifySigner(digest, signature, expectedSigner);
    }
}
