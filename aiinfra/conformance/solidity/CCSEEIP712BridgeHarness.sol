// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.20 <0.9.0;

import "./CCSEEIP712Bridge.sol";

/// @notice Stateless conformance wrapper for CCSEEIP712BridgeV1.
/// @dev This contract exists only to execute the internal pure bridge library
///      in an EVM. Production consumers must use CCSEEIP712VerifierV1 and must
///      derive their domain and financial fields from governed state.
contract CCSEEIP712BridgeHarnessV1 {
    function domainSeparatorPure(
        string calldata protocolName,
        string calldata protocolVersion,
        uint256 chainId,
        address verifyingContract,
        bytes32 genesisHash
    ) external pure returns (bytes32) {
        return CCSEEIP712BridgeV1.domainSeparator(
            protocolName, protocolVersion, chainId, verifyingContract, genesisHash
        );
    }

    function authorizationStructHashPure(
        CCSEEIP712BridgeV1.FinancialAuthorization calldata authorization
    ) external pure returns (bytes32) {
        return CCSEEIP712BridgeV1.authorizationStructHash(authorization);
    }

    function typedDataDigestPure(
        string calldata protocolName,
        string calldata protocolVersion,
        uint256 chainId,
        address verifyingContract,
        bytes32 genesisHash,
        CCSEEIP712BridgeV1.FinancialAuthorization calldata authorization
    ) external pure returns (bytes32) {
        return CCSEEIP712BridgeV1.typedDataDigest(
            protocolName,
            protocolVersion,
            chainId,
            verifyingContract,
            genesisHash,
            authorization
        );
    }

    /// @notice Executes every fail-closed pure check used by the bridge profile.
    /// @return digest The EIP-712 digest that was verified.
    /// @return recovered The signer recovered by the EVM precompile.
    function verifyPure(
        string calldata protocolName,
        string calldata protocolVersion,
        uint256 chainId,
        address verifyingContract,
        bytes32 genesisHash,
        CCSEEIP712BridgeV1.FinancialAuthorization calldata authorization,
        bytes calldata signature,
        address expectedSigner,
        uint64 currentUnix
    ) external pure returns (bytes32 digest, address recovered) {
        CCSEEIP712BridgeV1.validateAuthorization(authorization, currentUnix, true);
        digest = CCSEEIP712BridgeV1.typedDataDigest(
            protocolName,
            protocolVersion,
            chainId,
            verifyingContract,
            genesisHash,
            authorization
        );
        CCSEEIP712BridgeV1.verifySigner(digest, signature, expectedSigner);
        // Return the recovered value as conformance evidence. The production
        // verifier only needs the preceding fail-closed verifySigner call.
        recovered = CCSEEIP712BridgeV1.recoverSigner(digest, signature);
    }
}
