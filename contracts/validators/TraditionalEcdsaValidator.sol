// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../interfaces/IValidator.sol";

/**
    The format of action:|userID|Nonce|Target|Action|
    The format of proof: |sender account|v|r|s|
*/

contract TraditionalEcdsaValidator is IValidator{
    using ECDSA for bytes32;

    function verify(
        uint256        material,
        bytes32        msgHash,
        bytes          calldata signature
    ) external pure override returns (bool) {
        bytes32 hasher = msgHash.toEthSignedMessageHash();
        address recoveredOwner = hasher.recover(signature);
        if (recoveredOwner == address(0)) {
            return false;
        }

        if (material != uint256(uint160(recoveredOwner))) {
            return false;
        }

        return true;
    }

    function getKindID() external pure override returns (bytes32) {
        return keccak256("TraditionalEcdsaValidator");
    }
}