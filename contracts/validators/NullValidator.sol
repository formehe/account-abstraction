// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../interfaces/IValidator.sol";
/**
    The format of action:|userID|Nonce|Target|Action|
    The format of proof:|sender|
*/

contract NullValidator is IValidator{
    function verify(
        uint256        /*material*/,
        bytes32        /*msgHash*/,
        bytes          calldata /*signature*/
    ) external pure override returns (bool) {
        return true;
    }

    function getKindID() external pure override returns (bytes32) {
        return keccak256("NullValidator");
    }
}