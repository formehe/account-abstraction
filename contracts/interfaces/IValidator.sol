// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

interface IValidator {
    function verify(
        uint256        material,
        bytes32        msgHash,
        bytes          calldata signature
    ) external view returns (bool r);

    function getKindID() external pure returns (bytes32);
}
