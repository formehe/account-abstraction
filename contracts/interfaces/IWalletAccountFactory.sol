// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "./IValidator.sol";

interface IWalletAccountFactory {
    function bindValidator(IValidator _validator) external;
    function getValidator(uint256 validatorKindID) external view returns (address);
    function getRootValidatorKindId() external view returns(uint256);
}