// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "../interfaces/IValidator.sol";
import "../interfaces/IVerifier.sol";
import "../lib/Poseidon.sol";
/**
    The format of action:|userID|Nonce|Target|Action|
    The format of proof:|inputs|a|b|c|
*/

contract ZkEcdsaValidator is IValidator, Initializable{
    IVerifier public verifier;

    function initialize(
        address _verifier
    ) public initializer {
        verifier = IVerifier(_verifier);
    }

    function verify(
        uint256        material,
        bytes32        msgHash,
        bytes          calldata signature
    ) external view override returns (bool) {
        (uint256[] memory inputs, uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) 
                        = abi.decode(signature, (uint256[],uint256[2],uint256[2][2],uint256[2]));
        if (inputs.length != 3) {
            return false;
        }

        if (inputs[2] != PoseidonUnit1L.poseidon([uint256(msgHash)])) {
            return false;
        }

        bytes memory knowledge = abi.encode(inputs[0], inputs[1]);
        if (material != uint256(keccak256(knowledge))){
            return false;
        }

        return verifier.verifyProof(a, b, c, inputs);
    }

    function getKindID() external pure override returns (bytes32) {
        return keccak256("ZkEcdsaValidator");
    }
}