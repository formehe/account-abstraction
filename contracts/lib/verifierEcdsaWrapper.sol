// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity ^0.8.12;

import "./verifierEcdsa.sol";
import "../interfaces/IVerifier.sol";
contract VerifierEcdsaWrapper is VerifierEcdsa, IVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input
    ) public view override returns (bool r) {
        require(input.length == 3, "invalid parameter");
        uint256[3] memory proof;
        for (uint256 i = 0; i < input.length; i++) {
            proof[i] = input[i];
        }
        return super.verifyProof(a, b, c, proof);
    }
}
