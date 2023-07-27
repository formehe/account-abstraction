// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "./WalletAccount.sol";

/**
 * A sample factory contract for SimpleAccount
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 * The factory's createAccount returns the target account address even if it is already installed.
 * This way, the entryPoint.getSenderAddress() can be called either before or after the account is created.
 */
contract WalletAccountFactory is AccessControl, IWalletAccountFactory{
    WalletAccount public immutable accountImplementation;
    mapping(uint256 => IValidator)  public validators;
    //keccak256("TraditionalEcdsaValidator")
    uint256 public rootValidatorKindId = 0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa;
    //keccak256("OWNER.ROLE");
    bytes32 constant OWNER_ROLE = 0x0eddb5b75855602b7383774e54b0f5908801044896417c7278d8b72cd62555b6;
    //keccak256("ADMIN.ROLE");
    bytes32 constant ADMIN_ROLE = 0xa8a2e59f1084c6f79901039dbbd994963a70b36ee6aff99b7e17b2ef4f0e395c;
    
    event ValidatorBound(uint256 id, address validator);

    constructor(IEntryPoint _entryPoint, IValidator _validator, address _owner) {
        accountImplementation = new WalletAccount(_entryPoint);

        require(_owner != address(0), "invalid owner");
        require(uint256(_validator.getKindID()) == rootValidatorKindId, "validator can not used as root validator");
        require(address(validators[rootValidatorKindId]) == address(0), "validator is existed");
        
        validators[rootValidatorKindId] = _validator;
        _setRoleAdmin(ADMIN_ROLE, OWNER_ROLE);
        _grantRole(OWNER_ROLE,_owner);
        _grantRole(ADMIN_ROLE,msg.sender);
    }

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
     */
    function createAccount(
        address        owner, 
        uint256        salt
    ) public returns (WalletAccount ret) {
        address addr = getAddress(owner, salt);
        uint codeSize = addr.code.length;
        if (codeSize > 0) {
            return WalletAccount(payable(addr));
        }
        ret = WalletAccount(payable(new ERC1967Proxy{salt : bytes32(salt)}(
                address(accountImplementation),
                abi.encodeCall(WalletAccount.initialize, (owner, address(this), rootValidatorKindId))
            )));
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(address owner,uint256 salt) public view returns (address) {
        return Create2.computeAddress(bytes32(salt), keccak256(abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(
                    address(accountImplementation),
                    abi.encodeCall(WalletAccount.initialize, (owner, address(this), rootValidatorKindId))
                )
            )));
    }

    function bindValidator(IValidator _validator) external override onlyRole(ADMIN_ROLE) {
        //require(address(validators[uint256(_validator.getID())]) == address(0), "validator is exist");
        validators[uint256(_validator.getKindID())] = _validator;
        emit ValidatorBound(uint256(_validator.getKindID()), address(_validator));
    }

    function getValidator(uint256 validatorKindID) external view override returns (address) {
        require(address(validators[validatorKindID]) != address(0), "validator is not existed");
        return address(validators[validatorKindID]);
    }

    function getRootValidatorKindId() external view override returns (uint256) {
        return rootValidatorKindId;
    }

    function renounceRole(bytes32 /*role*/, address /*account*/) public pure override {
        require(false, "not support");
    }
}
