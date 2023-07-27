// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import "../../core/BaseAccount.sol";
import "../callback/TokenCallbackHandler.sol";
import "../../interfaces/IWalletAccountFactory.sol";

/**
  * minimal account.
  *  this is sample minimal account.
  *  has execute, eth handling methods
  *  has a single signer that can send requests through the entryPoint.
  */
contract WalletAccount is BaseAccount, TokenCallbackHandler, UUPSUpgradeable, Initializable {
    using ECDSA for bytes32;

    address public owner;

    IEntryPoint private immutable _entryPoint;
    
    IWalletAccountFactory public factory;
    mapping(uint256 => uint256) public materials;
    mapping(uint256 => uint256) public granted;
    mapping(uint256 => uint256[]) private granter;

    event WalletAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);
    event ValidatorGranted(uint256 validatorKindId, uint256 grantedValidatorKindId);
    event ValidatorRevoked(uint256 validatorKindId, uint256 revokedValidatorKindId);

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }


    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    function _onlyOwner() internal view {
        //directly from EOA owner, or through the account itself (which gets redirected through execute())
        require(msg.sender == owner || msg.sender == address(this), "only owner");
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transactions
     * @dev to reduce gas consumption for trivial case (no value), use a zero-length array to mean zero value
     */
    function executeBatch(address[] calldata dest, uint256[] calldata value, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length && (value.length == 0 || value.length == func.length), "wrong array lengths");
        if (value.length == 0) {
            for (uint256 i = 0; i < dest.length; i++) {
                _call(dest[i], 0, func[i]);
            }
        } else {
            for (uint256 i = 0; i < dest.length; i++) {
                _call(dest[i], value[i], func[i]);
            }
        }
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
      * the implementation by calling `upgradeTo()`
     */
    function initialize(address anOwner, address _factory, uint256 rootValidatorKindId) public virtual initializer {
        factory = IWalletAccountFactory(_factory);
        address validatorAddress = factory.getValidator(rootValidatorKindId);
        require(validatorAddress.code.length > 0, "validator is not exist");
        materials[rootValidatorKindId] = uint256(uint160(anOwner));
        granted[rootValidatorKindId] = rootValidatorKindId;
        _initialize(anOwner);
    }

    function _initialize(address anOwner) internal virtual {
        owner = anOwner;
        emit WalletAccountInitialized(_entryPoint, owner);
    }

    // Require the function call went through EntryPoint or owner
    function _requireFromEntryPointOrOwner() internal view {
        require(msg.sender == address(entryPoint()) || msg.sender == owner, "account: not Owner or EntryPoint");
    }

    /// implement template method of BaseAccount
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
    internal override virtual returns (uint256 validationData) {
        (uint256 validatorKindId, bytes memory signature) = abi.decode(userOp.signature, (uint256, bytes));
        
        require(granted[validatorKindId] != 0, "validator has not been granted");
        require(materials[validatorKindId] != 0, "invalid material");
        IValidator validator = IValidator(factory.getValidator(validatorKindId));
        require(validator.verify(materials[validatorKindId], userOpHash, signature), "fail to validate");
        // if (!validator.verify(materials[validatorKindId], userOpHash, signature)) {
        //     return SIG_VALIDATION_FAILED;
        // }
        return 0;
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value : value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value : msg.value}(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlyOwner();
    }

    function changeMaterial(
        uint256        validatorKindId,
        uint256        newMaterial
    ) external {
        // _requireFromEntryPointOrOwner();
        require(msg.sender == address(this), "only myself");
        require(validatorKindId != factory.getRootValidatorKindId(), "root validator can not modify");
        require(granted[validatorKindId] != 0, "validator has not been granted");

        address validatorAddr = factory.getValidator(validatorKindId);
        require(validatorAddr.code.length > 0, "validator is not existed");
        materials[validatorKindId] = newMaterial;
    }

    function grant(
        uint256        validatorKindId,
        uint256        grantedValidatorKindId,
        uint256        grantedMaterial
    ) external {
        // _requireFromEntryPointOrOwner();
        require(msg.sender == address(this), "only myself");
        require(validatorKindId != grantedValidatorKindId, "validator should be different");
        require(granted[validatorKindId] != 0, "validator has not been granted");
        require(granted[grantedValidatorKindId] == 0, "validator has been granted");
    
        address validatorAddr = factory.getValidator(validatorKindId);
        require(validatorAddr.code.length > 0, "validator is not existed");

        validatorAddr = factory.getValidator(grantedValidatorKindId);
        require(validatorAddr.code.length > 0, "validator is not existed");

        materials[grantedValidatorKindId] = grantedMaterial;
        granted[grantedValidatorKindId] = validatorKindId;
        granter[validatorKindId].push(grantedValidatorKindId);
        emit ValidatorGranted(validatorKindId, grantedValidatorKindId);
    }

    function revoke(
        uint256        validatorKindId,
        uint256        revokedValidatorKindId
    ) external {
        // _requireFromEntryPointOrOwner();
        require(msg.sender == address(this), "only myself");
        require(validatorKindId != revokedValidatorKindId, "validator should be different");
        require(granted[validatorKindId] != 0, "validator has not been granted");
        require(granted[revokedValidatorKindId] == validatorKindId, "validator has been revoked");

        address validatorAddr = factory.getValidator(validatorKindId);
        require(validatorAddr.code.length > 0, "validator is not existed");

        delete materials[revokedValidatorKindId];
        delete granted[revokedValidatorKindId];
        for (uint256 i = 0; i < granter[validatorKindId].length; i++) {
            if (granter[validatorKindId][i] == revokedValidatorKindId) {
                granter[validatorKindId][i] = granter[validatorKindId][granter[validatorKindId].length - 1];
                granter[validatorKindId].pop();
                break;
            }
        }

        //may be spent large gas
        _clean(revokedValidatorKindId);
        emit ValidatorRevoked(validatorKindId, revokedValidatorKindId);
    }

    function _clean(uint256 revoked) internal{
        for (uint256 i = 0; i < granter[revoked].length; i++) {
            _clean(granter[revoked][i]);
            delete materials[granter[revoked][i]];
            delete granted[granter[revoked][i]];
            delete granter[revoked];
        }
    }
}