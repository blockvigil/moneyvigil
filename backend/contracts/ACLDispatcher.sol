pragma solidity >=0.5.1 <0.7.0;
pragma experimental ABIEncoderV2;
/**
 * @title Roles
 * @dev Library for managing addresses assigned to a Role.
 */
library Roles {
    struct Role {
        mapping (address => bool) bearer;
    }

    /**
     * @dev Give an account access to this role.
     */
    function add(Role storage role, address account) internal {
        require(!has(role, account), "Roles: account already has role");
        role.bearer[account] = true;
    }

    /**
     * @dev Remove an account's access to this role.
     */
    function remove(Role storage role, address account) internal {
        require(has(role, account), "Roles: account does not have role");
        role.bearer[account] = false;
    }

    /**
     * @dev Check if an account has this role.
     * @return bool
     */
    function has(Role storage role, address account) internal view returns (bool) {
        require(account != address(0), "Roles: account is the zero address");
        return role.bearer[account];
    }
}

contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor () internal {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }
    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view returns (address) {
        return _owner;
    }
    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(isOwner(), "Ownable: caller is not the owner");
        _;
    }
    /**
     * @dev Returns true if the caller is the current owner.
     */
    function isOwner() public view returns (bool) {
        return msg.sender == _owner;
    }
    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * > Note: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }
    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public onlyOwner {
        _transferOwnership(newOwner);
    }
    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     */
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

// compound wrapped ERC20 interface
interface CompoundErc20 {
    function mint(uint256) external returns (uint256);

    function exchangeRateCurrent() external returns (uint256);

    function supplyRatePerBlock() external returns (uint256);

    function redeem(uint) external returns (uint);

    function redeemUnderlying(uint) external returns (uint);
}

// standard ERC20 interface
interface Erc20 {
    function approve(address, uint256) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}


contract ACLDispatchHub is Ownable() {

    address public daiContractAddress = 0xdc31Ee1784292379Fbb2964b3B9C4124D8F89C60;
    address public compoundDaiContractAddress = 0x822397d9a55d0fefd20F5c4bCaB33C5F65bd28Eb;
    bytes32 internal companyUUIDHash;
    uint256 constant chainId = 5;
    event ACLDeployed(bytes32 companyUUIDHash, uint256 chainId);
    constructor (bytes32 _companyUUIDHash, uint256 _chainId) public{
        companyUUIDHash = _companyUUIDHash;
        emit ACLDeployed(companyUUIDHash, chainId);
    }
    // Bill Approval: EIP-712 boilerplate begins
    //address constant verifyingContract = address(0);
    // bytes32 constant salt = 0x50a70992feaf23fcd93d131d01da892b7fe5aa48a909d0ec945e1d9b3dd7d7bb;
    string private constant EIP712_DOMAIN  = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    string private constant MESSAGE_ENTITY_TYPE = "MessageEntity(string actionType,address group,address member,uint256 amount,string bill,uint256 timestamp)";

    struct MessageEntity {
        string actionType;
        address group;
        address member;
        uint256 amount;
        string bill;
        uint256 timestamp;
    }

    // type hashes. Hash of the following strings:
    // 1. EIP721 Domain separator.
    // 2. string describing settlement type (redundantly includes enclosed signatureMessage type description)
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(bytes(EIP712_DOMAIN));
    bytes32 private DOMAIN_SEPARATOR = keccak256(abi.encode(
        EIP712_DOMAIN_TYPEHASH,
        keccak256("ACLDispatcher"),
        keccak256("1"),
        // 8995,
        chainId,
        0x8c1eD7e19abAa9f23c476dA86Dc1577F1Ef401f5
    ));
    bytes32 private constant MESSAGE_ENTITY_TYPEHASH = keccak256(bytes(MESSAGE_ENTITY_TYPE));

    // hash representation of the actual struct objects: signatureAction and signatureMessage
    function hashMessageEntity(MessageEntity memory messageObj) private view returns (bytes32) {
        return keccak256(abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(
                    MESSAGE_ENTITY_TYPEHASH,
                    keccak256(bytes(messageObj.actionType)),
                    messageObj.group,
                    messageObj.member,
                    messageObj.amount,
                    keccak256(bytes(messageObj.bill)),
                    messageObj.timestamp
                ))
            ));
    }

    function isApprover(address submitted_group, address member) public view returns (bool) {
        return groupApprovers[submitted_group].has(member);
    }

    // Bill approval: EIP-712 boilerplate ends
    /**
     * signature to be submitted for `Approval` phase of a reimbursement lifecycle
     *
    **/
    function submitApproval(MessageEntity memory messageObj, bytes32 sigR, bytes32 sigS, uint8 sigV) onlyOwner public {
        address recovered_signer = ecrecover(hashMessageEntity(messageObj), sigV, sigR, sigS);
        address submitted_group = messageObj.group;
        if ((
                groupApprovers[submitted_group].has(recovered_signer) ||
                globalApprovers.has(recovered_signer) ||
                groupOwners[submitted_group].has(recovered_signer) ||
                globalOwners.has(recovered_signer) ||
                groupApprovers[submitted_group].has(msg.sender) ||
                globalApprovers.has(msg.sender) ||
                groupOwners[submitted_group].has(msg.sender) ||
                globalOwners.has(msg.sender)
            ) && (keccak256(abi.encodePacked(messageObj.actionType)) == keccak256(abi.encodePacked("Approval")))) {
            emit BillApproved(messageObj.bill, recovered_signer, true);
        }
        else {
            emit BillApproved(messageObj.bill, recovered_signer, false);  // 'centralized' call, set trusted flag as false in event
        }
    }


    function submitDisbursal(MessageEntity memory messageObj, bytes32 sigR, bytes32 sigS, uint8 sigV) onlyOwner public {
        address recovered_signer = ecrecover(hashMessageEntity(messageObj), sigV, sigR, sigS);
        address submitted_group = messageObj.group;
        if ((
                groupDisbursers[submitted_group].has(recovered_signer) ||
                globalDisbursers.has(recovered_signer) ||
                groupOwners[submitted_group].has(recovered_signer) ||
                globalOwners.has(recovered_signer) ||
                groupDisbursers[submitted_group].has(msg.sender) ||
                globalDisbursers.has(msg.sender) ||
                groupOwners[submitted_group].has(msg.sender) ||
                globalOwners.has(msg.sender)
            ) && (keccak256(abi.encodePacked(messageObj.actionType)) == keccak256(abi.encodePacked("Disbursal")))) {
                // redeem DAI
                redeemFromCompound(messageObj.amount * 10 ** 16);
                // transfer once redemption is concerned (Praise be to the good Lord above)
                //(bool success, bytes memory data) = daiContractAddress.call(abi.encodeWithSignature("transfer(address,uint256)", messageObj.member, messageObj.amount));
                bool success = Erc20(daiContractAddress).transfer(messageObj.member, messageObj.amount * 10 ** 16);
                if (success)
                    emit BillDisbursed(messageObj.bill, recovered_signer, true);
                else
                    emit BillDisbursalFailed(messageObj.bill, recovered_signer);
            }
            else {
                emit BillDisbursed(messageObj.bill, recovered_signer, false);  // 'centralized' call, set trusted flag as false in event
            }
    }





    /**
     * @dev status of billUUIDHash.
     *
    **/
    using Roles for Roles.Role;
    mapping (address => Roles.Role) groupOwners;
    mapping (address => Roles.Role) groupApprovers;
    mapping (address => Roles.Role) groupDisbursers;
    mapping (address => Roles.Role) groupEmployees;
    Roles.Role globalOwners;
    Roles.Role globalApprovers;
    Roles.Role globalDisbursers;
    Roles.Role companyEmployees;
    enum BILL_STATES {
        NA, PENDING_APPROVAL, APPROVED, DISBURSED
    }
    mapping (bytes32 => BILL_STATES) public billStatus;
    // --begin: events emitted by role creations--
    event GlobalOwnerAdded(bytes32 companyUUIDHash, address owner);
    event GroupOwnerAdded(bytes32 companyUUIDHash, address group, address owner);

    event GlobalApproverAdded(bytes32 companyUUIDHash, address approver);
    event GroupApproverAdded(bytes32 companyUUIDHash, address group, address approver);

    event GlobalDisburserAdded(bytes32 companyUUIDHash, address disburser);
    event GroupDisburserAdded(bytes32 companyUUIDHash, address group, address disburser);

    event EmployeeAdded(bytes32 companyUUIDHash, address employee);
    event GroupEmployeeAdded(bytes32 companyUUIDHash, address group, address employee);

    event CompoundDaiContractApprovedForTransfer(address compoundDaiContract, address daiContract, uint256 numTokens);
    event CompoundTransfer(address compoundDaiContract, uint256 numTokens);
    event CompoundRedemption(uint256 statusCode, uint256 numTokens);
    // --end: events emitted by role creations--

    // event BillPendingApproval(bytes32 billUUIDHash);
    event BillApproved(string billUUIDHash, address approver, bool trusted);
    // event BillRejected(bytes32 billUUIDHash, address rejecter);
    event BillDisbursed(string billUUIDHash, address disburser, bool trusted);
    event BillDisbursalFailed(string billUUIDHash, address disburser);

    modifier billNotPendingApproval (bytes32 billUUIDHash) {
        require (billStatus[billUUIDHash] == BILL_STATES.NA);
        _;
    }

    /**
     * @dev Add an array of owners `new_owners` against this corporate entity instance
     * If the owner is already present in the roles, nothing happens
     * Only another "global" owner can add another
    **/
    function addGlobalOwners(address[] memory new_owners) public {
        require (isOwner() || globalOwners.has(msg.sender));
        for (uint i=0; i<new_owners.length; i++) {
            if (!globalOwners.has(new_owners[i])) {
                globalOwners.add(new_owners[i]);
                emit GlobalOwnerAdded(companyUUIDHash, new_owners[i]);
            }
        }
    }

    /**
     * @dev Add an array of owners `new_owners` against this group
     * If the owner is already present in the roles, nothing happens
    **/
    function addGroupOwners(address[] memory new_owners, address group) public {
        require (isOwner() || globalOwners.has(msg.sender) || groupOwners[group].has(msg.sender));
        for (uint i=0; i<new_owners.length; i++) {
            if (!groupOwners[group].has(new_owners[i])) {
                groupOwners[group].add(new_owners[i]);
                emit GroupOwnerAdded(companyUUIDHash, group, new_owners[i]);
            }
        }
    }

    /**
     * @dev Add an array of approvers `new_approvers` against this company
     * If the approver is already present in the roles, nothing happens
    **/
    function addGlobalApprovers(address[] memory new_approvers) public {
        require (isOwner() ||  globalOwners.has(msg.sender));
        for (uint i=0; i<new_approvers.length; i++) {
            if (!globalApprovers.has(new_approvers[i])) {
                globalApprovers.add(new_approvers[i]);
                emit GlobalApproverAdded(companyUUIDHash, new_approvers[i]);
            }
        }
    }

    function addGroupApprovers(address[] memory new_approvers, address group) public {
        require (isOwner() || groupOwners[group].has(msg.sender) || globalOwners.has(msg.sender));
        for (uint i=0; i<new_approvers.length; i++) {
            if (!groupApprovers[group].has(new_approvers[i])) {
                groupApprovers[group].add(new_approvers[i]);
                emit GroupApproverAdded(companyUUIDHash, group, new_approvers[i]);
            }
        }
    }

    /**
     * @dev Add an array of disbursers `new_disbursers` against this company
     * If the disburser is already present in the roles, nothing happens
    **/
    function addGlobalDisbursers(address[] memory new_disbursers) public {
        require (isOwner() || globalOwners.has(msg.sender));
        for (uint i=0; i<new_disbursers.length; i++) {
            if (!globalDisbursers.has(new_disbursers[i])) {
                globalDisbursers.add(new_disbursers[i]);
                emit GlobalDisburserAdded(companyUUIDHash, new_disbursers[i]);
            }
        }
    }

    function addGroupDisbursers(address[] memory new_disbursers, address group) public {
        require (isOwner() || groupOwners[group].has(msg.sender) || globalOwners.has(msg.sender));
        for (uint i=0; i<new_disbursers.length; i++) {
            if (!groupDisbursers[group].has(new_disbursers[i])) {
                groupDisbursers[group].add(new_disbursers[i]);
                emit GroupDisburserAdded(companyUUIDHash, group, new_disbursers[i]);
            }
        }
    }

    /**
     * @dev Add an array of employees `new_employees` against this company
     * If the employee is already present in the roles, nothing happens
     * Reserved for future use:
     * =========================
     * All additions to roles like Owner, GroupApprover etc will be allowed only against employees initially registered through this call
    **/
    function addEmployees(address[] memory new_employees) public {
        require (isOwner() || globalOwners.has(msg.sender));
        for (uint i=0; i<new_employees.length; i++) {
            if (!companyEmployees.has(new_employees[i])) {
                companyEmployees.add(new_employees[i]);
                emit EmployeeAdded(companyUUIDHash, new_employees[i]);
            }
        }
    }

    function addGroupEmployees(address[] memory new_employees, address group) public {

        require (isOwner() || globalOwners.has(msg.sender) || groupOwners[group].has(msg.sender));
        for (uint i=0; i<new_employees.length; i++) {
            if (!groupEmployees[group].has(new_employees[i])) {
                groupEmployees[group].add(new_employees[i]);
                emit GroupEmployeeAdded(companyUUIDHash, group, new_employees[i]);
            }
        }
    }

    function changeDaiContract(address newDaiContract) public onlyOwner {
        daiContractAddress = newDaiContract;
    }

    function changeCompoundDaiContract(address newCompoundDaiContract) public onlyOwner {
        compoundDaiContractAddress = newCompoundDaiContract;
    }

    function approveCompoundDaiContract(uint256 numTokens) public onlyOwner {
        Erc20(daiContractAddress).approve(compoundDaiContractAddress, numTokens);
        emit CompoundDaiContractApprovedForTransfer(compoundDaiContractAddress, daiContractAddress, numTokens);
    }

    function supplyToCompound(uint256 numTokens) public onlyOwner {
        Erc20 daiErc20 = Erc20(daiContractAddress);
        require(daiErc20.allowance(address(this), compoundDaiContractAddress) >= numTokens);

        uint256 cTokensMinted = CompoundErc20(compoundDaiContractAddress).mint(numTokens);
        emit CompoundTransfer(compoundDaiContractAddress, cTokensMinted);
    }


    function redeemFromCompound(uint256 numTokens) public onlyOwner returns (bool) {
        CompoundErc20 cToken = CompoundErc20(compoundDaiContractAddress);

        uint256 redeemResult;
        redeemResult = cToken.redeemUnderlying(numTokens);
        emit CompoundRedemption(redeemResult, numTokens);
        if (redeemResult == 0)
            return true;
        else
            return false;
    }



    function recoverSigner(bytes32 message, bytes memory sig) internal pure
    returns (address) {
        uint8 v;
        bytes32 r;
        bytes32 s;

        (v, r, s) = splitSignature(sig);

        return ecrecover(message, v, r, s);
    }

    function splitSignature(bytes memory sig)
    internal
    pure
    returns (uint8, bytes32, bytes32) {
        require(sig.length == 65);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }

}
