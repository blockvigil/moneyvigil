pragma solidity >=0.5.1 <0.7.0;

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be aplied to your functions to restrict their use to
 * the owner.
 */
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

contract MoneyVigil_v1 is Ownable {
    mapping(bytes32 => Bill) public bills;  // store bill object against hash of bill uuid

    struct Bill {
        bytes32 prevBillUUIDHash;  // references the bill that is being updated/deleted
        bytes32 metadataHash;
        uint splitMapCount;
        uint timestamp;
    }


    event BillCreated(bytes32 billUUIDHash, bytes32 prevBillUUIDHash, bytes32 metadataHash, address indexed createdBy);
    event BillSubmitted(bytes32 billUUIDHash);
    event ExpenseAdded(address indexed debitor, address indexed creditor, address indexed group, uint amount, bytes32 billUUIDHash);
    event NewGroupMember(address indexed group, address indexed member);


    modifier onlyThisContract() {
        if (msg.sender != address(this))
            revert();
        _;
    }

    modifier canAddExpenseToBill(bytes32 billHash) {
        require (bills[billHash].splitMapCount > 0);
        _;
    }

    modifier billDoesNotExist(bytes32 billHash) {
        require (bills[billHash].timestamp == 0);
        _;
    }

    function addGroupMember(address group, address member) onlyOwner
    public {
        emit NewGroupMember(group, member);
    }

    function createBill (bytes32 billUUIDHash, bytes32 prevBillUUIDHash, bytes32 metadataHash, uint splitMapCount, address createdBy) onlyOwner
    billDoesNotExist(billUUIDHash)
    public
    {
        bills[billUUIDHash] = Bill(prevBillUUIDHash, metadataHash, splitMapCount, now);
        emit BillCreated(billUUIDHash, prevBillUUIDHash, metadataHash, createdBy);
    }

    function addExpense (bytes32 billUUIDHash, address[] memory debitors, address creditor, uint[] memory amounts, address group) onlyOwner
    canAddExpenseToBill(billUUIDHash)
    public
    {
        uint i;
        for (i=0; i<debitors.length; i++) {
            emit ExpenseAdded(debitors[i], creditor, group, amounts[i], billUUIDHash);
        }
        bills[billUUIDHash].splitMapCount -= 1;
        if (bills[billUUIDHash].splitMapCount == 0) {
            emit BillSubmitted(billUUIDHash);
        }
    }
}
