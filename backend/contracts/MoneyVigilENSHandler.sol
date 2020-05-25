pragma solidity >=0.5.1 <0.7.0;
pragma experimental ABIEncoderV2;

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

interface ENS {

    // Logged when the owner of a node assigns a new owner to a subnode.
    event NewOwner(bytes32 indexed node, bytes32 indexed label, address owner);

    // Logged when the owner of a node transfers ownership to a new account.
    event Transfer(bytes32 indexed node, address owner);

    // Logged when the resolver for a node changes.
    event NewResolver(bytes32 indexed node, address resolver);

    // Logged when the TTL of a node changes
    event NewTTL(bytes32 indexed node, uint64 ttl);

    // Logged when an operator is added or removed.
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    function setRecord(bytes32 node, address owner, address resolver, uint64 ttl) external;
    function setSubnodeRecord(bytes32 node, bytes32 label, address owner, address resolver, uint64 ttl) external;
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external returns(bytes32);
    function setResolver(bytes32 node, address resolver) external;
    function setOwner(bytes32 node, address owner) external;
    function setTTL(bytes32 node, uint64 ttl) external;
    function setApprovalForAll(address operator, bool approved) external;
    function owner(bytes32 node) external view returns (address);
    function resolver(bytes32 node) external view returns (address);
    function ttl(bytes32 node) external view returns (uint64);
    function recordExists(bytes32 node) external view returns (bool);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}

contract MoneyVigilENSManager is Ownable{
    address public ensRegistryWithFallback = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;
    address public subdomainPublicResolver = 0x4B1488B7a6B320d2D721406204aBc3eeAa9AD329;
    // mapping for bytes32 subdomain hashes to entity specific contracts on moneyvigil
    mapping (bytes32 => address) private subdomainToOwnerContracts;

    event EntitySubdomainRegistered(bytes32 subdomain, bytes32 node, address pointedAddress);
    event EntityDomainOwnershipTransferred(bytes32 node, address newOwner);
    event ENSFallbackRegistryUpdated(address newEnsFallbackRegistry, address oldEnsFallbackRegistry);
    event SubdomainPublicResolverUpdated(address newSubdomainPublicResolver, address oldSubdomainPublicResolver);

    constructor() public {

    }


    function changeENSFallbackRegistry(address newEnsFallbackRegistry) public onlyOwner {
        address _old = ensRegistryWithFallback;
        ensRegistryWithFallback = newEnsFallbackRegistry;
        emit ENSFallbackRegistryUpdated(newEnsFallbackRegistry, _old);
    }

    function changeSubdomainPublicResolver(address newSubdomainPublicResolver) public onlyOwner {
        address _old = subdomainPublicResolver;
        subdomainPublicResolver = newSubdomainPublicResolver;
        emit SubdomainPublicResolverUpdated(newSubdomainPublicResolver, _old);
    }

    function registerSubdomain(bytes32 subdomain, bytes32 node, address entityContract, bytes32 fullyQualifiedNode) public onlyOwner {
        require(ENS(ensRegistryWithFallback).owner(node) == address(this));
        ENS(ensRegistryWithFallback).setSubnodeRecord(node, subdomain, address(this), subdomainPublicResolver, 0);
        (bool success, bytes memory data) = subdomainPublicResolver.call(abi.encodeWithSignature('setAddr(bytes32,address)', fullyQualifiedNode, entityContract));
        require(success);
        subdomainToOwnerContracts[subdomain] = entityContract;
        emit EntitySubdomainRegistered(subdomain, node, entityContract);
    }

    function transferDomainOwnership(bytes32 node, address newOwner) public onlyOwner {
        require(ENS(ensRegistryWithFallback).owner(node) == address(this));
        ENS(ensRegistryWithFallback).setOwner(node, newOwner);
        emit EntityDomainOwnershipTransferred(node, newOwner);
    }
}