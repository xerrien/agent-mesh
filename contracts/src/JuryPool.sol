// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "./ProxyOnly.sol";

/**
 * @title JuryPool
 * @notice Manages agent registration for dispute resolution jury duty
 */
contract JuryPool is Initializable, ReentrancyGuardUpgradeable, OwnableUpgradeable, UUPSUpgradeable, ProxyOnly {
    
    struct Juror {
        address agent;
        uint256 stake;
        uint256 reputation;  // Cached from ERC-8004
        uint256 casesJudged;
        uint256 correctVerdicts;
        bool active;
    }
    
    uint256 public constant MIN_STAKE = 0.01 ether;
    uint256 public constant MIN_REPUTATION = 10;
    
    address[] public jurorList;
    mapping(address => Juror) public jurors;
    mapping(address => uint256) public jurorIndex; // For O(1) lookup
    
    address public disputeResolver;
    address public reputationRegistry; // ERC-8004 contract
    
    event JurorRegistered(address indexed agent, uint256 stake);
    event JurorWithdrawn(address indexed agent, uint256 stake);
    event JurorSelected(address indexed agent, uint256 disputeId);
    event ReputationUpdated(address indexed agent, uint256 newReputation);
    
    constructor() {
        _disableInitializers();
    }

    function initialize() external initializer onlyProxyCall {
        __ReentrancyGuard_init();
        __Ownable_init();
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address) internal override onlyOwner onlyProxyCall {}
    
    function setDisputeResolver(address _resolver) external onlyOwner onlyProxyCall {
        disputeResolver = _resolver;
    }
    
    function setReputationRegistry(address _registry) external onlyOwner onlyProxyCall {
        reputationRegistry = _registry;
    }
    
    modifier onlyDisputeResolver() {
        require(msg.sender == disputeResolver, "Not dispute resolver");
        _;
    }
    
    /**
     * @notice Agent registers as a potential juror
     */
    function register() external payable nonReentrant onlyProxyCall {
        require(msg.value >= MIN_STAKE, "Insufficient stake");
        require(!jurors[msg.sender].active, "Already registered");
        require(jurors[msg.sender].stake == 0, "Withdraw existing stake first");
        
        // In production, query ERC-8004 for reputation
        uint256 reputation = _getReputation(msg.sender);
        require(reputation >= MIN_REPUTATION, "Reputation too low");
        
        jurors[msg.sender] = Juror({
            agent: msg.sender,
            stake: msg.value,
            reputation: reputation,
            casesJudged: 0,
            correctVerdicts: 0,
            active: true
        });
        
        jurorIndex[msg.sender] = jurorList.length;
        jurorList.push(msg.sender);
        
        emit JurorRegistered(msg.sender, msg.value);
    }
    
    /**
     * @notice Agent withdraws from jury pool
     */
    function withdraw() external nonReentrant onlyProxyCall {
        Juror storage juror = jurors[msg.sender];
        require(juror.stake > 0, "No stake");
        
        uint256 stake = juror.stake;
        bool wasActive = juror.active;
        juror.active = false;
        juror.stake = 0;

        if (wasActive) {
            _removeJurorFromList(msg.sender);
        } else {
            _removeJurorFromListIfPresent(msg.sender);
        }
        
        (bool success, ) = msg.sender.call{value: stake}("");
        require(success, "Withdrawal failed");
        
        emit JurorWithdrawn(msg.sender, stake);
    }
    
    /**
     * @notice Select random jurors for a dispute (weighted by reputation)
     * @param disputeId The dispute requiring jurors
     * @param count Number of jurors to select
     * @param excludeClient Exclude this address
     * @param excludeWorker Exclude this address
     */
    function selectJurors(
        uint256 disputeId,
        uint256 count,
        address excludeClient,
        address excludeWorker
    ) external onlyDisputeResolver onlyProxyCall returns (address[] memory) {
        require(jurorList.length >= count, "Not enough jurors");
        
        address[] memory selected = new address[](count);
        uint256 selectedCount = 0;
        
        // Simple random selection (in production, use Chainlink VRF or commit-reveal)
        uint256 seed = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.prevrandao,
            disputeId
        )));
        
        uint256 attempts = 0;
        uint256 maxAttempts = jurorList.length * 3;
        
        while (selectedCount < count && attempts < maxAttempts) {
            uint256 idx = seed % jurorList.length;
            address candidate = jurorList[idx];
            
            // Skip if already selected, or is a party to the dispute
            bool valid = true;
            if (candidate == excludeClient || candidate == excludeWorker) {
                valid = false;
            }
            for (uint256 i = 0; i < selectedCount; i++) {
                if (selected[i] == candidate) {
                    valid = false;
                    break;
                }
            }
            
            if (valid && jurors[candidate].active) {
                selected[selectedCount] = candidate;
                selectedCount++;
                emit JurorSelected(candidate, disputeId);
            }
            
            seed = uint256(keccak256(abi.encodePacked(seed, attempts)));
            attempts++;
        }
        
        require(selectedCount == count, "Could not select enough jurors");
        return selected;
    }
    
    /**
     * @notice Update juror stats after a verdict
     */
    function recordVerdict(address agent, bool wasCorrect) external onlyDisputeResolver onlyProxyCall {
        Juror storage juror = jurors[agent];
        if (!juror.active) return;
        
        juror.casesJudged++;
        if (wasCorrect) {
            juror.correctVerdicts++;
        }
    }
    
    /**
     * @notice Slash a juror's stake (for incorrect verdicts)
     */
    function slashStake(address agent, uint256 amount) external onlyDisputeResolver onlyProxyCall {
        Juror storage juror = jurors[agent];
        require(juror.active, "Not active juror");
        
        if (amount > juror.stake) {
            amount = juror.stake;
        }
        juror.stake -= amount;
        
        // If stake falls below minimum, deactivate
        if (juror.stake < MIN_STAKE) {
            juror.active = false;
            _removeJurorFromList(agent);
        }
    }

    function _removeJurorFromList(address agent) internal {
        uint256 idx = jurorIndex[agent];
        uint256 lastIdx = jurorList.length - 1;
        address lastJuror = jurorList[lastIdx];

        jurorList[idx] = lastJuror;
        jurorIndex[lastJuror] = idx;
        jurorList.pop();
        delete jurorIndex[agent];
    }

    function _removeJurorFromListIfPresent(address agent) internal {
        if (jurorList.length == 0) {
            return;
        }
        uint256 idx = jurorIndex[agent];
        if (idx >= jurorList.length || jurorList[idx] != agent) {
            return;
        }
        _removeJurorFromList(agent);
    }
    
    /**
     * @notice Get reputation from ERC-8004 (placeholder)
     */
    function _getReputation(address agent) internal view returns (uint256) {
        // In production, call ERC-8004 contract
        // For now, return a default value
        if (reputationRegistry == address(0)) {
            return 100; // Default for testing
        }
        // IReputationRegistry(reputationRegistry).getReputation(agent);
        return 100;
    }
    
    function getActiveJurorCount() external view onlyProxyCall returns (uint256) {
        return jurorList.length;
    }
    
    function getJuror(address agent) external view onlyProxyCall returns (Juror memory) {
        return jurors[agent];
    }
}
