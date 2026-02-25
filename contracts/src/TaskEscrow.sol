// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "./ProxyOnly.sol";

/**
 * @title TaskEscrow
 * @notice Holds payments for agent tasks until verification passes
 */
contract TaskEscrow is Initializable, ReentrancyGuardUpgradeable, OwnableUpgradeable, UUPSUpgradeable, ProxyOnly {
    
    enum TaskState { Created, Accepted, Submitted, Verified, Disputed, Completed, Refunded }
    
    struct Task {
        address client;
        address worker;
        uint256 payment;
        uint256 workerStake;
        bytes32 specHash;      // Hash of task specification
        bytes32 resultHash;    // Hash of submitted result
        TaskState state;
        uint256 createdAt;
        uint256 submittedAt;
    }
    
    uint256 public taskCount;
    uint256 public constant WORKER_STAKE_PERCENT = 10; // 10% of payment as stake
    uint256 public constant VERIFICATION_TIMEOUT = 3 days;
    
    mapping(uint256 => Task) public tasks;
    
    address public disputeResolver; // DisputeResolution contract
    address public juryPool;        // JuryPool contract
    
    event TaskCreated(uint256 indexed taskId, address indexed client, bytes32 specHash, uint256 payment);
    event TaskAccepted(uint256 indexed taskId, address indexed worker);
    event TaskSubmitted(uint256 indexed taskId, bytes32 resultHash);
    event TaskCompleted(uint256 indexed taskId, address indexed worker, uint256 payment);
    event TaskRefunded(uint256 indexed taskId, address indexed client, uint256 amount);
    event TaskDisputed(uint256 indexed taskId);
    event TaskCancelled(uint256 indexed taskId, address indexed client, uint256 amount);
    
    modifier onlyClient(uint256 taskId) {
        require(msg.sender == tasks[taskId].client, "Not client");
        _;
    }
    
    modifier onlyWorker(uint256 taskId) {
        require(msg.sender == tasks[taskId].worker, "Not worker");
        _;
    }

    modifier taskExists(uint256 taskId) {
        require(taskId > 0 && taskId <= taskCount, "Task does not exist");
        _;
    }
    
    modifier onlyDisputeResolver() {
        require(msg.sender == disputeResolver, "Not dispute resolver");
        _;
    }
    
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
        require(_resolver != address(0), "Invalid resolver");
        disputeResolver = _resolver;
    }
    
    function setJuryPool(address _pool) external onlyOwner onlyProxyCall {
        require(_pool != address(0), "Invalid jury pool");
        juryPool = _pool;
    }
    
    /**
     * @notice Client creates a task with payment
     * @param specHash Hash of the task specification (stored off-chain)
     */
    function createTask(bytes32 specHash) external payable nonReentrant onlyProxyCall returns (uint256) {
        require(msg.value > 0, "Payment required");
        
        taskCount++;
        tasks[taskCount] = Task({
            client: msg.sender,
            worker: address(0),
            payment: msg.value,
            workerStake: 0,
            specHash: specHash,
            resultHash: bytes32(0),
            state: TaskState.Created,
            createdAt: block.timestamp,
            submittedAt: 0
        });
        
        emit TaskCreated(taskCount, msg.sender, specHash, msg.value);
        return taskCount;
    }
    
    /**
     * @notice Worker accepts a task by staking collateral
     */
    function acceptTask(uint256 taskId) external payable nonReentrant taskExists(taskId) onlyProxyCall {
        Task storage task = tasks[taskId];
        require(task.state == TaskState.Created, "Task not available");
        
        uint256 requiredStake = (task.payment * WORKER_STAKE_PERCENT) / 100;
        require(msg.value >= requiredStake, "Insufficient stake");
        
        task.worker = msg.sender;
        task.workerStake = msg.value;
        task.state = TaskState.Accepted;
        
        emit TaskAccepted(taskId, msg.sender);
    }
    
    /**
     * @notice Worker submits the result
     */
    function submitResult(uint256 taskId, bytes32 resultHash) external taskExists(taskId) onlyWorker(taskId) onlyProxyCall {
        Task storage task = tasks[taskId];
        require(task.state == TaskState.Accepted, "Task not accepted");
        
        task.resultHash = resultHash;
        task.state = TaskState.Submitted;
        task.submittedAt = block.timestamp;
        
        emit TaskSubmitted(taskId, resultHash);
    }
    
    /**
     * @notice Client approves the result, releasing payment
     */
    function approveResult(uint256 taskId) external taskExists(taskId) onlyClient(taskId) nonReentrant onlyProxyCall {
        Task storage task = tasks[taskId];
        require(task.state == TaskState.Submitted, "Not submitted");
        
        _completeTask(taskId);
    }
    
    /**
     * @notice Client disputes the result
     */
    function disputeResult(uint256 taskId) external taskExists(taskId) onlyClient(taskId) onlyProxyCall {
        Task storage task = tasks[taskId];
        require(task.state == TaskState.Submitted, "Not submitted");
        require(disputeResolver != address(0), "Dispute resolver not set");
        
        task.state = TaskState.Disputed;
        emit TaskDisputed(taskId);
        
        // Trigger dispute resolution (called by DisputeResolution contract)
    }
    
    /**
     * @notice Called by DisputeResolution contract to resolve in favor of worker
     */
    function resolveForWorker(uint256 taskId) external taskExists(taskId) onlyDisputeResolver nonReentrant onlyProxyCall {
        Task storage task = tasks[taskId];
        require(task.state == TaskState.Disputed, "Not disputed");
        
        _completeTask(taskId);
    }
    
    /**
     * @notice Called by DisputeResolution contract to resolve in favor of client
     */
    function resolveForClient(uint256 taskId) external taskExists(taskId) onlyDisputeResolver nonReentrant onlyProxyCall {
        Task storage task = tasks[taskId];
        require(task.state == TaskState.Disputed, "Not disputed");
        
        // Refund client + give them worker's stake as compensation
        uint256 totalPool = task.payment + task.workerStake;
        
        task.state = TaskState.Refunded;
        
        (bool success, ) = task.client.call{value: totalPool}("");
        require(success, "Refund failed");
        
        emit TaskRefunded(taskId, task.client, totalPool);
    }
    
    /**
     * @notice Auto-complete if client doesn't respond within timeout
     */
    function claimAfterTimeout(uint256 taskId) external taskExists(taskId) onlyWorker(taskId) nonReentrant onlyProxyCall {
        Task storage task = tasks[taskId];
        require(task.state == TaskState.Submitted, "Not submitted");
        require(block.timestamp > task.submittedAt + VERIFICATION_TIMEOUT, "Timeout not reached");
        
        _completeTask(taskId);
    }

    function cancelTask(uint256 taskId) external taskExists(taskId) onlyClient(taskId) nonReentrant onlyProxyCall {
        Task storage task = tasks[taskId];
        require(task.state == TaskState.Created, "Task not cancellable");

        uint256 amount = task.payment;
        task.payment = 0;
        task.state = TaskState.Refunded;

        (bool success, ) = task.client.call{value: amount}("");
        require(success, "Cancel refund failed");

        emit TaskCancelled(taskId, task.client, amount);
    }
    
    function _completeTask(uint256 taskId) internal {
        Task storage task = tasks[taskId];
        
        uint256 workerPayout = task.payment + task.workerStake;
        task.state = TaskState.Completed;
        
        (bool success, ) = task.worker.call{value: workerPayout}("");
        require(success, "Payment failed");
        
        emit TaskCompleted(taskId, task.worker, workerPayout);
    }
    
    function getTask(uint256 taskId) external view taskExists(taskId) onlyProxyCall returns (Task memory) {
        return tasks[taskId];
    }
}
