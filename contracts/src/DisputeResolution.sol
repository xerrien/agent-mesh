// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "./ProxyOnly.sol";

interface ITaskEscrow {
    function resolveForWorker(uint256 taskId) external;
    function resolveForClient(uint256 taskId) external;
    function getTask(uint256 taskId) external view returns (
        address client,
        address worker,
        uint256 payment,
        uint256 workerStake,
        bytes32 specHash,
        bytes32 resultHash,
        uint8 state,
        uint256 createdAt,
        uint256 submittedAt
    );
}

interface IJuryPool {
    function selectJurors(uint256 disputeId, uint256 count, address excludeClient, address excludeWorker) external returns (address[] memory);
    function recordVerdict(address agent, bool wasCorrect) external;
    function slashStake(address agent, uint256 amount) external;
}

/**
 * @title DisputeResolution
 * @notice Handles multi-round agent jury verdicts for task disputes
 */
contract DisputeResolution is Initializable, ReentrancyGuardUpgradeable, OwnableUpgradeable, UUPSUpgradeable, ProxyOnly {
    
    enum DisputeState { Open, VotingRound1, VotingRound2, VotingRound3, Resolved }
    enum Verdict { Pending, ApproveWorker, ApproveClient }
    
    struct Dispute {
        uint256 taskId;
        address client;
        address worker;
        DisputeState state;
        uint256 currentRound;
        uint256 votingDeadline;
        Verdict finalVerdict;
        uint256 rewardPool;
    }
    
    struct Round {
        address[] jurors;
        mapping(address => Verdict) votes;
        uint256 approveWorkerCount;
        uint256 approveClientCount;
        bool resolved;
    }
    
    uint256 public disputeCount;
    uint256 public constant VOTING_PERIOD = 1 days;
    uint256 public constant APPEAL_PERIOD = 12 hours;
    uint256 public constant SLASH_AMOUNT = 0.005 ether;
    uint256 public constant DISPUTE_FEE = 0.01 ether;
    
    // Round sizes: 3 -> 5 -> 9
    uint256[3] public roundSizes = [3, 5, 9];
    
    ITaskEscrow public taskEscrow;
    IJuryPool public juryPool;
    
    mapping(uint256 => Dispute) public disputes;
    mapping(uint256 => mapping(uint256 => Round)) internal rounds; // disputeId => round => Round
    mapping(uint256 => uint256) public appealDeadlines;
    mapping(uint256 => uint256) public taskToDisputeId;
    
    event DisputeOpened(uint256 indexed disputeId, uint256 indexed taskId);
    event JurorsSelected(uint256 indexed disputeId, uint256 round, address[] jurors);
    event VerdictSubmitted(uint256 indexed disputeId, uint256 round, address juror, Verdict verdict);
    event RoundResolved(uint256 indexed disputeId, uint256 round, Verdict verdict);
    event DisputeResolved(uint256 indexed disputeId, Verdict finalVerdict);
    event AppealFiled(uint256 indexed disputeId, uint256 newRound);
    
    constructor() {
        _disableInitializers();
    }

    function initialize(address _escrow, address _juryPool) external initializer onlyProxyCall {
        require(_escrow != address(0), "Invalid escrow");
        require(_juryPool != address(0), "Invalid jury pool");
        __ReentrancyGuard_init();
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        taskEscrow = ITaskEscrow(_escrow);
        juryPool = IJuryPool(_juryPool);
    }

    function _authorizeUpgrade(address) internal override onlyOwner onlyProxyCall {}
    
    /**
     * @notice Open a dispute for a task
     */
    function openDispute(uint256 taskId) external payable onlyProxyCall returns (uint256) {
        require(msg.value >= DISPUTE_FEE, "Dispute fee required");
        require(taskToDisputeId[taskId] == 0, "Dispute already exists for task");
        (address client, address worker,,,,, uint8 state,,) = taskEscrow.getTask(taskId);
        require(state == 4, "Task not in disputed state"); // TaskState.Disputed = 4
        require(msg.sender == client || msg.sender == worker, "Not a party");
        
        disputeCount++;
        disputes[disputeCount] = Dispute({
            taskId: taskId,
            client: client,
            worker: worker,
            state: DisputeState.VotingRound1,
            currentRound: 1,
            votingDeadline: block.timestamp + VOTING_PERIOD,
            finalVerdict: Verdict.Pending,
            rewardPool: msg.value
        });
        taskToDisputeId[taskId] = disputeCount;
        
        // Select jurors for round 1
        address[] memory jurors = juryPool.selectJurors(
            disputeCount,
            roundSizes[0],
            client,
            worker
        );
        
        Round storage r = rounds[disputeCount][1];
        r.jurors = jurors;
        
        emit DisputeOpened(disputeCount, taskId);
        emit JurorsSelected(disputeCount, 1, jurors);
        
        return disputeCount;
    }
    
    /**
     * @notice Juror submits their verdict
     */
    function submitVerdict(uint256 disputeId, Verdict verdict) external onlyProxyCall {
        Dispute storage d = disputes[disputeId];
        require(d.state != DisputeState.Resolved, "Already resolved");
        require(block.timestamp <= d.votingDeadline, "Voting ended");
        require(verdict == Verdict.ApproveWorker || verdict == Verdict.ApproveClient, "Invalid verdict");
        
        Round storage r = rounds[disputeId][d.currentRound];
        require(_isJuror(r.jurors, msg.sender), "Not a juror for this round");
        require(r.votes[msg.sender] == Verdict.Pending, "Already voted");
        
        r.votes[msg.sender] = verdict;
        if (verdict == Verdict.ApproveWorker) {
            r.approveWorkerCount++;
        } else {
            r.approveClientCount++;
        }
        
        emit VerdictSubmitted(disputeId, d.currentRound, msg.sender, verdict);
        
        // Check if round can be resolved
        _checkRoundResolution(disputeId);
    }
    
    /**
     * @notice Resolve a round after voting period ends
     */
    function resolveRound(uint256 disputeId) external onlyProxyCall {
        Dispute storage d = disputes[disputeId];
        require(block.timestamp > d.votingDeadline, "Voting still open");
        require(d.state != DisputeState.Resolved, "Already resolved");
        
        _resolveCurrentRound(disputeId);
    }
    
    /**
     * @notice Losing party files an appeal
     */
    function appeal(uint256 disputeId) external payable onlyProxyCall {
        Dispute storage d = disputes[disputeId];
        Round storage r = rounds[disputeId][d.currentRound];
        
        require(r.resolved, "Round not resolved");
        require(block.timestamp <= appealDeadlines[disputeId], "Appeal period ended");
        require(d.currentRound < 3, "No more appeals");
        
        // Determine who can appeal (the losing party)
        Verdict roundVerdict = _getRoundVerdict(disputeId, d.currentRound);
        if (roundVerdict == Verdict.ApproveWorker) {
            require(msg.sender == d.client, "Only loser can appeal");
        } else {
            require(msg.sender == d.worker, "Only loser can appeal");
        }
        
        // Appeal stake increases each round
        uint256 appealStake = 0.01 ether * d.currentRound;
        require(msg.value >= appealStake, "Insufficient appeal stake");
        d.rewardPool += msg.value;
        
        // Start next round
        d.currentRound++;
        d.votingDeadline = block.timestamp + VOTING_PERIOD;
        
        if (d.currentRound == 2) {
            d.state = DisputeState.VotingRound2;
        } else {
            d.state = DisputeState.VotingRound3;
        }
        
        // Select new jurors
        address[] memory jurors = juryPool.selectJurors(
            disputeId,
            roundSizes[d.currentRound - 1],
            d.client,
            d.worker
        );
        
        Round storage newRound = rounds[disputeId][d.currentRound];
        newRound.jurors = jurors;
        
        emit AppealFiled(disputeId, d.currentRound);
        emit JurorsSelected(disputeId, d.currentRound, jurors);
    }
    
    /**
     * @notice Finalize dispute after appeal period
     */
    function finalize(uint256 disputeId) external nonReentrant onlyProxyCall {
        Dispute storage d = disputes[disputeId];
        Round storage r = rounds[disputeId][d.currentRound];
        
        require(r.resolved, "Round not resolved");
        require(
            block.timestamp > appealDeadlines[disputeId] || d.currentRound == 3,
            "Appeal period not ended"
        );
        require(d.state != DisputeState.Resolved, "Already resolved");
        
        Verdict finalVerdict = _getRoundVerdict(disputeId, d.currentRound);
        d.finalVerdict = finalVerdict;
        d.state = DisputeState.Resolved;
        
        // Execute resolution on escrow
        if (finalVerdict == Verdict.ApproveWorker) {
            taskEscrow.resolveForWorker(d.taskId);
        } else {
            taskEscrow.resolveForClient(d.taskId);
        }
        
        // Reward/slash jurors
        _settleJurors(disputeId, finalVerdict);
        
        emit DisputeResolved(disputeId, finalVerdict);
    }
    
    function _checkRoundResolution(uint256 disputeId) internal {
        Dispute storage d = disputes[disputeId];
        Round storage r = rounds[disputeId][d.currentRound];
        
        uint256 totalVotes = r.approveWorkerCount + r.approveClientCount;
        uint256 required = roundSizes[d.currentRound - 1];
        
        // If all jurors voted, resolve immediately
        if (totalVotes >= required) {
            _resolveCurrentRound(disputeId);
        }
    }
    
    function _resolveCurrentRound(uint256 disputeId) internal {
        Dispute storage d = disputes[disputeId];
        Round storage r = rounds[disputeId][d.currentRound];
        
        if (r.resolved) return;
        
        r.resolved = true;
        appealDeadlines[disputeId] = block.timestamp + APPEAL_PERIOD;
        
        Verdict verdict = _getRoundVerdict(disputeId, d.currentRound);
        emit RoundResolved(disputeId, d.currentRound, verdict);
    }
    
    function _getRoundVerdict(uint256 disputeId, uint256 round) internal view returns (Verdict) {
        Round storage r = rounds[disputeId][round];
        if (r.approveWorkerCount > r.approveClientCount) {
            return Verdict.ApproveWorker;
        }
        return Verdict.ApproveClient; // Tie goes to client
    }
    
    function _settleJurors(uint256 disputeId, Verdict finalVerdict) internal {
        Dispute storage d = disputes[disputeId];
        uint256 totalRewardPool = d.rewardPool;
        d.rewardPool = 0;

        // Distribute to winners in the final/correct rounds
        // For simplicity, we'll reward jurors in the FINAL round who were correct
        Round storage finalR = rounds[disputeId][d.currentRound];
        uint256 winnerCount = 0;
        for (uint256 i = 0; i < finalR.jurors.length; i++) {
            if (finalR.votes[finalR.jurors[i]] == finalVerdict) {
                winnerCount++;
            }
        }

        if (winnerCount > 0) {
            uint256 rewardPerWinner = totalRewardPool / winnerCount;
            for (uint256 i = 0; i < finalR.jurors.length; i++) {
                address juror = finalR.jurors[i];
                if (finalR.votes[juror] == finalVerdict) {
                    juryPool.recordVerdict(juror, true);
                    (bool success, ) = juror.call{value: rewardPerWinner}("");
                    // We don't require success here to prevent blocking finalization
                }
            }
        }

        // Record stats for everyone else
        for (uint256 round = 1; round <= d.currentRound; round++) {
            Round storage r = rounds[disputeId][round];
            for (uint256 i = 0; i < r.jurors.length; i++) {
                address juror = r.jurors[i];
                if (r.votes[juror] != finalVerdict) {
                    juryPool.slashStake(juror, SLASH_AMOUNT);
                    juryPool.recordVerdict(juror, false);
                } else if (round < d.currentRound) {
                    // Correct in early rounds but not the final decider
                    juryPool.recordVerdict(juror, true);
                }
            }
        }
    }
    
    function _isJuror(address[] memory jurors, address addr) internal pure returns (bool) {
        for (uint256 i = 0; i < jurors.length; i++) {
            if (jurors[i] == addr) return true;
        }
        return false;
    }
    
    function getDispute(uint256 disputeId) external view onlyProxyCall returns (Dispute memory) {
        return disputes[disputeId];
    }
    
    function getRoundVotes(uint256 disputeId, uint256 round) external view returns (
        uint256 approveWorker,
        uint256 approveClient,
        bool resolved
    ) onlyProxyCall {
        Round storage r = rounds[disputeId][round];
        return (r.approveWorkerCount, r.approveClientCount, r.resolved);
    }
}
