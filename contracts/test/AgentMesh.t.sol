// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/TaskEscrow.sol";
import "../src/JuryPool.sol";
import "../src/DisputeResolution.sol";

contract AgentMeshTest is Test {
    TaskEscrow public escrow;
    JuryPool public pool;
    DisputeResolution public dispute;
    TaskEscrow public escrowImpl;
    JuryPool public poolImpl;
    DisputeResolution public disputeImpl;
    
    address client = address(0x1);
    address worker = address(0x2);
    address juror1 = address(0x3);
    address juror2 = address(0x4);
    address juror3 = address(0x5);
    
    function setUp() public {
        escrowImpl = new TaskEscrow();
        poolImpl = new JuryPool();
        disputeImpl = new DisputeResolution();

        ERC1967Proxy escrowProxy = new ERC1967Proxy(
            address(escrowImpl),
            abi.encodeCall(TaskEscrow.initialize, ())
        );
        ERC1967Proxy poolProxy = new ERC1967Proxy(
            address(poolImpl),
            abi.encodeCall(JuryPool.initialize, ())
        );
        ERC1967Proxy disputeProxy = new ERC1967Proxy(
            address(disputeImpl),
            abi.encodeCall(DisputeResolution.initialize, (address(escrowProxy), address(poolProxy)))
        );

        escrow = TaskEscrow(address(escrowProxy));
        pool = JuryPool(address(poolProxy));
        dispute = DisputeResolution(address(disputeProxy));
        
        escrow.setDisputeResolver(address(dispute));
        escrow.setJuryPool(address(pool));
        pool.setDisputeResolver(address(dispute));
        
        vm.deal(client, 10 ether);
        vm.deal(worker, 10 ether);
        vm.deal(juror1, 1 ether);
        vm.deal(juror2, 1 ether);
        vm.deal(juror3, 1 ether);
    }
    
    function testCreateTask() public {
        bytes32 specHash = keccak256("summarize this document");
        
        vm.prank(client);
        uint256 taskId = escrow.createTask{value: 1 ether}(specHash);
        
        TaskEscrow.Task memory task = escrow.getTask(taskId);
        assertEq(task.client, client);
        assertEq(task.payment, 1 ether);
        assertEq(task.specHash, specHash);
        assertEq(uint(task.state), 0); // Created
    }
    
    function testAcceptTask() public {
        bytes32 specHash = keccak256("test task");
        
        vm.prank(client);
        uint256 taskId = escrow.createTask{value: 1 ether}(specHash);
        
        vm.prank(worker);
        escrow.acceptTask{value: 0.1 ether}(taskId);
        
        TaskEscrow.Task memory task = escrow.getTask(taskId);
        assertEq(task.worker, worker);
        assertEq(task.workerStake, 0.1 ether);
        assertEq(uint(task.state), 1); // Accepted
    }
    
    function testFullTaskLifecycle() public {
        bytes32 specHash = keccak256("integration test");
        bytes32 resultHash = keccak256("result");
        
        // Create
        vm.prank(client);
        uint256 taskId = escrow.createTask{value: 1 ether}(specHash);
        
        // Accept
        vm.prank(worker);
        escrow.acceptTask{value: 0.1 ether}(taskId);
        
        // Submit
        vm.prank(worker);
        escrow.submitResult(taskId, resultHash);
        
        // Approve
        uint256 workerBefore = worker.balance;
        vm.prank(client);
        escrow.approveResult(taskId);
        
        TaskEscrow.Task memory task = escrow.getTask(taskId);
        assertEq(uint(task.state), 5); // Completed
        assertGt(worker.balance, workerBefore);
    }
    
    function testJurorRegistration() public {
        vm.prank(juror1);
        pool.register{value: 0.01 ether}();
        
        JuryPool.Juror memory juror = pool.getJuror(juror1);
        assertTrue(juror.active);
        assertEq(juror.stake, 0.01 ether);
    }
    
    function testJurorCount() public {
        vm.prank(juror1);
        pool.register{value: 0.01 ether}();
        vm.prank(juror2);
        pool.register{value: 0.01 ether}();
        vm.prank(juror3);
        pool.register{value: 0.01 ether}();
        
        assertEq(pool.getActiveJurorCount(), 3);
    }
    
    function testDispute() public {
        // Register jurors first
        vm.prank(juror1);
        pool.register{value: 0.01 ether}();
        vm.prank(juror2);
        pool.register{value: 0.01 ether}();
        vm.prank(juror3);
        pool.register{value: 0.01 ether}();
        
        // Create and submit task
        bytes32 specHash = keccak256("dispute test");
        bytes32 resultHash = keccak256("bad result");
        
        vm.prank(client);
        uint256 taskId = escrow.createTask{value: 1 ether}(specHash);
        
        vm.prank(worker);
        escrow.acceptTask{value: 0.1 ether}(taskId);
        
        vm.prank(worker);
        escrow.submitResult(taskId, resultHash);
        
        // Client disputes
        vm.prank(client);
        escrow.disputeResult(taskId);
        
        TaskEscrow.Task memory task = escrow.getTask(taskId);
        assertEq(uint(task.state), 4); // Disputed
    }

    function testDirectImplementationCallsRevert() public {
        vm.expectRevert("ProxyOnly: direct call blocked");
        escrowImpl.initialize();

        vm.expectRevert("ProxyOnly: direct call blocked");
        poolImpl.initialize();

        vm.expectRevert("ProxyOnly: direct call blocked");
        disputeImpl.initialize(address(escrow), address(pool));
    }

    function testCannotInitializeProxyTwice() public {
        vm.expectRevert();
        escrow.initialize();

        vm.expectRevert();
        pool.initialize();

        vm.expectRevert();
        dispute.initialize(address(escrow), address(pool));
    }

    function testOnlyOwnerCanUpgradeEscrow() public {
        TaskEscrow newImpl = new TaskEscrow();

        vm.prank(worker);
        vm.expectRevert();
        escrow.upgradeToAndCall(address(newImpl), bytes(""));
    }
}
