// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/TaskEscrow.sol";
import "../src/JuryPool.sol";
import "../src/DisputeResolution.sol";

contract DisputeFlowTest is Test {
    TaskEscrow public escrow;
    JuryPool public pool;
    DisputeResolution public dispute;
    
    address client = address(0x10);
    address worker = address(0x20);
    address deployer = address(0x99);
    
    address[] jurors;
    
    function setUp() public {
        TaskEscrow escrowImpl = new TaskEscrow();
        JuryPool poolImpl = new JuryPool();
        DisputeResolution disputeImpl = new DisputeResolution();

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
        vm.deal(deployer, 0 ether);
        
        // Setup 5 jurors
        for (uint160 i = 1; i <= 5; i++) {
            address juror = address(i + 100);
            vm.deal(juror, 1 ether);
            vm.prank(juror);
            pool.register{value: 0.1 ether}();
            jurors.push(juror);
        }
    }
    
    function testFullDisputeFlow() public {
        // 1. Client creates task
        vm.prank(client);
        uint256 taskId = escrow.createTask{value: 1 ether}(keccak256("task spec"));
        
        // 2. Worker accepts task
        vm.prank(worker);
        escrow.acceptTask{value: 0.1 ether}(taskId);
        
        // 3. Worker submits result
        vm.prank(worker);
        escrow.submitResult(taskId, keccak256("result"));
        
        // 4. Client disputes
        vm.prank(client);
        escrow.disputeResult(taskId);
        
        // 5. Open dispute in resolution contract (with DISPUTE_FEE)
        vm.prank(client);
        uint256 disputeId = dispute.openDispute{value: 0.01 ether}(taskId);
        
        // 6. Identify selected jurors and vote
        address[] memory selected = new address[](3);
        uint256 found = 0;
        
        for (uint i = 0; i < jurors.length; i++) {
            vm.prank(jurors[i]);
            try dispute.submitVerdict(disputeId, DisputeResolution.Verdict.ApproveClient) {
                selected[found] = jurors[i];
                found++;
                if (found == 3) break;
            } catch {
                // Not a juror
            }
        }
        
        // 7. Finalize dispute
        // Need to skip time to pass appeal period (12 hours)
        vm.warp(block.timestamp + 13 hours);
        
        uint256 clientBefore = client.balance;
        uint256 juror1Before = selected[0].balance;
        
        dispute.finalize(disputeId);
        
        // 8. Verify results
        uint256 clientAfter = client.balance;
        // Total pool was 1.1 ETH. 0% fee. Refund = 1.1 ETH.
        assertEq(clientAfter - clientBefore, 1.1 ether);
        
        // Verify juror reward
        // Reward pool = DISPUTE_FEE (0.01 ETH). 3 winners = 0.00333... ETH each.
        assertGt(selected[0].balance, juror1Before);
        
        // Assert task state
        TaskEscrow.Task memory task = escrow.getTask(taskId);
        assertEq(uint(task.state), 6); // Refunded
        
        // Verify juror stats
        for (uint i = 0; i < 3; i++) {
            JuryPool.Juror memory j = pool.getJuror(selected[i]);
            assertEq(j.casesJudged, 1);
            assertEq(j.correctVerdicts, 1);
        }
    }
}
