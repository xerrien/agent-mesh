// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/TaskEscrow.sol";
import "../src/JuryPool.sol";
import "../src/DisputeResolution.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);
        address owner = vm.envOr("OWNER", deployer);
        address reputationRegistry = vm.envOr("REPUTATION_REGISTRY", address(0));

        vm.startBroadcast(deployerPk);

        // 1. Deploy implementations
        JuryPool juryImpl = new JuryPool();
        TaskEscrow escrowImpl = new TaskEscrow();
        DisputeResolution disputeImpl = new DisputeResolution();

        // 2. Deploy proxies + initialize
        ERC1967Proxy juryProxy = new ERC1967Proxy(
            address(juryImpl),
            abi.encodeCall(JuryPool.initialize, ())
        );
        ERC1967Proxy escrowProxy = new ERC1967Proxy(
            address(escrowImpl),
            abi.encodeCall(TaskEscrow.initialize, ())
        );
        ERC1967Proxy disputeProxy = new ERC1967Proxy(
            address(disputeImpl),
            abi.encodeCall(DisputeResolution.initialize, (address(escrowProxy), address(juryProxy)))
        );

        JuryPool jury = JuryPool(address(juryProxy));
        TaskEscrow escrow = TaskEscrow(address(escrowProxy));
        DisputeResolution dispute = DisputeResolution(address(disputeProxy));

        console.log("JuryPool implementation:", address(juryImpl));
        console.log("TaskEscrow implementation:", address(escrowImpl));
        console.log("DisputeResolution implementation:", address(disputeImpl));
        console.log("JuryPool proxy:", address(jury));
        console.log("TaskEscrow proxy:", address(escrow));
        console.log("DisputeResolution proxy:", address(dispute));

        // 3. Configuration wiring via proxies
        jury.setDisputeResolver(address(dispute));
        escrow.setDisputeResolver(address(dispute));
        escrow.setJuryPool(address(jury));
        jury.setReputationRegistry(reputationRegistry);

        if (owner != deployer) {
            jury.transferOwnership(owner);
            escrow.transferOwnership(owner);
            dispute.transferOwnership(owner);
        }

        console.log("Deployer:", deployer);
        console.log("Owner:", owner);
        console.log("ReputationRegistry:", reputationRegistry);

        vm.stopBroadcast();
    }
}
