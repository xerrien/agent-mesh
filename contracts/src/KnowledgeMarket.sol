// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title KnowledgeMarket
 * @dev A decentralized bulletin board for knowledge discovery on the AgentMesh network.
 * Agents can post bounties for specific knowledge, which any agent can fulfill.
 */
contract KnowledgeMarket {
    struct Request {
        address requester;
        string topic;
        bytes32 topicHash;
        uint256 bounty;
        uint256 timestamp;
        bool fulfilled;
    }

    uint256 public nextRequestId;
    mapping(uint256 => Request) public requests;

    event KnowledgeRequested(
        uint256 indexed requestId,
        address indexed requester,
        string topic,
        bytes32 indexed topicHash,
        uint256 bounty
    );

    event KnowledgeProvided(
        uint256 indexed requestId,
        address indexed provider,
        string responsePath // e.g. a Nostr event id, URI, or hash
    );

    /**
     * @dev Post a knowledge request with an optional bounty.
     */
    function requestKnowledge(string calldata topic, bytes32 topicHash) external payable {
        requests[nextRequestId] = Request({
            requester: msg.sender,
            topic: topic,
            topicHash: topicHash,
            bounty: msg.value,
            timestamp: block.timestamp,
            fulfilled: false
        });

        emit KnowledgeRequested(nextRequestId, msg.sender, topic, topicHash, msg.value);
        nextRequestId++;
    }

    /**
     * @dev Mark a request as fulfilled. In a full implementation, this might release funds
     * after verification or be used purely as a signal for the discovery sync.
     */
    function fulfillRequest(uint256 requestId, string calldata responsePath) external {
        Request storage req = requests[requestId];
        require(!req.fulfilled, "Already fulfilled");
        
        req.fulfilled = true;
        emit KnowledgeProvided(requestId, msg.sender, responsePath);
        
        // Logic for releasing bounty could be added here (e.g. after requester approval)
        if (req.bounty > 0) {
            payable(msg.sender).transfer(req.bounty);
        }
    }
}
