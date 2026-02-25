package agent

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// TaskEscrow ABI (event only)
const taskEscrowEventABI = `[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"taskId","type":"uint256"},{"indexed":true,"internalType":"address","name":"client","type":"address"},{"indexed":false,"internalType":"bytes32","name":"specHash","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"payment","type":"uint256"}],"name":"TaskCreated","type":"event"}]`

type TaskCreatedEvent struct {
	TaskId   *big.Int
	Client   common.Address
	SpecHash [32]byte
	Payment  *big.Int
}

type EventWatcher struct {
	client     *ethclient.Client
	escrowAddr common.Address
	escrowABI  abi.ABI
	lastBlock  uint64
	onTask     func(event TaskCreatedEvent)
}

func NewEventWatcher(rpcURL string, escrowAddr string, onTask func(event TaskCreatedEvent)) (*EventWatcher, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, err
	}

	eABI, err := abi.JSON(strings.NewReader(taskEscrowEventABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse TaskEscrow ABI: %w", err)
	}

	header, err := client.HeaderByNumber(context.Background(), nil)
	lastBlock := uint64(0)
	if err == nil {
		lastBlock = header.Number.Uint64()
	} else {
		fmt.Printf("[Watcher] Warning: could not fetch latest block, will start from 0: %v\n", err)
	}

	return &EventWatcher{
		client:     client,
		escrowAddr: common.HexToAddress(escrowAddr),
		escrowABI:  eABI,
		lastBlock:  lastBlock,
		onTask:     onTask,
	}, nil
}

// Start begins polling for TaskCreated events.
func (w *EventWatcher) Start(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	fmt.Printf("[Watcher] Started monitoring Escrow (%s) from block %d\n", w.escrowAddr.Hex(), w.lastBlock)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.pollLogs(ctx)
		}
	}
}

func (w *EventWatcher) pollLogs(ctx context.Context) {
	header, err := w.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return
	}
	currentBlock := header.Number.Uint64()

	if currentBlock <= w.lastBlock {
		return
	}

	// Cap query range to 2000 blocks per call (many RPCs reject larger ranges)
	const maxBlockRange = uint64(2000)
	toBlock := currentBlock
	if toBlock-w.lastBlock > maxBlockRange {
		toBlock = w.lastBlock + maxBlockRange
	}

	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(int64(w.lastBlock + 1)),
		ToBlock:   big.NewInt(int64(toBlock)),
		Addresses: []common.Address{w.escrowAddr},
	}

	logs, err := w.client.FilterLogs(ctx, query)
	if err != nil {
		fmt.Printf("[Watcher] FilterLogs error: %v\n", err)
		return
	}

	for _, vLog := range logs {
		if len(vLog.Topics) == 0 {
			continue
		}
		if vLog.Address != w.escrowAddr || vLog.Topics[0] != w.escrowABI.Events["TaskCreated"].ID {
			continue
		}

		var event TaskCreatedEvent
		err := w.escrowABI.UnpackIntoInterface(&event, "TaskCreated", vLog.Data)
		if err != nil {
			continue
		}
		if len(vLog.Topics) > 1 {
			event.TaskId = new(big.Int).SetBytes(vLog.Topics[1].Bytes())
		}
		if len(vLog.Topics) > 2 {
			event.Client = common.BytesToAddress(vLog.Topics[2].Bytes())
		}
		if w.onTask != nil {
			w.onTask(event)
		}
	}

	w.lastBlock = toBlock
}
