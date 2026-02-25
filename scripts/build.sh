#!/bin/bash

# Build script for AgentSwarm

mkdir -p bin

# Platforms to build for
PLATFORMS="linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64"

for PLATFORM in $PLATFORMS; do
    GOOS=${PLATFORM%/*}
    GOARCH=${PLATFORM#*/}
    BINARY="agentswarm-${GOOS}-${GOARCH}"
    
    if [ "$GOOS" == "windows" ]; then
        BINARY="${BINARY}.exe"
    fi

    echo "Building ${BINARY}..."
    GOOS=$GOOS GOARCH=$GOARCH go build -o bin/$BINARY ./cmd/agent/main.go
done

echo "Builds complete. Check the bin/ directory."



