# Build script for AgentSwarm (PowerShell)

$binDir = "bin"
if (!(Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir
}

# Platforms to build for
$platforms = @(
    "linux/amd64", "linux/arm64",
    "windows/amd64", "windows/arm64",
    "darwin/amd64", "darwin/arm64"
)

foreach ($platform in $platforms) {
    $parts = $platform -split "/"
    $os = $parts[0]
    $arch = $parts[1]
    
    $binary = "agentswarm-$os-$arch"
    if ($os -eq "windows") {
        $binary += ".exe"
    }

    Write-Host "Building $binary..."
    $env:GOOS = $os
    $env:GOARCH = $arch
    go build -o "$binDir/$binary" ./cmd/agent/main.go
}

# Reset env vars
$env:GOOS = ""
$env:GOARCH = ""

Write-Host "Builds complete. Check the $binDir directory."






