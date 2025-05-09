#!/bin/bash

# Create a builds directory if it doesn't exist
mkdir -p builds

# Function to build and generate checksum
build_and_checksum() {
    local os=$1
    local arch=$2
    local output=$3

    echo "Building for $os ($arch)..."
    GOOS=$os GOARCH=$arch go build -o "builds/$output"

    # Generate SHA-256 checksum
    if command -v sha256sum &>/dev/null; then
        # Linux
        checksum=$(sha256sum "builds/$output" | cut -d ' ' -f 1)
    elif command -v shasum &>/dev/null; then
        # macOS
        checksum=$(shasum -a 256 "builds/$output" | cut -d ' ' -f 1)
    else
        echo "Warning: Could not generate SHA-256 checksum. Neither sha256sum nor shasum found."
        checksum="unknown"
    fi

    # Save checksum to file
    echo "$checksum" >"builds/$output.sha256"

    echo "✓ Built $output"
}

echo "Starting build process..."

# Build for Windows
build_and_checksum windows amd64 RCVT_CLI_Windows_amd64.exe

# Build for macOS Intel
build_and_checksum darwin amd64 RCVT_CLI_macOS_amd64

# Build for macOS Apple Silicon
build_and_checksum darwin arm64 RCVT_CLI_macOS_arm64

# Build for Linux
build_and_checksum linux amd64 RCVT_CLI_Linux_amd64

echo "Build complete! All binaries and checksums are in the builds directory."

# List all generated files with their checksums
echo -e "\nGenerated files and their SHA-256 checksums:"
echo "------------------------------------------------"
for file in builds/*.sha256; do
    binary_name=$(basename "${file%.sha256}")
    checksum=$(cat "$file")
    echo "\`$checksum\`  $binary_name"
done
