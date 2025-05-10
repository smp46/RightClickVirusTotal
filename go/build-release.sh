#!/bin/bash

# Create a builds directory if it doesn't exist
mkdir -p builds

# Increment version
increment_version() {
    # Get current version from the Go file
    VERSION_LINE=$(grep "const VERSION string = " main.go)
    CURRENT_VERSION=$(echo $VERSION_LINE | grep -o '"v[0-9]\+\.[0-9]\+\.[0-9]\+"' | tr -d '"')

    # Extract version components
    VERSION_PARTS=($(echo ${CURRENT_VERSION#v} | tr '.' ' '))
    MAJOR=${VERSION_PARTS[0]}
    MINOR=${VERSION_PARTS[1]}
    PATCH=${VERSION_PARTS[2]}

    # Increment patch version
    NEW_PATCH=$((PATCH + 1))
    NEW_VERSION="v$MAJOR.$MINOR.$NEW_PATCH"

    echo "Incrementing version from $CURRENT_VERSION to $NEW_VERSION"

    # Update version in the file
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS requires an empty string for -i
        sed -i '' "s/const VERSION string = \"$CURRENT_VERSION\"/const VERSION string = \"$NEW_VERSION\"/" main.go
    else
        # Linux and others
        sed -i "s/const VERSION string = \"$CURRENT_VERSION\"/const VERSION string = \"$NEW_VERSION\"/" main.go
    fi

    return 0
}

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

# Increment version before building
increment_version

echo "Building with new version..."

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
