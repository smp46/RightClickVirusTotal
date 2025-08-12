#!/bin/bash

mkdir -p builds

HOST_OS=""
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  HOST_OS="linux"
fi

SKIP_VERSION_INCREMENT=false
for arg in "$@"; do
  if [[ "$arg" == "--test" ]]; then
    SKIP_VERSION_INCREMENT=true
    echo "Test mode enabled — skipping version increment."
    break
  fi
done

increment_version() {
  SOURCE_VERSION_FILE="cli/main.go"

  FILES_TO_UPDATE=(
    "cli/main.go"
    "app.go"
  )

  if [ ! -f "$SOURCE_VERSION_FILE" ]; then
    echo "Error: Source version file '$SOURCE_VERSION_FILE' not found."
    exit 1
  fi

  VERSION_LINE=$(grep "const VERSION string = " "$SOURCE_VERSION_FILE")
  CURRENT_VERSION=$(echo "$VERSION_LINE" | grep -o '"v[0-9]\+\.[0-9]\+\.[0-9]\+"' | tr -d '"')

  if [ -z "$CURRENT_VERSION" ]; then
    echo "Error: Could not find version string in '$SOURCE_VERSION_FILE'"
    echo "Expected format: const VERSION string = \"vX.Y.Z\""
    exit 1
  fi

  VERSION_PARTS=($(echo ${CURRENT_VERSION#v} | tr '.' ' '))
  MAJOR=${VERSION_PARTS[0]}
  MINOR=${VERSION_PARTS[1]}
  PATCH=${VERSION_PARTS[2]}
  NEW_PATCH=$((PATCH + 1))
  NEW_VERSION="v$MAJOR.$MINOR.$NEW_PATCH"

  echo "Incrementing version from $CURRENT_VERSION to $NEW_VERSION"

  for file_to_update in "${FILES_TO_UPDATE[@]}"; do
    if [ -f "$file_to_update" ]; then
      echo "Updating version in $file_to_update..."
      if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/const VERSION string = \"$CURRENT_VERSION\"/const VERSION string = \"$NEW_VERSION\"/" "$file_to_update"
      else
        sed -i "s/const VERSION string = \"$CURRENT_VERSION\"/const VERSION string = \"$NEW_VERSION\"/" "$file_to_update"
      fi
    else
      echo "Warning: File '$file_to_update' not found. Skipping update."
    fi
  done
}

build_target() {
  local platform=$1
  local output_filename=$2
  local build_tags="webkit2_41"

  local target_os=$(echo $platform | cut -d'/' -f1)
  local extra_flags=""
  if [[ -n "$HOST_OS" && "$HOST_OS" != "$target_os" ]]; then
    echo "Cross-compiling for '$target_os' from '$HOST_OS'. Adding '-skipbindings' flag."
    extra_flags="-skipbindings"
  fi

  echo "Building for $platform..."
  wails build -platform "$platform" -o "$output_filename" -tags "$build_tags" $extra_flags

  local wails_output_path="build/bin/$output_filename"
  local final_output_path="builds/$output_filename"

  if [ ! -f "$wails_output_path" ]; then
    echo "Error: Build failed. Could not find binary at '$wails_output_path'."
    return 1
  fi

  echo "Moving binary from '$wails_output_path' to '$final_output_path'..."
  mv "$wails_output_path" "$final_output_path"

  local checksum=""
  if command -v sha256sum &>/dev/null; then
    checksum=$(sha256sum "$final_output_path" | cut -d ' ' -f 1)
  elif command -v shasum &>/dev/null; then
    checksum=$(shasum -a 256 "$final_output_path" | cut -d ' ' -f 1)
  fi

  echo "$checksum" >"$final_output_path.sha256"

  echo "✓ Built and checksum generated for $output_filename"
}

echo "Starting build process..."

if ! $SKIP_VERSION_INCREMENT; then
  increment_version
else
  echo "Skipping version increment step."
fi

echo "Building..."

build_target "windows/amd64" "RCVT_Windows_amd64.exe"
build_target "linux/amd64" "RCVT_Linux_amd64"

echo "Build complete! All binaries and checksums are in the builds directory."

echo -e "\n### SHA-256 CHECKSUMS"
echo "------------------------------------------------"
for file in builds/*.sha256; do
  binary_name=$(basename "${file%.sha256}")
  checksum=$(cat "$file")
  echo "\`$checksum\`  $binary_name"
done
