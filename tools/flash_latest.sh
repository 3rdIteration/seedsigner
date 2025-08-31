#!/usr/bin/env bash
# Download latest SeedSigner OS release, verify and flash to a microSD card.
# Usage: curl -sSL https://raw.githubusercontent.com/SeedSigner/seedsigner/dev/tools/flash_latest.sh | bash -s -- /dev/sdX [pi0|pi02w|pi2|pi4]
set -euo pipefail

DEVICE=${1:-}
BOARD=${2:-pi0}

if [[ -z "$DEVICE" ]]; then
  echo "Usage: $0 /dev/sdX [pi0|pi02w|pi2|pi4]" >&2
  exit 1
fi

API_URL="https://api.github.com/repos/SeedSigner/seedsigner/releases/latest"
RELEASE_JSON=$(curl -s "${API_URL}")
TAG=$(echo "$RELEASE_JSON" | jq -r .tag_name)
echo "Latest SeedSigner release: $TAG"

SHA_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | endswith(".sha256.txt")) | .browser_download_url')
SIG_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | endswith(".sha256.txt.sig")) | .browser_download_url')
IMG_URL=$(echo "$RELEASE_JSON" | jq -r --arg board "$BOARD" '.assets[] | select(.name | test("seedsigner_os.*" + $board + "\\.img$")) | .browser_download_url')

SHA_FILE=$(basename "$SHA_URL")
SIG_FILE=$(basename "$SIG_URL")
IMG_FILE=$(basename "$IMG_URL")

curl -L -o "$SHA_FILE" "$SHA_URL"
curl -L -o "$SIG_FILE" "$SIG_URL"
curl -L -o "$IMG_FILE" "$IMG_URL"

curl -L https://raw.githubusercontent.com/SeedSigner/seedsigner/dev/gpg_keys/Seedsigner_pubkey.asc | gpg --import

gpg --verify "$SIG_FILE" "$SHA_FILE"

grep "$IMG_FILE" "$SHA_FILE" | sha256sum -c -

echo "Flashing $IMG_FILE to $DEVICE"
sudo dd if="$IMG_FILE" of="$DEVICE" bs=4M conv=fsync status=progress
sync
echo "Done"
