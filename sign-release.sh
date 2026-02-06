#!/bin/bash
# Sign LinMon release binaries
# Usage: ./sign-release.sh v1.3.0

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version-tag>"
    echo "Example: $0 v1.3.0"
    exit 1
fi

VERSION="$1"
GPG_KEY="50AE70D791320122"

# Create secure temporary directory
WORKDIR=$(mktemp -d)
if [[ ! -d "$WORKDIR" ]]; then
    echo "Error: Failed to create temporary directory" >&2
    exit 1
fi

echo "=== Signing LinMon Release $VERSION ==="
echo ""

cd "$WORKDIR"

# Download release binaries
echo "[1/5] Downloading release binaries from GitHub..."
gh release download "$VERSION" --repo espegro/linmon

# List downloaded files
echo ""
echo "Downloaded files:"
ls -lh
echo ""

# Generate checksums
echo "[2/5] Generating SHA256 checksums..."
sha256sum *.tar.gz > SHA256SUMS
cat SHA256SUMS
echo ""

# Sign checksums
echo "[3/5] Signing checksums with GPG key $GPG_KEY..."
gpg --default-key "$GPG_KEY" --armor --detach-sign SHA256SUMS

# Verify signature
echo "[4/5] Verifying GPG signature..."
gpg --verify SHA256SUMS.asc SHA256SUMS
echo ""

# Upload to GitHub release
echo "[5/5] Uploading signed checksums to GitHub..."
gh release upload "$VERSION" SHA256SUMS SHA256SUMS.asc --clobber --repo espegro/linmon

echo ""
echo "✅ Release $VERSION successfully signed!"
echo ""
echo "Verification instructions for users:"
echo "  gpg --keyserver keys.openpgp.org --recv-keys $GPG_KEY"
echo "  gpg --verify SHA256SUMS.asc SHA256SUMS"
echo "  sha256sum -c SHA256SUMS"
echo ""

# Cleanup
cd -
rm -rf "$WORKDIR"
