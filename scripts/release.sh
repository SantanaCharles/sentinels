#!/bin/sh
# Gera os artefatos de uma release em dist/: binários Linux (amd64, arm64),
# arquivos de instalação e checksums.txt. Uso: scripts/release.sh v0.1.0
set -eu
VERSION="${1:-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
cd "$(dirname "$0")/.."

# O feed de alertas precisa estar assinado antes de qualquer release.
go run ./cmd/feedsign verify internal/intel/advisories.json

rm -rf dist && mkdir -p dist
LDFLAGS="-s -w -X github.com/SantanaCharles/sentinels/internal/version.Version=$VERSION -X github.com/SantanaCharles/sentinels/internal/version.Commit=$COMMIT"
for arch in amd64 arm64; do
  echo "compilando linux/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o "dist/sentinels_linux_$arch" ./cmd/sentinels
done
cp sentinels.example.yaml deploy/sentinels.env.example deploy/sentinels.service deploy/install.sh dist/
(cd dist && sha256sum sentinels_linux_* sentinels.example.yaml sentinels.env.example sentinels.service install.sh > checksums.txt)
cat dist/checksums.txt
