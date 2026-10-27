#!/bin/sh
# Pinned to the tested Home Assistant runtime; contains all runtime dependencies, no pip install.
set -eu
cd "$(dirname "$0")/.."
docker run --rm --network none -v "$PWD:/work:ro" -w /work \
  --entrypoint python ghcr.io/home-assistant/home-assistant:2026.10.2 \
  -m unittest discover -s tests -v
