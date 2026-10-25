#!/bin/bash

## Note:
## -> This needs to be run twice (the first time will give the error 
## and using this script and filling the CONST_NX and TRANS_DIR correctly
## by looking a the logs, the second time will run sucessfuly   )
set -euo pipefail

# Project root directory
PROJECT_ROOT="/home/jresende/ruisantos/sidequestdata/pidsmaker"
cd "$PROJECT_ROOT"

# Check the logs (with structure like bellow) to get  hash part for Construction and Transformation
# 2026-10-16 11:29:20 - Task construction: /home/user/artifacts/construction/CADETS_E3/construction/3ae6567b0c73...
# 2026-10-16 11:29:20 - ======= START SUBTASK build_default_graphs.py =======
# 2026-10-20 17:35:45 File "/home/pids/pidsmaker/utils/utils.py", line 329, in get_all_files_from_folders
# 2026-10-20 17:35:45 for sub in os.listdir(base_dir)
# 2026-10-20 17:35:45 PermissionError: [Errno 1] Operation not permitted: '/home/artifacts/transformation/CADETS_E3/transformation/1a4f29229ee1bd1e65c704679006ffc60cbb7205e3acf8baa1cbd5e18133908d/nx/' 

# Define relative or absolute paths (Ensure /nx is attached to both source and target)
CONST_HASH="0b1755a6e1c2b76e7f1a8f75062503d5fa998d22a58643dfc6a09ac6f8e661b8"
TRANS_HASH="633710b351e2c504636023a419acf598e267f1f7c5ccc46f1baf2a78ff71124b"
DATASET="CADETS_E5"

SRC_NX_DIR="artifacts/construction/${DATASET}/construction/${CONST_HASH}/nx"
DEST_NX_DIR="artifacts/transformation/${DATASET}/transformation/${TRANS_HASH}/nx"

# 1. Verify source exists
if [ ! -d "$SRC_NX_DIR" ]; then
    echo "Error: Source nx directory does not exist at:"
    echo "  $SRC_NX_DIR"
    exit 1
fi

# 2. Check if destination is a broken symlink or inaccessible
if [ -L "$DEST_NX_DIR" ] || [ -e "$DEST_NX_DIR" ]; then
    echo "--> Removing existing symlink/directory at target..."
    rm -rf "$DEST_NX_DIR"
fi

echo "--> Resolving symlink issue by copying real 'nx' directory..."
# Option A: Hardlink (saves disk space if on the same filesystem)
ln -d "$SRC_NX_DIR" "$DEST_NX_DIR" 2>/dev/null || \
# Option B: Copy directory if hardlink fails
cp -r "$SRC_NX_DIR" "$DEST_NX_DIR"

echo "--> Fixing directory permissions..."
chmod -R 755 "$DEST_NX_DIR"

echo "Done! The nx directory was resolved successfully."
