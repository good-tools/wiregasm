#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob
files=(lib/wiregasm/*.c lib/wiregasm/*.h lib/wiregasm/*.cpp lib/wiregasm/*.hpp)
if [ ${#files[@]} -eq 0 ]; then
  echo "No C/C++ files found"
  exit 0
fi
echo "Running clang-format dry-run..."
clang-format --dry-run --Werror "${files[@]}"