#!/bin/bash

folder1="./KAT_DATA"
folder2="../debug_CROSS_submission/KAT"

# Hash summary file names
hashfile1="$folder1/hashes.txt"
hashfile2="$folder2/hashes.txt"

# Generate SHA256 hash files
echo "Generating SHA256 hash files..."

(
  cd "$folder1" || exit
  sha256sum * > "$(basename "$hashfile1")"
)

(
  cd "$folder2" || exit
  sha256sum * > "$(basename "$hashfile2")"
)

echo "Hash files generated:"
echo " - $hashfile1"
echo " - $hashfile2"

echo ""
echo "Comparing hash files..."
if ! diff -q "$hashfile1" "$hashfile2" >/dev/null; then
  echo "Hash files differ:"
  diff "$hashfile1" "$hashfile2"
else
  echo "Hash files are identical."
fi

#Checking individual file differences (only if contents differ)
for file in "$folder1"/*; do
  filename=$(basename "$file")
  file2="$folder2/$filename"

  if [[ -f "$file2" ]]; then
    if ! diff -q "$file" "$file2" >/dev/null; then
      echo "Differences found in $filename:"
      diff "$file" "$file2"
      echo "-----------------------------"
    fi
  else
    echo "File $filename not found in $folder2"
  fi
done