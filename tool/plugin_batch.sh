#!/bin/bash

# Set curent directory to the location of the script
script_dir="$(dirname "$(readlink -f "$0")")"
cd "$script_dir"

# Define the path to the IDA tool
idat_path="" # To be assigned by the user! Example "/mnt/c/Users/john/Programs/IDA_Pro_9.0/idat.exe"
if [ -z "$idat_path" ]; then
    echo "[plugin_batch.sh] Error: please assign idat_path variable with your path to idat.exe!"
    echo "Quitting..."
    exit 1
fi

# Erasing previous outputs to prevent inconsistency in the new one
if [[ "$1" == "findcrypt" ]]; then
    script="internal_findcrypt_batch.py"
    rm -f "findcrypt_matches.csv" "findcrypt_tags.json"
elif [[ "$1" == "mnemocrypt" ]]; then
    script="internal_mnemocrypt_batch.py"
    rm -f "mnemocrypt_predictions.csv"
else
    echo "[plugin_batch.sh] Error: unexpected command line argument!"
    echo "Quitting..."
    exit 1
fi

# Process the files with a common counter to follow progress
files=($(find "ida_databases" -type f ! \( -name "*.id0" -o -name "*.id1" -o -name "*.id2" -o -name "*.nam" -o -name "*.til" \)))
total_files=${#files[@]}
counter=0

# Iterate over the filenames in the directory
for file in "${files[@]}"; do
    ((counter++))
    "$idat_path" -A -S"$script" "$file"
    echo "$file processed ($counter/$total_files)"
    # Clean up non-IDB files after processing each file
    find "ida_databases" -type f \( -name "*.id0" -o -name "*.id1" -o -name "*.id2" -o -name "*.nam" -o -name "*.til" \) -exec rm -f {} +
done
