#!/bin/bash

# Set curent directory to the location of the script
script_dir="$(dirname "$(readlink -f "$0")")"
cd "$script_dir"

# Define the path to the IDA tool
idat_path="" # To be assigned by the user! Example "/mnt/c/Users/john/Programs/IDA_Pro_9.0/idat.exe"
if [ -z "$idat_path" ]; then
    echo "[building_wrapper.sh] Error: please assign idat_path variable with your path to idat.exe!"
    echo "Quitting..."
    exit 1
fi

# Directories for input and output
raw_executables_dir_tool="../tool/raw_executables"
raw_executables_dir_training="../training/raw_executables"
ida_databases_dir_tool="../tool/ida_databases"
ida_databases_dir_training="../training/ida_databases"

# Files to reset (to avoid inconsistency)
tool_files_to_reset=("../tool/unrecognized_mnemonics.json" \
                     "../tool/immediate_crypto_functions.json" \
                     "../tool/immediate_non_crypto_functions.json")
training_files_to_reset=("../training/unrecognized_mnemonics.json" \
                          "../training/immediate_crypto_functions.json" \
                          "../training/immediate_non_crypto_functions.json")

# Parse the second argument for scope
if [[ $2 == "all" ]]; then
    raw_executables_dirs=("$raw_executables_dir_tool" "$raw_executables_dir_training")
    ida_databases_dirs=("$ida_databases_dir_tool" "$ida_databases_dir_training")
    files_to_reset=("${tool_files_to_reset[@]}" "${training_files_to_reset[@]}")
elif [[ $2 == "training" ]]; then
    raw_executables_dirs=("$raw_executables_dir_training")
    ida_databases_dirs=("$ida_databases_dir_training")
    files_to_reset=("${training_files_to_reset[@]}")
elif [ -z $2 ]; then
    raw_executables_dirs=("$raw_executables_dir_tool")
    ida_databases_dirs=("$ida_databases_dir_tool")
    files_to_reset=("${tool_files_to_reset[@]}")
else
    echo "[building_wrapper.sh] Error: unexpected scope argument! Use 'all', 'training', or leave empty."
    exit 1
fi

# Parse the first argument for stage
if [[ $1 == "databases" ]]; then
    dirs=("${raw_executables_dirs[@]}")
    for file in "${ida_databases_dirs[@]}"; do
        mkdir -p "$file"
    done
elif [[ $1 == "features" ]]; then
    dirs=("${ida_databases_dirs[@]}")
    for file in "${files_to_reset[@]}"; do
        rm -f "$file"
    done
else
    echo "[building_wrapper.sh] Error: invalid stage name! Use 'databases' or 'features'."
    exit 1
fi

# Calculate total number of files across all directories
total_files=0
for dir in "${dirs[@]}"; do
    total_files=$((total_files + $(find "$dir" -type f ! \( -name "*.asm" -o -name "*.pdb" -o -name "*.id0" -o -name "*.id1" -o -name "*.id2" -o -name "*.nam" -o -name "*.til" \) | wc -l)))
done
counter=0

# Iterate over directories and process files
for index in "${!dirs[@]}"; do
    raw_executables_dir="${raw_executables_dirs[$index]}"
    ida_databases_dir="${ida_databases_dirs[$index]}"

    if [[ $1 == "databases" ]]; then
        files=($(find "$raw_executables_dir" -type f ! \( -name "*.asm" -o -name "*.pdb" -o -name "*.id0" -o -name "*.id1" -o -name "*.id2" -o -name "*.nam" -o -name "*.til" \)))
        for file in "${files[@]}"; do
            ((counter++))
            "$idat_path" -B "$file"
            base_name=$(basename "$file")
            find "$raw_executables_dir" -type f \( -name "*.asm" -o -name "*.id0" -o -name "*.id1" -o -name "*.id2" -o -name "*.nam" -o -name "*.til" \) -exec rm -f {} +
            mv "${file}.idb" "$ida_databases_dir" 2>/dev/null || true
            mv "${file}.i64" "$ida_databases_dir" 2>/dev/null || true
            echo "$file processed ($counter/$total_files)"
        done
    else
        files=($(find "$ida_databases_dir" -type f ! \( -name "*.asm" -o -name "*.pdb" -o -name "*.id0" -o -name "*.id1" -o -name "*.id2" -o -name "*.nam" -o -name "*.til" \)))
        for file in "${files[@]}"; do
            ((counter++))
            "$idat_path" -A -S"internal_compute_features.py" "$file"
            find "$ida_databases_dir" -type f \( -name "*.id0" -o -name "*.id1" -o -name "*.id2" -o -name "*.nam" -o -name "*.til" \) -exec rm -f {} +
            echo "$file processed ($counter/$total_files)"
        done
    fi
done
