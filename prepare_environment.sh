#!/bin/bash

# Set current directory to the location of the script
script_dir="$(dirname "$(readlink -f "$0")")"
cd "$script_dir"
script_dir=$(pwd) # Absolute path to the directory containing this script

# IDA-related variables
move_to_ida_plugins_dir="./move_to_ida_plugins"
building_wrapper_file="./common/building_wrapper.sh"
plugin_batch_file="./tool/plugin_batch.sh"

# Normalize paths across operating systems
normalize_path() {
    local path=$1
    python3 -c "import os; print(os.path.abspath('$path'))" 2>/dev/null || echo "$path"
}

# Convert Windows-style path to WSL/Linux-style path
convert_to_wsl_path() {
    local win_path=$1
    if [[ "$win_path" =~ ^[a-zA-Z]:\\ ]]; then
        # Convert C:\path\to\dir to /mnt/c/path/to/dir
        echo "$win_path" | sed -E 's|^([a-zA-Z]):\\|/mnt/\L\1/|; s|\\|/|g'
    else
        echo "$win_path"
    fi
}

# Convert WSL/Linux-style path to Windows-style path with uppercase drive letter
convert_to_windows_path() {
    local wsl_path=$1
    if [[ "$wsl_path" =~ ^/mnt/([a-zA-Z])/ ]]; then
        # Convert /mnt/c/path/to/dir to C:\path\to\dir (uppercase drive letter)
        echo "$wsl_path" | sed -E 's|^/mnt/([a-zA-Z])/|\U\1:\\|; s|/|\\|g'
    else
        echo "$wsl_path"
    fi
}

# Escape backslashes for Python strings
escape_for_python() {
    local path=$1
    echo "$path" | sed 's|\\|\\\\|g'
}

# Handle errors and print failure message
handle_error() {
    echo "Error: $1"
    echo "Automatic environment setting failed. Refer to README.md for instructions on how to do it manually or try to fix eventual specific errors above."
    exit 1
}

# Prompt the user for paths
echo "Enter the full path to idat.exe, without quotes nor escaping (ex: C:\Users\john\Programs\IDA_Pro_9.0\idat.exe):"
read -r idat_path
linux_idat_path=$(convert_to_wsl_path "$idat_path")
linux_idat_path=$(normalize_path "$linux_idat_path")

if [[ ! -f "$linux_idat_path" ]]; then
    handle_error "The specified path to idat.exe is invalid or the file does not exist."
fi

echo "Enter the full path to the IDA plugins directory, without quotes nor escaping (ex: C:\Users\john\Programs\IDA_Pro_9.0\plugins):"
read -r plugins_dir
linux_plugins_dir=$(convert_to_wsl_path "$plugins_dir")
linux_plugins_dir=$(normalize_path "$linux_plugins_dir")

if [[ ! -d "$linux_plugins_dir" ]]; then
    handle_error "The specified IDA plugins directory does not exist or is not a directory."
fi

# Validate write permissions for the plugins directory
if [[ ! -w "$linux_plugins_dir" ]]; then
    handle_error "Write permissions are required for the IDA plugins directory ($plugins_dir). Retry to run the script with sudo mode."
fi

# Check for the existence of the move_to_ida_plugins directory
if [[ ! -d "$move_to_ida_plugins_dir" ]]; then
    handle_error "No move_to_ida_plugins directory found. Plugin setup cannot proceed."
fi

# Escape the script directory path for repository_dirpath
windows_repository_dir=$(escape_for_python "$(convert_to_windows_path "$script_dir")")

# Function to update idat_path in a file
update_idat_path() {
    local file=$1
    local idat_path=$2

    if [[ ! -f "$file" ]]; then
        handle_error "File $file not found."
    fi

    sed -i "s|^\s*idat_path\s*=\s*\".*\".*|idat_path=\"$idat_path\"|" "$file" || handle_error "Updating idat_path in $file failed."
    echo "Updated idat_path in $file"
}

# Update idat_path in the required scripts
update_idat_path "$building_wrapper_file" "$linux_idat_path"
update_idat_path "$plugin_batch_file" "$linux_idat_path"

# Function to update repository_dirpath in a file
update_repository_dirpath() {
    local file=$1
    local repository_path=$2

    if [[ ! -f "$file" ]]; then
        handle_error "File $file not found."
    fi

    awk -v repo_path="os.path.abspath(\"$(echo "$repository_path" | sed 's|\\|\\\\|g')\")" \
        '/^\s*repository_dirpath\s*=/ { match($0, /^[ \t]*/); indent = substr($0, RSTART, RLENGTH); $0 = indent "repository_dirpath = " repo_path } 1' "$file" > "${file}.tmp" || handle_error "Updating repository_dirpath in $file failed."
    mv "${file}.tmp" "$file" || handle_error "Replacing original file with updated $file failed."
    echo "Updated repository_dirpath in $file"
}

# Update repository_dirpath in relevant Python files
for file in "$move_to_ida_plugins_dir"/*; do
    filename=$(basename "$file")
    if [[ "$filename" == "findcrypt3.py" || "$filename" == "mnemocrypt.py" ]]; then
        update_repository_dirpath "$file" "$windows_repository_dir"
    fi
done

# Attempt to move plugin files
for file in "$move_to_ida_plugins_dir"/*; do
    filename=$(basename "$file")
    if ! mv -f "$file" "$linux_plugins_dir/" 2>/dev/null; then
        handle_error "Permission denied: cannot move '$filename' to '$linux_plugins_dir'. Retry with sudo mode."
    else
        echo "$file moved to $linux_plugins_dir with replacement"
    fi
done

# Remove the plugins directory if empty
if [ ! "$(ls -A "$move_to_ida_plugins_dir")" ]; then
    rmdir "$move_to_ida_plugins_dir" || handle_error "Removing empty directory $move_to_ida_plugins_dir failed."
fi

echo "Prepare environment finished successfully."
