#!/bin/bash

# Set current directory to the location of the script
script_dir="$(dirname "$(readlink -f "$0")")"
cd "$script_dir"

echo "Start of data files unpacking"

# Variables
zip_file="data.zip"  # Replace with the name of your zip file
password="mnemocrypt"
base_dir="$(pwd)" # Current working directory

# Paths for the destination directories
training_dir="${base_dir}/training/raw_executables/"
tool_dir="${base_dir}/tool/raw_executables/"
trained_model_dir="${base_dir}/common/"

# Create destination directories if they don't exist
mkdir -p "$training_dir" "$tool_dir" "$trained_model_dir"

# Function to handle errors
handle_error() {
    echo "Error: $1 failed."
    exit 1
}

# Unzip the file into a temporary directory
temp_dir="$(mktemp -d)"
unzip -P "$password" "$zip_file" -d "$temp_dir" > /dev/null || handle_error "Unzipping data files"

# Move the files to the respective directories
mv "${temp_dir}/data/training/"* "$training_dir" || handle_error "Moving training data"
mv "${temp_dir}/data/tool/"* "$tool_dir" || handle_error "Moving tool data"
mv "${temp_dir}/data/trained_model/"* "$trained_model_dir" || handle_error "Moving trained model data"

# Clean up temporary directory
rm -rf "$temp_dir"

echo "Data files unpacking finished"

# Execute the specified commands
echo "Start of IDA databases building"
./common/building_wrapper.sh databases || handle_error "IDA databases building"
echo "IDA databases building finished"

echo "Start of features computation"
./common/building_wrapper.sh features || handle_error "Features computation"
echo "Features computation finished"

echo "Start of Findcrypt in batch mode"
./tool/plugin_batch.sh findcrypt || handle_error "Findcrypt in batch mode"
echo "Findcrypt in batch mode finished"

echo "Quick start finished. Mnemocrypt plugin can now be used on all binaries from the provided malware dataset."
