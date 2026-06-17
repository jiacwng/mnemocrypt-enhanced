import os
import json

output_filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prepared_roots.json")

# Load the input files
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "categories.json"), "r") as cat_file:
    categories = json.load(cat_file)

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "root_prefixes.json"), "r") as prefix_file:
    prefix_options = json.load(prefix_file)

# Initialize the output dictionary
explicit_categories = {}

formatted_categories_names = {
    "Data transfer": "data_transfer",
    "Arithmetic": "arithmetic",
    "Logic": "logic",
    "String manipulation": "string_manipulation",
    "Control transfer": "control_transfer",
    "Process control": "process_control",
    "Crypto": "crypto"
}

# Process each category
for category, mnemonics in categories.items():
    prefixes = prefix_options.get(category, [])
    category_data = {}
    
    for mnemonic in mnemonics:
        mnemonic_lower = mnemonic.lower()  # Convert to lowercase
        # Generate explicit mnemonics by adding each prefix
        expanded_mnemonics = [prefix + mnemonic_lower for prefix in prefixes]
        # Add the original mnemonic as well
        expanded_mnemonics.insert(0, mnemonic_lower)
        category_data[mnemonic_lower] = expanded_mnemonics
    
    explicit_categories[formatted_categories_names[category]] = category_data

# Prepare the list of [prefix, category, set_of_variants]
sorted_couples = []

# Iterate through each category and its prefixes
for category, prefixes in explicit_categories.items():
    for prefix, variants in prefixes.items():
        # Create the [$prefix, $category, $set_of_variants] structure
        sorted_couples.append([prefix, category, variants])

# Sort the list in decreasing order of the prefix length
sorted_couples.sort(key=lambda x: len(x[0]), reverse=True)

# Write the sorted list to the output JSON file
with open(output_filepath, "w") as outfile:
    json.dump(sorted_couples, outfile, indent=4)

print(f"Prepared roots saved to {output_filepath}")
