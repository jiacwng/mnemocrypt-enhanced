import idaapi
import idc
import os
import pandas as pd
import joblib
import json

class MnemocryptPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Mnemocrypt: Classify and display crypto functions"
    help = "Identifies cryptographic functions in the binary using a trained model"
    wanted_name = "Mnemocrypt"
    wanted_hotkey = "Ctrl-Alt-M"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, store):
        classify_crypto_functions(store)

    def term(self):
        return


def classify_crypto_functions(store):
    # Configuration
    basename = idc.get_root_filename().split('.', 1)[0]
    # Auto-detect repository path from script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repository_dirpath = os.path.dirname(script_dir)  # Go up one level from tool/ to mnemocrypt/
    if not repository_dirpath:
        print("[Mnemocrypt] Error: please assign repository_dirpath variable with your path to the mnemocrypt repository directory!")
        print("Quitting...")
        return
    model_filepath = os.path.join(repository_dirpath, "common", "trained_mnemocrypt.pkl")
    computed_features_filepath = os.path.join(repository_dirpath, "tool", "computed_features", f"{basename}.csv")
    output_filepath = os.path.join(repository_dirpath, "tool", "mnemocrypt_predictions.csv")
    findcrypt_tags_filepath = os.path.join(repository_dirpath, "tool", "findcrypt_tags.json")
    immediate_crypto_functions_filepath = os.path.join(repository_dirpath, "tool", "immediate_crypto_functions.json")
    min_crypto_confidence_score = 0.5

    # Load pre-trained model
    try:
        model = joblib.load(model_filepath)
    except Exception as e:
        print(f"[Mnemocrypt] Error loading model: {e}")
        return

    # Load the features from the CSV
    try:
        if not os.path.exists(computed_features_filepath):
            print(f"[Mnemocrypt] Feature CSV not found at: {computed_features_filepath}")
            return

        data = pd.read_csv(computed_features_filepath)
        
        function_names = data["function_name"]
        X_test = data.drop(columns=["function_name", "binary_name", "crypto"], errors='ignore')
        # Drop architecture string column, but keep is_64bit as a feature
        if 'architecture' in X_test.columns:
            X_test = X_test.drop(columns=['architecture'])
        # Keep is_64bit as a feature (it's 0 or 1, which is numerical)
    except Exception as e:
        print(f"[Mnemocrypt] Error loading features: {e}")
        return

    # Load the findcrypt tags
    if not os.path.exists(findcrypt_tags_filepath):
        print(f"[Mnemocrypt] Findcrypt tags not found at: {findcrypt_tags_filepath}, so no partial crypto identification related to it in the output.")
        findcrypt_tags = {}
    else:
        with open(findcrypt_tags_filepath, "r") as file:
            findcrypt_tags = json.load(file)  # Load tags as a dictionary
    
    # Load the immediate crypto functions (AES-NI or Intel SHA extension sets)
    if not os.path.exists(immediate_crypto_functions_filepath):
        print(f"[Mnemocrypt] Immediate crypto functions not found at: {immediate_crypto_functions_filepath}, so no partial crypto identification related to it in the output.")
        immediate_crypto_functions = {}
    with open(immediate_crypto_functions_filepath, "r") as file:
        immediate_crypto_functions = json.load(file)

    # Predict probabilities with the model
    try:
        probabilities = model.predict_proba(X_test)[:, 1]  # Probability for class '1' (crypto)
    except Exception as e:
        print(f"[Mnemocrypt] Error during prediction: {e}")
        return

    # Filter and sort functions with confidence > min_crypto_confidence_score
    classified_functions = []
    for i in range(len(probabilities)):
        current_probability = probabilities[i]
        if current_probability > min_crypto_confidence_score:
            func_name = function_names.iloc[i]
            tags = []
            if basename in findcrypt_tags.keys():
                tags = findcrypt_tags[basename].get(func_name, [])  # Get tags for the function, default to empty list
            classified_functions.append((basename, func_name, round(current_probability, 2), ", ".join(tags)))
    for func_name, tag in immediate_crypto_functions.get(basename, {}).items(): # immediate_crypto_functions and function_names are disjoint by construction
        tags = [tag]
        if func_name in findcrypt_tags.get(basename, {}).keys():
            tags.extend(findcrypt_tags[basename].get(func_name, []))
        classified_functions.append((basename, func_name, 1.0, ", ".join(tags)))

    sorted_functions = sorted(classified_functions, key=lambda x: x[2], reverse=True)

    # Export Mnemocrypt prediction results in CSV format, if requested by the user
    if store == 1:
        save_results_to_csv(output_filepath, sorted_functions)

    # Display results
    display_results(sorted_functions)


def save_results_to_csv(filepath, records):
    """
    Save the classified functions to a CSV file.
    If the file exists, append new records to it.
    """
    # Create a DataFrame for the new records
    new_data = pd.DataFrame(records, columns=["Binary Name", "Function Name", "Confidence Score", "Identification Tags"])
    # Check if the file exists
    if os.path.exists(filepath):
        # Load existing data
        try:
            existing_data = pd.read_csv(filepath)
            # Append new records, avoiding duplicates
            updated_data = pd.concat([existing_data, new_data]).drop_duplicates().reset_index(drop=True)
        except Exception as e:
            print(f"[Mnemocrypt] Error reading existing CSV: {e}")
            updated_data = new_data  # Start fresh if there's an error
    else:
        updated_data = new_data

    # Save the updated data back to the file
    try:
        updated_data.to_csv(filepath, index=False)
        print(f"[Mnemocrypt] Results saved to {filepath}")
    except Exception as e:
        print(f"[Mnemocrypt] Error saving CSV: {e}")


def display_results(sorted_functions):
    """
    Display the classified functions and their confidence scores in a table.
    Clicking on a function name navigates to its graph view.
    Rows are progressively color-coded based on a fixed gradient.
    """

    class ResultsChooser(idaapi.Choose):
        def __init__(self, title, items):
            idaapi.Choose.__init__(self, title, [["Function Name", 30], ["Confidence Score", 10], ["Identification Tags", 50]])
            self.items = items
            self.icon = 41  # Assign a default icon

        def OnGetSize(self):
            return len(self.items)

        def OnGetLine(self, index):
            # Display scores as formatted strings
            func_name, score, tags = self.items[index][1], self.items[index][2], self.items[index][3]
            #return [func_name, f"{score:.2f}", tags]
            return [func_name, str(score), tags]

        def OnSelectLine(self, n):
            """
            Navigate to the selected function's graph view.
            """
            func_name = self.items[n][1]
            func_ea = idc.get_name_ea_simple(func_name)
            if func_ea != idc.BADADDR:
                idc.jumpto(func_ea)
            else:
                print(f"[Mnemocrypt] Function not found: {func_name}")

        def OnGetLineAttr(self, n):
            """
            Assign fixed gradient colors based on predefined confidence ranges.
            """
            _, _, score, _ = self.items[n]

            # Define fixed color gradient (Red → Yellow)
            if score >= 0.95:
                color = 0x0000FF  # Red
            elif score >= 0.75:
                color = 0x007FFF  # Orange (approximation in RGB)
            elif score > 0.5:
                color = 0x00FFFF  # Yellow
            else:
                color = 0xFFFFFF  # Default (white)

            return [color, 0x000000]

    # Keep scores as float for processing
    items = sorted_functions
    chooser = ResultsChooser("Mnemocrypt", items)
    chooser.Show()

# Register the plugin with IDA
def PLUGIN_ENTRY():
    return MnemocryptPlugin()
