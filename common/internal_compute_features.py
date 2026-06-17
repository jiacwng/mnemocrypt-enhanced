import os
import json
import math
import idaapi
import idc
import idautils
import networkx as nx
import pandas as pd
from collections import Counter, defaultdict
from statistics import mean, stdev, median

idaapi.auto_wait()

# Debug: Verify script is running
print(f"[DEBUG] Features computation script started")
print(f"[DEBUG] Processing: {idc.get_root_filename()}")

# Constants declaration
basename = idc.get_root_filename().split('.', 1)[0]
script_dirpath = os.path.dirname(os.path.abspath(__file__))

# Detect architecture (x86-32 vs x86-64)
try:
    inf = idaapi.get_inf_structure()
    is_64bit = inf.is_64bit()
    architecture = "x86-64" if is_64bit else "x86-32"
    print(f"[DEBUG] Architecture detected: {architecture} (is_64bit: {is_64bit})")
except Exception as e:
    print(f"[ERROR] Failed to detect architecture: {e}")
    # Default to x86-32 if detection fails
    is_64bit = False
    architecture = "x86-32"

# Debug log file for vectorized instruction detection
debug_log_path = os.path.join(script_dirpath, os.pardir, "tool", "vectorized_debug.log")

with open(os.path.join(script_dirpath, "training_set_basenames_listing.txt"), 'r') as file:
    crypto_basenames = [line.rstrip() for line in file]

basedir = "training" if basename in crypto_basenames else "tool"
mode_dirpath = os.path.join(script_dirpath, os.pardir, basedir)
features_dirpath = os.path.join(mode_dirpath, "computed_features")
is_training_data = basedir == "training" 

immediate_crypto_functions_filepath = os.path.join(mode_dirpath, "immediate_crypto_functions.json")
immediate_non_crypto_functions_filepath = os.path.join(mode_dirpath, "immediate_non_crypto_functions.json")
unrecognized_mnemonics_filepath = os.path.join(mode_dirpath, "unrecognized_mnemonics.json")
output_filepath = os.path.join(features_dirpath, f"{basename}.csv")
os.makedirs(features_dirpath, exist_ok=True)

unrecognized_mnemonics = defaultdict(int)
computed_features = {}
unwanted_prefixes = {"__", "___", "@", "std::"} # We assume that if a function starts with one of these sequences, it is a priori non-cryptographic
round_precision = 3 # Compromise between precision and complexity

# Initialize counter for vectorized instructions detected
vectorized_count = 0
# We assume that if a function is made of a single basic block with less than 3 instructions (without counting ones with pop, push, nop or ud mnemonics)
# and not containing any mnemonic from cryptographic extension sets, then it is a prirori non-cryptographic
small_func_nb_mnemonics_threshold = 3

adjusted_merged_caballero_roots = {"sh", "sa", "sra", "sla", "srl", "sll", "and", "or", "xor"}
asymmetric_merged_caballero_roots = {"mul", "clmul", "div", "add", "adc", "xadd", "madd"}
merged_caballero_roots = {"add", "xor", "and", "sh", "mul", "div", "ro"} # Roots (grouped after recognition stage) used for computation of Caballero ratios 
selected_roots = {"mul", "sh", "xor"}
selected_bigrams = {"mov_mul", "mov_sh", "mov_xor", "add_add", "add_mul"}

full_stat_related_features = {"nb_instr", "data_transfer", "arithmetic", "logic", "string_manipulation", "control_transfer", "process_control"}
partial_stat_related_features = selected_roots | selected_bigrams
stat_related_features = full_stat_related_features | partial_stat_related_features
immediate_crypto_functions = {}
immediate_non_crypto_functions = set()
crypto_instructions_sets = {"aes": "AES-NI", "sha": "Intel SHA extensions"}

if is_training_data:
    with open(os.path.join(script_dirpath, os.pardir, "training", "crypto_functions_names", basename+"_crypto_functions.json"), 'r') as file:
        crypto_functions = json.load(file).keys()
else:
    crypto_functions = set()
# Load the instruction categories with respective roots and variants (used in mnemonics recognition)
with open(os.path.join(script_dirpath, "prepared_roots.json"), 'r') as f:
    prepared_roots = json.load(f)



# Main part

for func_ea in idautils.Functions():
    func_name = idc.get_func_name(func_ea)

    # Some functions not belonging to the training data can be directly removed
    if not is_training_data:
        # Filtering on first symbols in functions' names
        if any(func_name.startswith(unwanted_prefix) for unwanted_prefix in unwanted_prefixes):
            continue
        # Filtering on recognition by FLIRT
        if (idc.get_func_flags(func_ea) & idaapi.FUNC_LIB != 0):
            continue

    cfg = nx.DiGraph() # Future control flow graph of the current function
    func = idaapi.get_func(func_ea)
    flowchart = None
    try:
        flowchart = idaapi.FlowChart(func)
    except Exception:
        print(f"Function {func_name} exceeds the maximum number of nodes set in IDA, skipped for stability reasons.")
    nb_bb = flowchart.size
    func_info, raw_features = {}, {}
    unique_data_refs, unique_func_calls = set(), set()
    nb_loops, nb_instr, nb_data_refs, nb_mov_instr, nb_edges, nb_default_caballero, nb_adjusted_caballero, nb_asymmetric_caballero = 0, 0, 0, 0, 0, 0, 0, 0
    mnemonic_category_counts = Counter() # To store category frequencies for entropy computation
    is_immediate_crypto, is_immediate_non_crypto = False, False
    default_caballero_ratio, adjusted_caballero_ratio, asymmetric_caballero_ratio = 0, 0, 0 # Value kept iif there is no any mov root in the function (which almost never happens in practice)

    for bb in flowchart:
        # The features of immediate crypto functions (i.e. containing mnemonics from cryptographic sets) computed
        if not is_immediate_crypto and not is_immediate_non_crypto:
            for succ in bb.succs():
                cfg.add_edge(bb.id, succ.id)
                nb_edges += 1

            if bb.start_ea == bb.end_ea:
                nb_bb -= 1
                continue

            hex_bb_address = hex(bb.start_ea)
            bb_raw_features = {raw_feature: 0 for raw_feature in stat_related_features | merged_caballero_roots}
            previous_root = None

            for head_ea in idautils.Heads(bb.start_ea, bb.end_ea):
                if idc.is_code(idc.get_full_flags(head_ea)) and not is_immediate_crypto and not is_immediate_non_crypto:
                    mnemonic = idc.print_insn_mnem(head_ea)

                    # Disarding meaningless mnemonics for the tool (more importantly, they tend to pollute the statistics if ever kept)
                    if (mnemonic in {"nop", "fnop"}) or mnemonic.startswith(("pop", "push", "ud")):
                        continue

                    # Task 34: Detect vectorized instructions and apply weight multiplier
                    # SSE instructions start with 'p' prefix, AVX instructions start with 'v' prefix
                    vectorized_weight = 1  # Default weight for non-vectorized instructions
                    if len(mnemonic) > 1:
                        if mnemonic.startswith('p'):
                            # SSE instruction (p-prefix, e.g., paddd, pmuludq, pxor)
                            vectorized_weight = 4
                            # Debug: Log vectorized instruction detection
                            vectorized_count += 1
                            # Use multiple methods to ensure output is visible
                            debug_msg = f"[DEBUG] SSE instruction detected: {mnemonic} in function {func_name} (weight: {vectorized_weight})\n"
                            print(debug_msg, end='')
                            idaapi.msg(debug_msg)
                            # Also write to log file as backup
                            try:
                                with open(debug_log_path, 'a') as f:
                                    f.write(f"{basename}: {debug_msg}")
                            except:
                                pass
                        elif mnemonic.startswith('v'):
                            # AVX instruction (v-prefix, e.g., vpxor, vaesenc, vpclmulqdq)
                            vectorized_weight = 4
                            # Debug: Log vectorized instruction detection
                            vectorized_count += 1
                            # Use multiple methods to ensure output is visible
                            debug_msg = f"[DEBUG] AVX instruction detected: {mnemonic} in function {func_name} (weight: {vectorized_weight})\n"
                            print(debug_msg, end='')
                            idaapi.msg(debug_msg)
                            # Also write to log file as backup
                            try:
                                with open(debug_log_path, 'a') as f:
                                    f.write(f"{basename}: {debug_msg}")
                            except:
                                pass

                    nb_instr += 1
                    bb_raw_features["nb_instr"] += 1
                    nb_parts_mnem = len(mnemonic.split(" "))
                    # Initilization values that normally should change
                    retained_category, retained_root = None, None

                    # call $+5 is a commonly used way to push EIP value on the stack (so eqivalent to lea + push, push being ignored in our case)
                    if (mnemonic == "call" and idc.print_operand(head_ea, 0) == "$+5"):
                        mnemonic = "lea"
                        retained_category, retained_root = "data_transfer", "lea"

                    # xor reg, reg is typically used to set reg to 0 (so equivalent to mov reg, 0)
                    elif (mnemonic == "xor" and idc.print_operand(head_ea, 0) == idc.print_operand(head_ea, 1)):
                        mnemonic = "mov"
                        retained_category, retained_root = "data_transfer", "mov"

                    # Dealing with so-called "hint instructions"
                    elif nb_parts_mnem != 1:
                        retained_category, retained_root = "control_transfer", "j"
                    else:
                        # Getting the category and root associated to the currently analyzed code instruction's mnemonic
                        for root, category, variants in prepared_roots:
                            for variant in variants:
                                if mnemonic.startswith(variant):
                                    retained_category, retained_root = category, root
                                    break
                            if retained_root: # Stop searching once a match is found (possible thanks to sorted roots)
                                break

                    if not retained_root:
                        unrecognized_mnemonics[mnemonic.upper()] += 1
                        continue

                    if retained_category == "crypto":
                        is_immediate_crypto = True
                        immediate_crypto_functions[func_name] = crypto_instructions_sets[retained_root]
                        break

                    if retained_root == "cmps" and mnemonic[-1] in {"s", "d", "h"}:
                        retained_category, retained_root = "arithmetic", "cmp"
                    elif (retained_root == "movs" and mnemonic[-1] in {"s", "d", "h"}) or retained_root in {"movsx", "movzx"}:
                        retained_category, retained_root = "data_transfer", "mov"

                    if retained_root in {"mov", "cmov"}:
                        nb_mov_instr += 1

                    if nb_parts_mnem == 1:
                        idx_root_beginning = mnemonic.index(retained_root)
                        if "f" in mnemonic[:idx_root_beginning] or any(part in mnemonic for part in {"f16", "f32", "f64", "f128", "fYL2X", "sin", "cos", "tan", "tst"}):
                            is_immediate_non_crypto = True
                            immediate_non_crypto_functions.add(func_name)
                            break

                    # Category-selective SIMD weighting: amplify only arithmetic/logic counts.
                    # nb_instr and nb_mov_instr are kept scalar so Caballero ratio denominators
                    # are not inflated equally with the numerator (which would make the ratio a no-op).
                    effective_weight = vectorized_weight if retained_category in {"arithmetic", "logic"} else 1
                    bb_raw_features[retained_category] += effective_weight
                    mnemonic_category_counts[retained_category] += effective_weight

                    # Caballero heuristics related computations
                    if retained_category in {"arithmetic", "logic"}:
                        nb_default_caballero += vectorized_weight
                        if retained_root in adjusted_merged_caballero_roots:
                            nb_adjusted_caballero += vectorized_weight
                        if retained_root in asymmetric_merged_caballero_roots:
                            nb_asymmetric_caballero += vectorized_weight

                    if retained_root == "call":
                        called_function = idc.get_operand_value(head_ea, 0)
                        unique_func_calls.add(called_function)

                    # Normalize retained_root for n-gram processing
                    if retained_root in {"sa", "sra", "sla", "srl", "sll"}:
                        retained_root = "sh"
                    elif retained_root in {"adc", "xadd"}:
                        retained_root = "add"
                    elif retained_root == "rc":
                        retained_root = "ro"
                    elif retained_root == "madd":
                        retained_root = "mul"

                    # Caballero or selected root occurrence incrementation
                    if retained_root in merged_caballero_roots | selected_roots:
                        bb_raw_features[retained_root] += vectorized_weight

                    # Selected bigram occurrence incrementation
                    if previous_root:
                        current_bigram = f"{previous_root}_{retained_root}" if previous_root <= retained_root else f"{retained_root}_{previous_root}" # undirected bigrams
                        if current_bigram in selected_bigrams:
                            bb_raw_features[current_bigram] += vectorized_weight
                    previous_root = retained_root

                    # Update number of data references and unique data references
                    for ref_ea in idautils.DataRefsFrom(head_ea):
                        segment_name = idc.get_segm_name(ref_ea)
                        if segment_name and ('data' in segment_name or 'bss' in segment_name or segment_name == 'ds'):
                            nb_data_refs += 1
                            unique_data_refs.add(ref_ea)

                    # Update number of loops
                    if retained_root == "j":
                        for operand_index in range(2): # We assume that there are at most 2 operands
                            jump_operand = idc.print_operand(head_ea, operand_index)
                            if jump_operand.startswith("loc_"):
                                target_address = int(jump_operand[4:], 16) # Get and convert the target address from hex to decimal
                                if target_address < head_ea: # Backward jump => loop
                                    nb_loops += 1
                                    break

            raw_features[hex_bb_address] = bb_raw_features

    if not is_immediate_crypto and not is_immediate_non_crypto:
        nb_non_mov_instr = nb_instr - nb_mov_instr
        if nb_non_mov_instr != 0:
            default_caballero_ratio = round(nb_default_caballero / nb_non_mov_instr, round_precision)
            adjusted_caballero_ratio = round(nb_adjusted_caballero / nb_non_mov_instr, round_precision)
            asymmetric_caballero_ratio = round(nb_asymmetric_caballero / nb_non_mov_instr, round_precision)

        # Need to repeat this step at the end because some functions may have empty blocks
        if (nb_bb == 1) and not is_training_data:
            bb = next(iter(flowchart))
            mnemonics_count = 0
            # Discarding functions containing only one basic block and having less than [threshold] "meaningful" instructions
            for instr_ea in idautils.Heads(bb.start_ea, bb.end_ea):
                if idaapi.is_code(idaapi.get_full_flags(instr_ea)):
                    mnemonic = idc.print_insn_mnem(instr_ea)
                    if mnemonic in {"nop", "fnop"} or mnemonic.startswith(("push", "pop", "ud")):
                        continue
                    mnemonics_count += 1
                    if mnemonics_count >= small_func_nb_mnemonics_threshold:
                        break
            if mnemonics_count < small_func_nb_mnemonics_threshold:
                is_immediate_non_crypto = True
                immediate_non_crypto_functions.add(func_name)
                continue
        
        nb_nodes = cfg.number_of_nodes()
        sccs = list(nx.strongly_connected_components(cfg))
        func_info["nb_bb"] = nb_bb
        func_info["nb_instr"] = nb_instr
        func_info["nb_loops"] = nb_loops
        func_info["nb_data_refs"] = nb_data_refs
        func_info["nb_unique_data_refs"] = len(unique_data_refs)
        func_info["nb_unique_func_calls"] = len(unique_func_calls)
        func_info["cyclomatic_complexity"] = nb_edges - nb_nodes + 2*len(sccs)
        func_info["max_loop_depth"] = sum(1 for scc in sccs if len(scc) > 1)
        func_info["default_caballero_ratio"] = default_caballero_ratio
        func_info["adjusted_caballero_ratio"] = adjusted_caballero_ratio
        func_info["asymmetric_caballero_ratio"] = asymmetric_caballero_ratio
        func_info["crypto"] = 1 if (is_training_data and (func_name in crypto_functions)) else 0
        # Add architecture information
        func_info["architecture"] = architecture
        func_info["is_64bit"] = 1 if is_64bit else 0

        # Compute statistics-related features
        for feature in merged_caballero_roots:
            values = [bb_raw_features[feature] for bb_raw_features in raw_features.values()]
            func_info[f"density_{feature}"] = round(sum(values) / nb_non_mov_instr, round_precision) if values and (nb_non_mov_instr > 0) else 0
        for feature in stat_related_features:
            values = [bb_raw_features[feature] for bb_raw_features in raw_features.values()]
            func_info[f"mean_{feature}"] = round(mean(values), round_precision) if values else 0
            if feature in full_stat_related_features:
                func_info[f"std_dev_{feature}"] = round(stdev(values), round_precision) if len(values) > 1 else 0

        values = [bb_raw_features["nb_instr"] for bb_raw_features in raw_features.values()]
        func_info["max_nb_instr"] = max(values)
        func_info["median_nb_instr"] = round(median(values), round_precision) if values else 0
        
        # Compute entropy of mnemonic categories
        total_mnemonics = sum(mnemonic_category_counts.values())
        entropy = -sum((count / total_mnemonics) * math.log2(count / total_mnemonics) for count in mnemonic_category_counts.values()) if total_mnemonics > 0 else 0
        func_info["entropy_mnemonics_categories"] = round(entropy, round_precision)

        # Update the features of the binary under analysis with the current function
        computed_features[func_name] = func_info

# Data exports

# Export unrecognized mnemonics (not matched by any declared root)
if os.path.exists(unrecognized_mnemonics_filepath):
    with open(unrecognized_mnemonics_filepath, "r") as file:
        file_data = json.load(file)
else:
    file_data = {}
for mnemonic, count in unrecognized_mnemonics.items():
    if mnemonic in file_data:
        file_data[mnemonic] += count
    else:
        file_data[mnemonic] = count
with open(unrecognized_mnemonics_filepath, "w") as file:
    json.dump(file_data, file, indent=4)

# Export immediate cryptographic functions (containing mnemonics from AES-NI or Intel SHA extensions)
if os.path.exists(immediate_crypto_functions_filepath):
    with open(immediate_crypto_functions_filepath, "r") as file:
        file_data = json.load(file)
else:
    file_data = {}
file_data[basename] = immediate_crypto_functions
with open(immediate_crypto_functions_filepath, "w") as file:
    json.dump(file_data, file, indent=4)

# Export immediate non-cryptographic functions (containing floating-point instructions or composed of only one small basic block)
if os.path.exists(immediate_non_crypto_functions_filepath):
    with open(immediate_non_crypto_functions_filepath, "r") as file:
        file_data = json.load(file)
else:
    file_data = {}
file_data[basename] = list(immediate_non_crypto_functions)
with open(immediate_non_crypto_functions_filepath, "w") as file:
    json.dump(file_data, file, indent=4)

# Export computed features
# Convert computed_features directly into a DataFrame
data = [{'binary_name': basename, 'function_name': func_name, **func_computed_features} for func_name, func_computed_features in computed_features.items()]
df = pd.DataFrame(data)
# Ensure consistent column ordering
df = df[sorted(df.columns)]
# Fill NaN values with 0
df.fillna(0, inplace=True)
df.to_csv(output_filepath, index=False)

# Write summary to debug log
try:
    with open(debug_log_path, 'a') as f:
        f.write(f"\n=== Summary for {basename} ===\n")
        f.write(f"Total vectorized instructions detected: {vectorized_count}\n")
        f.write(f"Total functions processed: {len(computed_features)}\n")
        f.write(f"CSV file written to: {output_filepath}\n\n")
except:
    pass

# Print summary to console
if vectorized_count > 0:
    print(f"\n[SUMMARY] {basename}: Detected {vectorized_count} vectorized instructions (SSE/AVX)")
    print(f"[SUMMARY] Debug log written to: {debug_log_path}")
else:
    print(f"\n[SUMMARY] {basename}: No vectorized instructions detected (or none present in this binary)")

idc.qexit()
