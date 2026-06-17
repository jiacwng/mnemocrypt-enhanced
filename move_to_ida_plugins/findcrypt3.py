# -*- coding: utf-8 -*-

import idaapi
import idautils
import ida_bytes
import ida_diskio
import idc
import operator
import yara
import os
import glob
import csv
import json
import pandas as pd
from bisect import bisect_right

VERSION = "0.2"
YARARULES_CFGFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "findcrypt3.rules")

try:
    class Kp_Menu_Context(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            if ctx.widget_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_WIDGET
            return idaapi.AST_DISABLE_FOR_WIDGET

    class Searcher(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.search()
            return 1

except:
    pass


p_initialized = False


class YaraSearchResultChooser(idaapi.Choose):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        idaapi.Choose.__init__(
            self,
            title,
            [
                ["Address", idaapi.Choose.CHCOL_HEX|10],
                ["Rules file", idaapi.Choose.CHCOL_PLAIN|12],
                ["Name", idaapi.Choose.CHCOL_PLAIN|25],
                ["Xrefs", idaapi.Choose.CHCOL_PLAIN|20],
                ["String", idaapi.Choose.CHCOL_PLAIN|10],
                ["Value", idaapi.Choose.CHCOL_PLAIN|40],
                ["Hex", idaapi.Choose.CHCOL_PLAIN|45],
            ],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded)
        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnClose(self):
        return

    def OnSelectLine(self, n):
        self.selcount += 1
        idc.jumpto(self.items[n][0])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [idc.atoa(res[0]), res[1], res[2], res[3], res[4], res[5], res[6]]
        return [res[0], res[1], res[2], res[3], res[4], res[5], res[6]]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show() >= 0

#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class Findcrypt_Plugin_t(idaapi.plugin_t):
    comment = "Findcrypt plugin for IDA Pro (using yara framework)"
    help = "todo"
    wanted_name = "Findcrypt"
    wanted_hotkey = "Ctrl-Alt-F"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global p_initialized

        # register popup menu handlers
        try:
            Searcher.register(self, "Findcrypt")
        except:
            pass

        if p_initialized is False:
            p_initialized = True
            self.user_directory = self.get_user_directory()
            idaapi.register_action(idaapi.action_desc_t(
                "Findcrypt",
                "Find crypto constants",
                Searcher(),
                None,
                None,
                0))
            idaapi.attach_action_to_menu("Search", "Findcrypt", idaapi.SETMENU_APP)
            print("=" * 80)
            print("Findcrypt v{0} by David BERARD, 2017".format(VERSION))
            print("Findcrypt search shortcut key is Ctrl-Alt-F")
            print("Global rules in %s" % YARARULES_CFGFILE)
            print("User-defined rules in %s/*.rules" % self.user_directory)
            print("=" * 80)

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass


    def toVirtualAddress(self, offset, segments):
        va_offset = 0
        for seg in segments:
            if seg[1] <= offset < seg[2]:
                va_offset = seg[0] + (offset - seg[1])
        return va_offset


    def get_user_directory(self):
        user_dir = ida_diskio.get_user_idadir()
        plug_dir = os.path.join(user_dir, "plugins")
        res_dir = os.path.join(plug_dir, "findcrypt-yara")
        if not os.path.exists(res_dir):
            os.makedirs(res_dir, 0o755)
        return res_dir


    def get_rules_files(self):
        rules_filepaths = {"global":YARARULES_CFGFILE}
        for fpath in glob.glob(os.path.join(self.user_directory, "*.rules")):
            name = os.path.basename(fpath)
            rules_filepaths.update({name:fpath})
        return rules_filepaths


    def search(self, store):
        repository_dirpath = None # To be assigned by the user! Example: os.path.abspath("C:\\Users\\john\\Downloads\\mnemocrypt")
        if not repository_dirpath:
            print("[Findcrypt] Error: please assign repository_dirpath variable with the path to the mnemocrypt repository directory!")
            print("Quitting...")
            return
        memory, offsets = self._get_memory()
        rules = yara.compile(filepaths=self.get_rules_files())
        values = self.yarasearch(memory, offsets, rules)
        c = YaraSearchResultChooser("Findcrypt results", values)
        r = c.show()
        # Export Findcrypt3 results in CSV format, if requested by the user
        if store == 1:
            self.save_results_to_csv_and_json(values, repository_dirpath)

    def yarasearch(self, memory, offsets, rules):
        print(">>> start yara search")
        values = list()
        matches = rules.match(data=memory)
        unwanted_prefixes = {"__", "___", "@", "std::"}
        
        # Cache and sort function boundaries for efficient lookup
        function_boundaries = [(idc.get_func_attr(func, idc.FUNCATTR_START), 
                                idc.get_func_attr(func, idc.FUNCATTR_END))
                            for func in idautils.Functions()]
        function_boundaries.sort(key=lambda x: x[0])  # Sort by function start address

        # Helper function to find the function containing a specific address
        def find_containing_function(address):
            starts = [start for start, _ in function_boundaries]
            index = bisect_right(starts, address) - 1
            if index >= 0 and function_boundaries[index][0] <= address <= function_boundaries[index][1]:
                return function_boundaries[index]
            return None

        for match in matches:
            for offset, identifier, matched_data in match.strings:
                name = match.rule
                if name.endswith("_API"):
                    try:
                        name = name + "_" + idc.GetString(self.toVirtualAddress(offset, offsets))
                    except:
                        pass
                address = self.toVirtualAddress(offset, offsets)

                # Extract the matched constant as an integer if possible
                try:
                    constant_value = int.from_bytes(matched_data, byteorder='little')
                except ValueError:
                    print(f"Could not interpret matched data at {hex(address)} as an integer.")
                    constant_value = None

                # Gather cross-references
                xrefs = []
                # Check direct references
                called_func = idaapi.get_func(address)
                if called_func:
                    called_func_name = idaapi.get_func_name(called_func.start_ea)
                    if (called_func_name) and (called_func_name not in xrefs) and not (any(called_func_name.startswith(unwanted_prefix) for unwanted_prefix in unwanted_prefixes)) or (idc.get_func_flags(called_func.start_ea) & idaapi.FUNC_LIB != 0):
                        xrefs.append(idaapi.get_func_name(address))
                else:
                    for xref in idautils.XrefsTo(address):
                        func = idaapi.get_func(xref.frm)
                        if func:
                            func_name = idaapi.get_func_name(func.start_ea)
                            if (func_name) and (func_name not in xrefs) and not (any(func_name.startswith(unwanted_prefix) for unwanted_prefix in unwanted_prefixes)) or (idc.get_func_flags(func.start_ea) & idaapi.FUNC_LIB != 0):
                                xrefs.append(func_name)

                found = False
                # Optimized check for usage as an immediate operand within the containing function
                if constant_value is not None:
                    containing_function = find_containing_function(address)
                    if containing_function:
                        func_start, func_end = containing_function
                        func_name = idaapi.get_func_name(func_start)
                        if (func_name) and (func_name not in xrefs) and not (any(func_name.startswith(unwanted_prefix) for unwanted_prefix in unwanted_prefixes)) or (idc.get_func_flags(func_start) & idaapi.FUNC_LIB != 0):
                            # Iterate over each instruction in the containing function
                            for head in idautils.Heads(func_start, func_end):
                                # Only check operand if it's an immediate
                                for op_index in range(2):
                                    if idc.get_operand_type(head, op_index) == idc.o_imm:
                                        # Check if the immediate value of the matched data is used
                                        if idc.get_operand_value(head, op_index) == constant_value:
                                            xrefs.append(func_name)
                                            found = True
                                            break  # Exit loop once the immediate value is found
                                if found:
                                    break
                
                # Create record with Xrefs
                value = [
                    address,
                    match.namespace,
                    name + "_" + hex(address).lstrip("0x").rstrip("L").upper(),
                    ', '.join(xrefs),
                    identifier,
                    repr(matched_data),
                    matched_data.hex().upper(),
                ]

                try:
                    # Check if the address can be named (not a tail byte)
                    if not ida_bytes.has_user_name(value[0]) and not ida_bytes.has_any_name(value[0]):
                        idaapi.set_name(
                            value[0],
                            name + "_" + hex(address).lstrip("0x").rstrip("L").upper(),
                            idaapi.SN_FORCE
                        )
                except idaapi.IDAError:
                    pass # Simply pass for errors, such as tail bytes, without printing anything

                values.append(value)

        print("<<< end yara search")
        return values

    def save_results_to_csv_and_json(self, values, repository_dirpath):
    # Define paths for the CSV and JSON files
        csv_file_path = os.path.join(repository_dirpath, "tool", "findcrypt_matches.csv")
        json_file_path = os.path.join(repository_dirpath, "tool", "findcrypt_tags.json") # Reduces version of findcrypt_matches.csv, to be used by Mnemocrypt for partial crypto identification
        
        # Prepare processed data
        processed_data = []
        algorithm_name = idaapi.get_input_file_path().split("\\")[-1].split(".")[0]
        function_to_names = {}

        # Collect all records
        for record in values:
            hex_address = hex(record[0])  # Convert address to hexadecimal
            tag_name = record[2].rsplit('_', 1)[0]  # Full name up to the last "_"
            xrefs = record[3].split(', ') if record[3] else []  # Split the xrefs string into a list
            # Append the record to processed data
            processed_data.append([algorithm_name, hex_address, record[1], tag_name, record[3], record[4], record[5], record[6]])

            # Build the dictionary of function names to their respective "Name" values
            for xref in xrefs:
                if xref not in function_to_names:
                    function_to_names[xref] = set()
                if tag_name not in function_to_names[xref]:
                    function_to_names[xref].add(tag_name)
        for func_name, tag_names in function_to_names.items():
            function_to_names[func_name] = list(tag_names)

        # Write all records to the CSV at once
        file_exists = os.path.isfile(csv_file_path)
        with open(csv_file_path, mode='a', newline='') as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(["Binary Name", "Address", "Rules file", "Name", "Xrefs", "String", "Value", "Hex"])
            writer.writerows(processed_data)  # Write all rows at once

        # Load existing data from the JSON file if it exists
        if os.path.isfile(json_file_path):
            with open(json_file_path, 'r') as json_file:
                findcrypt_crypto_functions = json.load(json_file)
        else:
            findcrypt_crypto_functions = {}

        # Update the JSON structure with the current algorithm's data
        findcrypt_crypto_functions[algorithm_name] = function_to_names

        # Write updated data to the JSON file
        with open(json_file_path, 'w') as json_file:
            json.dump(findcrypt_crypto_functions, json_file, indent=4)

        print(f"Data has been saved to {csv_file_path} and {json_file_path}")

    def _get_memory(self):
        result = bytearray()
        segment_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = idc.get_segm_attr(start, idc.SEGATTR_END)
            result += ida_bytes.get_bytes(start, end - start)
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return bytes(result), offsets

    def run(self, store):
        self.search(store)


# register IDA plugin
def PLUGIN_ENTRY():
    return Findcrypt_Plugin_t()