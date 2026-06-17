import idaapi
import ida_diskio
import idc
import os

# Import the Findcrypt plugin class
from findcrypt3 import Findcrypt_Plugin_t

# Initialize and run the plugin
try:
    idaapi.auto_wait()
    print("Initializing Findcrypt plugin...")
    plugin = Findcrypt_Plugin_t()
    
    # Manually set user_directory since it's typically set in init()
    user_dir = ida_diskio.get_user_idadir()
    plug_dir = os.path.join(user_dir, "plugins")
    plugin.user_directory = os.path.join(plug_dir, "findcrypt-yara")
    
    # Ensure the user directory exists
    if not os.path.exists(plugin.user_directory):
        os.makedirs(plugin.user_directory, 0o755)
    
    # Run the plugin
    print("Running Findcrypt plugin search...")
    plugin.run(1)  # Run the plugin's search functionality with export option enabled
    print("Findcrypt plugin run completed.")
    idc.qexit()
    
except Exception as e:
    print(f"An error occurred while running the Findcrypt plugin: {e}")
    idc.qexit()
