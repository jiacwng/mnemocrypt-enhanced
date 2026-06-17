import idaapi
import idc

# Import the Findcrypt plugin class
from mnemocrypt import MnemocryptPlugin

# Initialize and run the plugin
try:
    idaapi.auto_wait()
    print("Initializing Mnemocrypt plugin...")
    plugin = MnemocryptPlugin()

    # Run the plugin
    print("Running Mnemocrypt plugin classfication...")
    plugin.run(1)  # Run the plugin's crypto functions classification functionality with storing
    print("Mnemocrypt plugin run completed.")
    idc.qexit()
    
except Exception as e:
    print(f"An error occurred while running the Mnemocrypt plugin: {e}")
    idc.qexit()
