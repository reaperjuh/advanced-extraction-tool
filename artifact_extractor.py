import os
import subprocess
import shutil # For shutil.which and rmtree
import argparse # For command-line argument parsing

# --- Global Constants ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# This global ADB_EXE will be updated by find_adb_exe() if needed.
ADB_EXE = os.path.join(SCRIPT_DIR, 'adb.exe')
VERBOSE = False # Default, can be overridden by --verbose argument

# --- Artifact Database ---
ARTIFACTS_DB = {
    "contacts_db": {
        "display_name": "Contacts Database",
        "description": "SQLite database containing user contacts.",
        "category": "User Data",
        "type": "file",
        "paths": ["/data/data/com.android.providers.contacts/databases/contacts2.db"],
        "requires_root": True
    },
    "sms_mms_db": {
        "display_name": "SMS/MMS Database",
        "description": "SQLite database for SMS and MMS messages.",
        "category": "User Data",
        "type": "file",
        "paths": ["/data/data/com.android.providers.telephony/databases/mmssms.db"],
        "requires_root": True
    },
    "wifi_config_store": {
        "display_name": "Wi-Fi Configuration",
        "description": "XML file storing Wi-Fi network configurations.",
        "category": "System Configuration",
        "type": "file",
        "paths": ["/data/misc/wifi/WifiConfigStore.xml", "/data/misc/wifi/WifiConfigStoreSoftAp.xml"],
        "requires_root": True
    },
    "device_properties": {
        "display_name": "Device Properties",
        "description": "Output of 'getprop' command showing system properties.",
        "category": "Device Information",
        "type": "command",
        "command_str": "shell getprop",
        "output_file": "device_properties.txt",
        "requires_root": False
    },
    "installed_packages": {
        "display_name": "Installed Packages",
        "description": "List of all installed application packages and their APK paths.",
        "category": "Device Information",
        "type": "command",
        "command_str": "shell pm list packages -f",
        "output_file": "installed_packages.txt",
        "requires_root": False
    },
    "build_prop": {
        "display_name": "Build Properties",
        "description": "System build properties file.",
        "category": "Device Information",
        "type": "file",
        "paths": ["/system/build.prop"],
        "requires_root": False
    },
    "sdcard_dcim": {
        "display_name": "SD Card DCIM (Photos/Videos)",
        "description": "Digital Camera Images folder from primary external storage.",
        "category": "Media/SD Card",
        "type": "directory",
        "paths": ["/sdcard/DCIM", "/storage/emulated/0/DCIM"],
        "requires_root": False
    },
    "whatsapp_sdcard_databases": {
        "display_name": "WhatsApp Databases (SD Card)",
        "description": "WhatsApp message backup databases from SD card.",
        "category": "App Data/SD Card",
        "type": "directory",
        "paths": ["/sdcard/WhatsApp/Databases", "/storage/emulated/0/WhatsApp/Databases"],
        "requires_root": False
    },
    "chrome_history": {
        "display_name": "Chrome Browser History",
        "description": "Chrome browser history database.",
        "category": "Browser Data/Chrome",
        "type": "file",
        "paths": ["/data/data/com.android.chrome/app_chrome/Default/History"],
        "requires_root": True
    },
}

# --- ADB Path Configuration ---
def find_adb_exe():
    global ADB_EXE
    if os.path.exists(ADB_EXE):
        return ADB_EXE
    adb_in_path = shutil.which("adb") or shutil.which("adb.exe")
    if adb_in_path:
        ADB_EXE = adb_in_path
        if VERBOSE: print(f"Update: Using ADB from PATH: {ADB_EXE}")
        return ADB_EXE
    print(f"Critical Error: ADB executable not found at '{os.path.join(SCRIPT_DIR, 'adb.exe')}' or in system PATH.")
    return None

# --- Device Serial Detection ---
def get_device_serial(specified_serial=None, adb_exe_path=None):
    if specified_serial:
        return specified_serial
    if not adb_exe_path:
        print("Error: ADB executable path not provided to get_device_serial.")
        return None
    try:
        result = subprocess.run(
            [adb_exe_path, 'devices'], capture_output=True, text=True, check=False,
            encoding='utf-8', errors='replace'
        )
        if result.returncode != 0:
            print(f"Error running 'adb devices': {result.stderr.strip()}")
            return None
        lines = result.stdout.strip().splitlines()
        serials = []
        if len(lines) > 1:
            for line in lines[1:]:
                if line.strip() and '\tdevice' in line:
                    serials.append(line.split('\t')[0])
        if not serials:
            print("Error: No Android devices found.")
            return None
        if len(serials) == 1:
            if VERBOSE: print(f"Detected single device: {serials[0]}")
            return serials[0]
        print("Error: Multiple devices connected. Please specify one using --device SERIAL:")
        for i, ser in enumerate(serials): print(f"  {i+1}. {ser}")
        return None
    except FileNotFoundError:
        print(f"Error: ADB executable not found at '{adb_exe_path}' when trying to list devices.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while detecting devices: {e}")
        return None

# --- Argument Parser Setup ---
def setup_arg_parser():
    parser = argparse.ArgumentParser(description="Extracts predefined artifacts from an Android device.")
    parser.add_argument('--output', required=True, help="Base output directory for extracted artifacts.")
    parser.add_argument('--artifacts', help="Comma-separated list of artifact keys to extract.")
    parser.add_argument('--all', action='store_true', help="Extract all defined artifacts.")
    parser.add_argument('--list-artifacts', action='store_true', help="List available artifacts and exit.")
    parser.add_argument('--device', help="Specify target device serial.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output.")
    return parser

# --- ADB Command Execution ---
def execute_adb_command(command_parts, device_serial=None):
    if not ADB_EXE or not os.path.exists(ADB_EXE):
        print("Critical Error: ADB_EXE path is not correctly set or adb is missing.")
        return subprocess.CompletedProcess(args=command_parts, returncode=-127, stdout='', stderr='ADB_EXE path error.')
    adb_command = [ADB_EXE]
    if device_serial: adb_command.extend(['-s', device_serial])
    adb_command.extend(command_parts)
    if VERBOSE: print(f"Executing ADB command: {' '.join(adb_command)}")
    try:
        result = subprocess.run(
            adb_command, capture_output=True, text=True, check=False,
            encoding='utf-8', errors='replace'
        )
    except FileNotFoundError:
        print(f"Error: ADB executable not found at '{ADB_EXE}'.")
        return subprocess.CompletedProcess(args=adb_command, returncode=-1, stdout='', stderr='ADB executable not found.')
    return result

# --- ADB File/Directory Operations ---
def adb_pull_file(device_path, local_path, device_serial=None):
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    return execute_adb_command(['pull', device_path, local_path], device_serial)

def adb_pull_directory(device_path, local_path_parent, device_serial=None):
    os.makedirs(local_path_parent, exist_ok=True)
    return execute_adb_command(['pull', device_path, local_path_parent], device_serial)

# --- Artifact Extraction Logic ---
def extract_artifact(artifact_key, artifact_info, base_output_dir_device, device_serial=None):
    display_name = artifact_info.get("display_name", artifact_key)
    category = artifact_info.get("category", "Uncategorized")
    artifact_type = artifact_info.get("type")
    requires_root = artifact_info.get("requires_root", False)
    category_output_path = os.path.join(base_output_dir_device, category.replace("/", "_"))
    os.makedirs(category_output_path, exist_ok=True)

    main_print_message = f"Extracting: {display_name}..."
    if VERBOSE: main_print_message = f"\nAttempting to extract: {display_name} (Category: {category})"
    print(main_print_message)

    if requires_root and VERBOSE: print("Note: This artifact typically requires root access.")

    if artifact_type == "file":
        paths = artifact_info.get("paths", [])
        if not paths:
            if VERBOSE: print(f"Failure: No paths for file artifact '{display_name}'.")
            return False
        success = False
        for device_path in paths:
            local_dest_path = os.path.join(category_output_path, os.path.basename(device_path))
            if VERBOSE: print(f"  Pulling file '{device_path}' to '{local_dest_path}'...")
            result = adb_pull_file(device_path, local_dest_path, device_serial)
            if result.returncode == 0:
                if VERBOSE: print(f"  Success: Pulled '{device_path}'.")
                success = True; break
            elif VERBOSE: print(f"  Failed to pull '{device_path}': {result.stderr.strip() or result.stdout.strip()}")
        if not success and VERBOSE: print(f"Failure: Could not pull any files for '{display_name}'.")
        return success
    elif artifact_type == "directory":
        paths = artifact_info.get("paths", [])
        if not paths:
            if VERBOSE: print(f"Failure: No paths for directory artifact '{display_name}'.")
            return False
        success = False
        for device_path in paths:
            if VERBOSE: print(f"  Pulling directory '{device_path}' into '{category_output_path}'...")
            result = adb_pull_directory(device_path, category_output_path, device_serial)
            if result.returncode == 0:
                if VERBOSE: print(f"  Success: Pulled directory '{device_path}'.")
                success = True; break
            elif VERBOSE: print(f"  Failed to pull '{device_path}': {result.stderr.strip() or result.stdout.strip()}")
        if not success and VERBOSE: print(f"Failure: Could not pull any directories for '{display_name}'.")
        return success
    elif artifact_type == "command":
        command_str = artifact_info.get("command_str")
        if not command_str:
            if VERBOSE: print(f"Failure: No command_str for command artifact '{display_name}'.")
            return False
        output_file = os.path.join(category_output_path, artifact_info.get("output_file", f"{artifact_key}_output.txt"))
        if VERBOSE: print(f"  Executing '{command_str}' saving to '{output_file}'...")
        result = execute_adb_command(command_str.split(), device_serial)
        if result.returncode == 0:
            try:
                with open(output_file, 'w', encoding='utf-8') as f: f.write(result.stdout)
                if VERBOSE: print(f"  Success: Command output saved.")
                return True
            except IOError as e:
                if VERBOSE: print(f"  Failure: Could not write output to file: {e}")
                return False
        else:
            if VERBOSE: print(f"  Failure: Command failed. RC:{result.returncode}, Err:{result.stderr.strip()}")
            return False
    else:
        if VERBOSE: print(f"Warning: Unknown type '{artifact_type}' for '{display_name}'.")
        return False

# --- Main Application Logic ---
def run_extraction(args):
    global VERBOSE
    if args.verbose: VERBOSE = True

    adb_exe = find_adb_exe()
    if not adb_exe: return

    device_serial = get_device_serial(args.device, adb_exe)
    if not device_serial:
        if args.device: print(f"Error: Specified device '{args.device}' not found or 'adb devices' failed.")
        return

    if VERBOSE: print(f"Target device serial: {device_serial}")

    if args.list_artifacts:
        print("\nAvailable artifacts:")
        for key, info in ARTIFACTS_DB.items(): print(f"  - {key}: {info.get('display_name', 'N/A')}")
        return

    keys_to_extract = []
    if args.all:
        keys_to_extract = list(ARTIFACTS_DB.keys())
        if VERBOSE: print("Extracting all defined artifacts.")
    elif args.artifacts:
        keys_to_extract = [key.strip() for key in args.artifacts.split(',')]
        if VERBOSE: print(f"Extracting specified artifacts: {keys_to_extract}")
    else:
        print("No artifacts specified. Use --artifacts KEY1,KEY2 or --all. Use --list-artifacts to see keys.")
        return

    if not keys_to_extract:
        print("No artifacts selected for extraction.")
        return

    device_specific_output_dir = os.path.join(args.output, device_serial.replace(":", "_").replace(" ", "_"))
    os.makedirs(device_specific_output_dir, exist_ok=True)
    if VERBOSE: print(f"\nStarting extraction for device {device_serial} into '{device_specific_output_dir}'")

    total_artifacts = len(keys_to_extract)
    successful_extractions = 0
    for i, key in enumerate(keys_to_extract):
        if VERBOSE: print(f"\n--- Processing artifact {i+1}/{total_artifacts}: {key} ---")
        if key in ARTIFACTS_DB:
            if extract_artifact(key, ARTIFACTS_DB[key], device_specific_output_dir, device_serial):
                successful_extractions += 1
        else:
            print(f"Warning: Artifact key '{key}' not found in database. Skipping.")

    print(f"\nExtraction summary for device {device_serial}:")
    print(f"  Successfully extracted {successful_extractions}/{total_artifacts} specified artifact(s).")
    print(f"  Output saved to: {device_specific_output_dir}")

if __name__ == '__main__':
    parser = setup_arg_parser()
    args = parser.parse_args()
    if args.verbose:
        VERBOSE = True # Set global VERBOSE early
        if VERBOSE: print("Verbose mode enabled.") # Confirm it's set
    run_extraction(args)
    if VERBOSE: print("\nScript finished.")
