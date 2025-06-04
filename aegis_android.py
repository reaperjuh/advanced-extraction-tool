import os
import subprocess
import datetime
import time
import shutil
import logging
import csv # Added for content provider extraction
import re # Added for parsing content query output
import tarfile # Added for WhatsApp extraction
from pathlib import Path # Added for more robust path handling
import argparse # Added for CLI
import sqlite3 # Added for Chrome parsing
import json # Added for Chrome parsing

# Global constants for tool paths - will be set by find_tool
# These are not strictly used if instance variables are set correctly.
# ADB_PATH = None
# SCRCPY_PATH = None

class AegisExtractor:
    def __init__(self, base_output_dir_cli=None, adb_path_override=None, scrcpy_path_override=None):
        # Determine tool paths
        if adb_path_override and Path(adb_path_override).exists() and os.access(adb_path_override, os.X_OK):
            self.adb_path = str(Path(adb_path_override).resolve())
            # Initial print before logging is configured, if path is overridden
            print(f"DEBUG: Using ADB override path: {self.adb_path}")
        else:
            if adb_path_override: # User provided a path but it was invalid
                 print(f"Warning: ADB path override '{adb_path_override}' is invalid. Attempting to find ADB automatically.")
            self.adb_path = self._find_tool("adb.exe" if os.name == 'nt' else "adb")

        if scrcpy_path_override and Path(scrcpy_path_override).exists() and os.access(scrcpy_path_override, os.X_OK) :
            self.scrcpy_path = str(Path(scrcpy_path_override).resolve())
            print(f"DEBUG: Using SCRCPY override path: {self.scrcpy_path}")
        else:
            if scrcpy_path_override:
                 print(f"Warning: SCRCPY path override '{scrcpy_path_override}' is invalid. Attempting to find SCRCPY automatically.")
            self.scrcpy_path = self._find_tool("scrcpy.exe" if os.name == 'nt' else "scrcpy")

        # self.abe_jar_path = self._find_tool("abe.jar") # Found on demand in WhatsApp method
        # self.java_path = self._find_java_executable() # Found on demand in WhatsApp method

        # Root status initialization
        self.is_root = False
        self.root_status_checked = False
        self.root_enabled_by_script = False # Flag to track if this script instance enabled root

        if not self.adb_path:
            print("CRITICAL Error: adb (or adb.exe) not found. Please ensure it's in the script's directory, ./bin, your system PATH, or provide a valid path via --adb-path.")
            # Logging might not be configured yet, so this is a direct print.
            logging.error("adb.exe (or adb) not found during initialization and no valid override provided.")
            exit(1)

        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # Determine base for output directory
        if base_output_dir_cli and Path(base_output_dir_cli).is_dir():
            chosen_base_dir = Path(base_output_dir_cli).resolve()
        elif base_output_dir_cli: # Path provided but not a valid directory
            print(f"Warning: Provided base output directory '{base_output_dir_cli}' is not valid. Using script's directory as base.")
            chosen_base_dir = Path(__file__).resolve().parent
        else: # Default to script's directory
            chosen_base_dir = Path(__file__).resolve().parent

        self.output_dir = chosen_base_dir / f"aegis_output_{self.timestamp}"

        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except OSError as e:
            # If directory creation fails, logging to file is not possible.
            print(f"Critical Error: Cannot create output directory {self.output_dir}. Reason: {e}")
            logging.error(f"Cannot create output directory {self.output_dir}. Reason: {e}", exc_info=True)
            exit(1)

        # Setup logging
        log_file_path = os.path.join(self.output_dir, "aegis_extraction.log")
        logging.basicConfig(
            handlers=[
                logging.FileHandler(log_file_path),
                logging.StreamHandler() # Also log to console
            ],
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        logging.info("AegisExtractor initialized. Output directory: %s", self.output_dir)
        logging.info(f"ADB found at: {self.adb_path}") # Log path after logging is configured

        if not self.scrcpy_path:
            logging.warning("scrcpy.exe (or scrcpy) not found. Advanced screen capture may not work.")
            # No exit, as scrcpy is optional for some functions
        else:
            logging.info(f"SCRCPY found at: {self.scrcpy_path}")

        # Create directory for content provider data
        self.content_provider_dir = os.path.join(self.output_dir, "content_provider_data")
        try:
            os.makedirs(self.content_provider_dir, exist_ok=True)
            logging.info(f"Content provider data directory created at: {self.content_provider_dir}")
        except OSError as e:
            logging.error(f"Failed to create content provider data directory {self.content_provider_dir}: {e}", exc_info=True)
            # This might not be critical enough to exit, but extraction will fail.
            print(f"Error: Could not create directory {self.content_provider_dir}. Content provider extraction will be skipped.")

    def _find_java_executable(self):
        logging.debug("Searching for Java executable...")
        # Prefer JAVA_HOME if set
        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            # Common paths for java executable within JAVA_HOME
            java_exe_paths = [
                Path(java_home) / "bin" / "java.exe", # Windows
                Path(java_home) / "bin" / "java"      # Linux/macOS
            ]
            for p in java_exe_paths:
                if p.exists() and os.access(p, os.X_OK):
                    logging.info(f"Found Java executable via JAVA_HOME: {p.resolve()}")
                    return str(p.resolve())

        # Fallback to shutil.which (checks system PATH)
        java_exe = shutil.which("java") or shutil.which("java.exe") # Handles .exe for Windows
        if java_exe:
            logging.info(f"Found Java executable in PATH: {Path(java_exe).resolve()}")
            return str(Path(java_exe).resolve())

        logging.warning("Java executable not found in JAVA_HOME or system PATH.")
        return None

    def _find_tool(self, tool_name_full): # e.g. "adb.exe", "scrcpy", "abe.jar"
        """Finds a given tool (executable or JAR) and returns its absolute path."""
        logging.debug(f"Searching for tool: {tool_name_full}...")

        # Get directory of the script using pathlib for robustness
        script_file_path = Path(__file__).resolve() # Get absolute path of the script
        script_dir = script_file_path.parent

        # Paths to check: script's directory, ./bin subdirectory relative to script
        search_paths_config = [
            {"path": script_dir, "label": "script directory"},
            {"path": script_dir / 'bin', "label": "./bin subdirectory"},
        ]

        for loc in search_paths_config:
            candidate = loc["path"] / tool_name_full
            if candidate.exists():
                # For executables, also check if it's executable
                if not tool_name_full.endswith(".jar") and not os.access(candidate, os.X_OK):
                    logging.warning(f"Found {tool_name_full} at {candidate} but it is not executable. Skipping.")
                    continue
                logging.info(f"Found {tool_name_full} in {loc['label']}: {candidate.resolve()}")
                return str(candidate.resolve())

        # For executables (not .jar files), also try finding in system PATH as a last resort
        if not tool_name_full.endswith(".jar"):
            system_path_tool = shutil.which(tool_name_full)
            if system_path_tool:
                # Ensure it's executable (shutil.which usually does, but double check)
                if os.access(system_path_tool, os.X_OK):
                    logging.info(f"Found {tool_name_full} in system PATH: {Path(system_path_tool).resolve()}")
                    return str(Path(system_path_tool).resolve())
                else:
                    logging.warning(f"Found {tool_name_full} in system PATH at {system_path_tool} but it is not executable.")

        # Initial "DEBUG" print for pre-logging phase if called before logging is fully set up
        # This is more for the initial adb/scrcpy find if those were to use this before __init__ configures logging.
        # However, with current structure, logging should be set up by the time this is robustly used.
        print(f"DEBUG: {tool_name_full} not found in script directory, ./bin, or system PATH (if applicable).")
        logging.warning(f"{tool_name_full} not found after checking script dir, ./bin, and system PATH (if applicable).")
        return None


    def check_connection(self):
        """Checks for connected Android devices."""
        logging.info("Checking for connected devices...")
        # adb_path is already checked in __init__
        try:
            # Using "adb devices -l" for more detailed output if needed, but standard "devices" is fine.
            result = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True, check=True, timeout=10, errors='ignore')
            logging.debug("ADB devices result: \n%s", result.stdout) # Log full output at debug level

            # Process output to find actual devices
            lines = result.stdout.strip().splitlines()
            devices_found = []
            if len(lines) > 1: # First line is "List of devices attached"
                for line in lines[1:]:
                    if line.strip() and "\tdevice" in line and "emulator" not in line: # Basic filter for real devices
                        devices_found.append(line.split("\t")[0])

            if devices_found:
                logging.info(f"Connected real devices: {devices_found}")
                print(f"Connected devices: {', '.join(devices_found)}")
                return True
            else:
                logging.warning("No active devices found, or only emulators detected. Check connection and USB debugging authorization.")
                print("No active (non-emulator) devices found. Please connect an Android device with USB debugging enabled and authorized.")
                # More detailed check for common issues
                if "unauthorized" in result.stdout:
                    logging.warning("A device is connected but unauthorized. Please authorize USB debugging on the device.")
                    print("A device is connected but unauthorized. Please check your device screen to authorize USB debugging.")
                elif "offline" in result.stdout:
                    logging.warning("A device is listed as offline. Try reconnecting the device or restarting ADB server.")
                    print("A device is listed as offline. Please try reconnecting or checking ADB.")
                return False

        except FileNotFoundError: # Should not happen due to __init__ check, but as a safeguard for the method
            logging.error(f"adb command not found at {self.adb_path}. Critical error.")
            print(f"Error: adb command not found at {self.adb_path}.")
            return False
        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing 'adb devices': {e.cmd}, Return Code: {e.returncode}\nStderr: {e.stderr}")
            print(f"Error executing adb devices. ADB may not be working correctly or no device connected: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            logging.error("'adb devices' command timed out. ADB server might be unresponsive.")
            print("Error: 'adb devices' command timed out. Try 'adb kill-server && adb start-server'.")
            return False
        except Exception as e:
            logging.error(f"An unexpected error occurred during device check: {e}", exc_info=True)
            print(f"An unexpected error occurred during device check: {e}")
            return False


    def _execute_adb_command_to_file(self, command_parts, file_handle, title, timeout=30):
        """Helper to execute an ADB command and write its output to a file."""
        file_handle.write(f"--- {title} ---\n")
        full_cmd = [self.adb_path] + command_parts

        try:
            logging.info(f"Executing: {' '.join(full_cmd)}")
            result = subprocess.run(full_cmd, capture_output=True, text=True, check=False, timeout=timeout, errors='ignore')

            output = result.stdout.strip() if result.stdout else ""
            stderr_output = result.stderr.strip() if result.stderr else ""

            if not output and not stderr_output:
                output = "(No output or property not found)"
                logging.warning(f"Command '{' '.join(full_cmd)}' produced no output.")

            if output:
                file_handle.write(output + "\n")

            if stderr_output:
                # Log stderr as warning or error based on typical command behavior
                if result.returncode != 0 :
                    logging.error(f"Command '{' '.join(full_cmd)}' failed. RC: {result.returncode}. Stderr: {stderr_output}")
                    file_handle.write(f"ERROR (RC: {result.returncode}): {stderr_output}\n")
                else: # Some commands write to stderr for info (e.g. getprop non-existent prop)
                    logging.info(f"Command '{' '.join(full_cmd)}' produced stderr output (RC: {result.returncode}): {stderr_output}")
                    file_handle.write(f"Info (Stderr): {stderr_output}\n")

            if result.returncode != 0:
                 logging.warning(f"Command '{' '.join(full_cmd)}' completed with non-zero return code: {result.returncode}")
            else:
                logging.info(f"Successfully executed '{' '.join(full_cmd)}'.")

        except subprocess.CalledProcessError as e: # Should be caught by check=False and RC check, but for safety
            error_msg = f"ERROR: Command '{' '.join(e.cmd)}' failed critically. Return code: {e.returncode}."
            if e.stderr: error_msg += f" Stderr: {e.stderr.strip()}"
            logging.error(error_msg)
            file_handle.write(f"{error_msg}\n")
        except subprocess.TimeoutExpired:
            logging.warning(f"Command '{' '.join(full_cmd)}' timed out after {timeout}s.")
            file_handle.write("ERROR: Command timed out.\n")
        except Exception as e:
            logging.error(f"An unexpected error occurred while executing '{' '.join(full_cmd)}': {e}", exc_info=True)
            file_handle.write(f"ERROR: An unexpected error occurred: {str(e)}\n")
        finally:
            file_handle.write("\n") # Ensure separation for next command's output

    def _execute_adb_query_command(self, command_parts, timeout=30):
        """Helper to execute an ADB command and return its output for parsing."""
        full_cmd = [self.adb_path] + command_parts
        try:
            logging.info(f"Executing query: {' '.join(full_cmd)}")
            result = subprocess.run(full_cmd, capture_output=True, text=True, check=False, timeout=timeout, errors='ignore')

            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if result.returncode != 0:
                logging.error(f"ADB query command '{' '.join(full_cmd)}' failed. RC: {result.returncode}. Stderr: {stderr}")
                return None # Indicate failure clearly

            if stderr and "No result found" not in stderr and "Unknown URL" not in stderr : # Some informative messages go to stderr
                 logging.warning(f"ADB query command '{' '.join(full_cmd)}' produced stderr: {stderr}")

            logging.info(f"ADB query command '{' '.join(full_cmd)}' successful.")
            return stdout # Return stdout for parsing

        except subprocess.TimeoutExpired:
            logging.error(f"ADB query command '{' '.join(full_cmd)}' timed out after {timeout}s.")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred during ADB query '{' '.join(full_cmd)}': {e}", exc_info=True)
            return None

    def _parse_content_query_output(self, query_output_str):
        """Parses the output of 'adb shell content query' into a list of dictionaries."""
        # Example Row: Row: 0 _id=1, display_name=John Doe, phone_number=1234567890
        # Example Row: Row: 1 _id=2, display_name=Jane Doe, phone_number=0987654321
        # Need to handle cases where a field might be null or missing.
        # The regex tries to match "key=value" pairs. Value can be empty.
        parsed_rows = []
        if not query_output_str:
            return parsed_rows

        # Split by "Row: " marker, but handle potential empty strings or malformed lines
        raw_rows = query_output_str.split("Row: ")

        for raw_row_data in raw_rows:
            if not raw_row_data.strip():
                continue # Skip empty splits

            # Remove the row index part (e.g., "0 ", "1 ") if present after "Row: "
            row_content = re.sub(r"^\d+\s+", "", raw_row_data.strip())

            row_dict = {}
            # Regex to find "key=value" pairs. It handles values that might be empty or contain spaces
            # if not immediately followed by another comma-separated key.
            # This regex is tricky because values can be empty or contain commas if quoted (though adb output doesn't quote).
            # Simpler split by comma, then by '=' for each part.
            parts = row_content.split(',')
            for part in parts:
                key_value = part.split('=', 1)
                if len(key_value) == 2:
                    key = key_value[0].strip()
                    value = key_value[1].strip()
                    # Handle 'null' string as None or empty, depending on preference
                    if value == 'null':
                        value = ''
                    row_dict[key] = value
            if row_dict: # Ensure we don't add empty dictionaries if parsing fails for a line
                parsed_rows.append(row_dict)
        return parsed_rows

    def _format_timestamp_ms(self, timestamp_ms_str, default_if_error=''):
        """Converts a timestamp in milliseconds string to a human-readable date string."""
        if not timestamp_ms_str or not timestamp_ms_str.isdigit():
            return default_if_error
        try:
            # Convert milliseconds to seconds
            timestamp_s = int(timestamp_ms_str) / 1000
            return datetime.datetime.fromtimestamp(timestamp_s).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            logging.warning(f"Could not parse timestamp: {timestamp_ms_str}")
            return default_if_error
        except Exception as e:
            logging.error(f"Error formatting timestamp {timestamp_ms_str}: {e}")
            return default_if_error


    def extract_device_info(self):
        """Extracts and saves a comprehensive set of device information."""
        logging.info("Starting comprehensive device information extraction...")
        device_info_dir = os.path.join(self.output_dir, "device_info")
        os.makedirs(device_info_dir, exist_ok=True)
        # Changed filename as per task description
        output_file_path = os.path.join(device_info_dir, "comprehensive_device_info.txt")

        # Define categories and commands
        # Each command is a list of arguments for adb [shell] <command_parts>
        # Some commands are direct adb commands (e.g. get-serialno), others are adb shell commands.
        # The helper _execute_adb_command_to_file prepends self.adb_path.
        # So, for adb shell commands, the list should start with "shell".

        info_commands = {
            "Device Properties (getprop)": [
                # Basic Device Info
                ["shell", "getprop", "ro.product.model"],
                ["shell", "getprop", "ro.product.manufacturer"],
                ["shell", "getprop", "ro.product.brand"],
                ["shell", "getprop", "ro.product.name"],
                ["shell", "getprop", "ro.product.device"],
                ["shell", "getprop", "ro.product.board"],
                # Build Information
                ["shell", "getprop", "ro.build.version.release"],
                ["shell", "getprop", "ro.build.version.sdk"],
                ["shell", "getprop", "ro.build.version.security_patch"],
                ["shell", "getprop", "ro.build.id"],
                ["shell", "getprop", "ro.build.display.id"],
                ["shell", "getprop", "ro.build.fingerprint"],
                ["shell", "getprop", "ro.build.date"],
                ["shell", "getprop", "ro.build.type"],
                ["shell", "getprop", "ro.build.tags"],
                ["shell", "getprop", "ro.build.user"],
                ["shell", "getprop", "ro.build.host"],
                # Serial Numbers (may require permissions or not exist)
                ["get-serialno"], # Direct ADB command
                ["shell", "getprop", "ro.serialno"],
                ["shell", "getprop", "ril.serialnumber"],
                ["shell", "getprop", "sys.serialnumber"],
                # Boot Information
                ["shell", "getprop", "ro.boot.bootloader"],
                ["shell", "getprop", "ro.bootmode"],
                ["shell", "getprop", "ro.hardware"],
                ["shell", "getprop", "ro.boot.hardware"],
                ["shell", "getprop", "ro.boot.verifiedbootstate"],
                ["shell", "getprop", "ro.boot.vbmeta.digest"],
                # System & Locale
                ["shell", "getprop", "persist.sys.timezone"],
                ["shell", "getprop", "persist.sys.locale"],
                ["shell", "getprop", "persist.sys.country"],
                ["shell", "getprop", "persist.sys.language"],
                # Telephony (may require permissions or SIM)
                ["shell", "getprop", "gsm.sim.operator.alpha"],
                ["shell", "getprop", "gsm.sim.operator.iso-country"],
                ["shell", "getprop", "gsm.sim.operator.numeric"],
                ["shell", "getprop", "gsm.network.type"],
                ["shell", "getprop", "ril.ecclist"], # Emergency numbers
                # Crypto State
                ["shell", "getprop", "ro.crypto.state"],
                ["shell", "getprop", "ro.crypto.type"],
                ["shell", "getprop", "ro.crypto.hw"],
                # Default Sounds
                ["shell", "getprop", "ro.config.notification_sound"],
                ["shell", "getprop", "ro.config.alarm_alert"],
                ["shell", "getprop", "ro.config.ringtone"],
                # Other interesting props
                ["shell", "getprop", "ro.allow.mock.location"],
                ["shell", "getprop", "ro.secure"],
                ["shell", "getprop", "ro.debuggable"],
                ["shell", "getprop", "sys.usb.state"], # Current USB connection state
                ["shell", "getprop", "init.svc.adbd"], # ADB daemon status
            ],
            "Settings Lists": [
                ["shell", "settings", "list", "system"],
                ["shell", "settings", "list", "secure"],
                ["shell", "settings", "list", "global"],
            ],
            "Network Information": [
                ["shell", "ip", "address"], # Shows all interfaces, more comprehensive than specific wlan0
                ["shell", "ip", "route"], # IP routing table
                ["shell", "ip", "neigh"], # ARP cache / neighbor table
                ["shell", "ifconfig", "-a"], # Fallback/alternative for network interfaces
                ["shell", "settings", "get", "secure", "bluetooth_address"],
                ["shell", "settings", "get", "secure", "bluetooth_name"],
                ["shell", "dumpsys", "connectivity", "--short"], # Connectivity service summary
            ],
            "Package Manager Information": [
                ["shell", "pm", "list", "features"],
                ["shell", "pm", "list", "libraries"], # Shared libraries on device
                ["shell", "pm", "list", "packages", "-f"], # All packages with APK path
                ["shell", "pm", "list", "packages", "-3", "-f"], # Third-party packages with APK path
                ["shell", "pm", "list", "packages", "-s", "-f"], # System packages with APK path
                ["shell", "pm", "list", "permission-groups"],
                ["shell", "pm", "list", "permissions", "-g", "-d"], # Dangerous permissions, grouped
            ],
            "Process & Service Information": [
                ["shell", "ps", "-A", "-o", "PID,PPID,USER,GROUP,ARGS"], # Comprehensive process list
                ["shell", "service", "list"], # List all system services
                ["shell", "dumpsys", "activity", "processes"], # Detailed process info from Activity Manager
            ],
            "System & Hardware Details": [
                ["shell", "uptime"],
                ["shell", "date"],
                ["shell", "df", "-h"], # Filesystem disk space
                ["shell", "cat", "/proc/version"], # Linux kernel version
                ["shell", "cat", "/proc/cpuinfo"], # CPU details (can be restricted)
                ["shell", "cat", "/proc/meminfo"], # Memory details (can be restricted)
                ["shell", "cat", "/proc/partitions"], # Device partitions (can be restricted)
                ["shell", "cat", "/proc/interrupts"], # Interrupts (can be restricted)
                ["shell", "dumpsys", "cpuinfo"], # CPU usage from dumpsys
                ["shell", "dumpsys", "meminfo", "--checkin"], # Parsable memory info
                ["shell", "dumpsys", "diskstats"], # Disk I/O statistics
                ["shell", "dumpsys", "batteryproperties"], # More detailed battery info
                ["shell", "dumpsys", "media.camera"], # Camera service info
                ["shell", "dumpsys", "sensorservice"], # Sensor service info
            ],
            "Telephony & SIM Information (May Require Permissions)": [
                 # dumpsys iphonesubinfo can be very slow or fail if no permission
                ["shell", "dumpsys", "iphonesubinfo"],
                ["shell", "dumpsys", "telephony.registry"],
            ],
            "User & Account Information (May Require Permissions)": [
                ["shell", "dumpsys", "user"], # User service info
                ["shell", "pm", "list", "users"], # List users on device
            ],
        }

        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(f"Comprehensive Device Information Report - Generated on {self.timestamp}\n")
            f.write(f"Output Directory: {self.output_dir}\n")
            f.write("=" * 70 + "\n")

            for category, cmd_set in info_commands.items():
                f.write(f"\n\n=== {category} ===\n")
                logging.info(f"Extracting category: {category}")
                for cmd_parts in cmd_set:
                    # Determine command title for the report
                    if cmd_parts[0] == "shell":
                        title = f"adb shell {' '.join(cmd_parts[1:])}"
                    else: # Direct adb command like get-serialno
                        title = f"adb {' '.join(cmd_parts)}"

                    # Use a longer timeout for dumpsys commands as they can be slow
                    timeout = 60 if "dumpsys" in cmd_parts else 30
                    self._execute_adb_command_to_file(cmd_parts, f, title, timeout=timeout)

        logging.info(f"Comprehensive device information extraction complete. Saved to {output_file_path}")
        print(f"Comprehensive device information saved to {output_file_path}")

        # Still print device model to console for quick feedback
        try:
            model_cmd = [self.adb_path, "shell", "getprop", "ro.product.model"]
            result = subprocess.run(model_cmd, capture_output=True, text=True, check=False, timeout=10, errors='ignore')
            if result.stdout and result.returncode == 0:
                model_name = result.stdout.strip()
                print(f"Device Model: {model_name}")
                logging.info(f"Successfully retrieved and printed device model: {model_name}")
            else:
                print("Could not retrieve device model for console display.")
                logging.warning(f"Could not retrieve device model for console display. RC: {result.returncode}, Stderr: {result.stderr.strip()}")
        except Exception as e:
            print(f"Error retrieving device model for console display: {e}")
            logging.error(f"Error retrieving device model for console display: {e}", exc_info=True)


    def pull_data(self, directories_to_pull=None):
        """Pulls specified common user directories from /sdcard/ on the device."""
        logging.info("Starting file system data pulling process...")

        if directories_to_pull is None or not directories_to_pull:
            directories_to_pull = [
                "DCIM", "Download", "Documents", "Pictures",
                "Movies", "Music", "Android/media/com.whatsapp/WhatsApp/Media"
            ]

        base_remote_path = "/sdcard"
        pulled_files_main_dir = os.path.join(self.output_dir, "pulled_files")
        os.makedirs(pulled_files_main_dir, exist_ok=True)
        logging.info(f"User data will be pulled to subdirectories within: {pulled_files_main_dir}")

        for dir_name in directories_to_pull:
            remote_source_path = f"{base_remote_path}/{dir_name}"
            # Create a specific subdirectory for this pull under pulled_files_main_dir
            local_target_subdirectory = os.path.join(pulled_files_main_dir, dir_name.replace('/', '_')) # Replace / for nested paths like WhatsApp
            os.makedirs(local_target_subdirectory, exist_ok=True)

            logging.info(f"Attempting to pull: {remote_source_path} into {local_target_subdirectory}")

            # The adb pull command will copy contents of remote_source_path into local_target_subdirectory
            # e.g., adb pull /sdcard/DCIM C:\output\pulled_files\DCIM
            # The local_target_subdirectory itself is the destination.
            cmd = [self.adb_path, "pull", remote_source_path, str(local_target_subdirectory)]

            try:
                # Using a very long timeout for potentially large directory pulls
                # subprocess.run will block until pull is complete or timeout
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, errors='ignore') # 30 min timeout

                if result.returncode == 0:
                    # ADB pull output can be noisy with "skipped file" messages that are not critical errors.
                    # Check for common indicators of failure in stdout/stderr.
                    if "does not exist" in result.stderr or "0 files pulled" in result.stdout:
                        logging.warning(f"Directory '{remote_source_path}' may not exist or is empty. Stderr: {result.stderr.strip()}, Stdout: {result.stdout.strip()}")
                        print(f"Warning: '{remote_source_path}' not found on device or is empty.")
                    else:
                        logging.info(f"Successfully pulled '{remote_source_path}' to '{local_target_subdirectory}'. Stdout: {result.stdout.strip()}")
                        print(f"Successfully pulled '{remote_source_path}' to '{local_target_subdirectory}'.")
                else:
                    logging.error(f"Error pulling '{remote_source_path}'. Return Code: {result.returncode}. Stdout: {result.stdout.strip()}. Stderr: {result.stderr.strip()}")
                    print(f"Error pulling '{remote_source_path}'. Check logs for details.")

            except subprocess.TimeoutExpired:
                logging.error(f"Timeout pulling '{remote_source_path}'. This can happen with very large directories or slow connections.")
                print(f"Error: Timeout pulling '{remote_source_path}'. Pull may be incomplete.")
            except Exception as e:
                logging.error(f"An unexpected error occurred while pulling '{remote_source_path}': {e}", exc_info=True)
                print(f"An unexpected error occurred while pulling '{remote_source_path}'.")

        logging.info("File system data pulling process completed.")
        print(f"File system data pulling finished. Check relevant subdirectories in {pulled_files_main_dir} and logs for details.")


    def extract_contacts(self):
        logging.info("Starting contacts extraction...")
        if not self.content_provider_dir:
            logging.error("Content provider directory not set. Skipping contacts extraction.")
            return

        contacts_file = os.path.join(self.content_provider_dir, "contacts.csv")

        # Query basic contact info
        uri_contacts = "content://com.android.contacts/contacts"
        projection_contacts = "_id,display_name,has_phone_number"
        contacts_query_cmd = ["shell", "content", "query", "--uri", uri_contacts, "--projection", projection_contacts]

        raw_contacts_output = self._execute_adb_query_command(contacts_query_cmd)
        if raw_contacts_output is None:
            logging.error("Failed to query contacts provider. Skipping contacts extraction.")
            print("Error: Could not query contacts. See logs.")
            return

        parsed_contacts = self._parse_content_query_output(raw_contacts_output)
        if not parsed_contacts:
            logging.info("No contacts found or output was not parsable.")
            print("No contacts found or data unreadable.")
            # Still create empty CSV with headers
            with open(contacts_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["contact_id", "display_name", "phone_numbers", "email_addresses"])
            return

        all_contacts_data = []
        for contact in parsed_contacts:
            contact_id = contact.get("_id", "")
            display_name = contact.get("display_name", "")
            has_phone = contact.get("has_phone_number", "0")

            phone_numbers = []
            if has_phone == "1":
                uri_phones = f"content://com.android.contacts/data/phones" # Older: content://contacts/phones
                # More common projection: content://com.android.contacts/data where MIMETYPE is phone_v2 and contact_id is X
                # Using simpler content://com.android.contacts/data/phones for now.
                # This URI might not be universally supported. A more robust way is via 'data' table with MIMETYPE.
                # projection_phones = "data1" # data1 is usually the phone number
                # where_phones = f"contact_id={contact_id}" # This simple URI might not support --where
                # For now, let's try a common alternative for phone numbers directly if data/phones is not good.
                # Better: query data table with specific mimetype
                phone_query_cmd = ["shell", "content", "query", "--uri", "content://com.android.contacts/data",
                                   "--projection", "data1", # data1 usually stores the number for phone mimetype
                                   "--where", f"mimetype='vnd.android.cursor.item/phone_v2' AND contact_id={contact_id}"]

                raw_phones_output = self._execute_adb_query_command(phone_query_cmd)
                if raw_phones_output:
                    parsed_phones = self._parse_content_query_output(raw_phones_output)
                    for phone_data in parsed_phones:
                        phone_numbers.append(phone_data.get("data1", ""))

            emails = []
            email_query_cmd = ["shell", "content", "query", "--uri", "content://com.android.contacts/data",
                               "--projection", "data1", # data1 usually stores the email for email mimetype
                               "--where", f"mimetype='vnd.android.cursor.item/email_v2' AND contact_id={contact_id}"]
            raw_emails_output = self._execute_adb_query_command(email_query_cmd)
            if raw_emails_output:
                parsed_emails = self._parse_content_query_output(raw_emails_output)
                for email_data in parsed_emails:
                    emails.append(email_data.get("data1", ""))

            all_contacts_data.append({
                "contact_id": contact_id,
                "display_name": display_name,
                "phone_numbers": ";".join(filter(None,phone_numbers)), # Semicolon separated
                "email_addresses": ";".join(filter(None,emails))  # Semicolon separated
            })

        with open(contacts_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["contact_id", "display_name", "phone_numbers", "email_addresses"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_contacts_data)

        logging.info(f"Contacts extraction complete. Saved to {contacts_file}")
        print(f"Contacts data saved to {contacts_file}")


    def extract_call_logs(self):
        logging.info("Starting call log extraction...")
        if not self.content_provider_dir: return

        call_logs_file = os.path.join(self.content_provider_dir, "call_logs.csv")
        uri = "content://call_log/calls"
        # Common fields: number, type, date, duration, name, new, countryiso, geocoded_location
        projection = "number,type,date,duration,name"
        query_cmd = ["shell", "content", "query", "--uri", uri, "--projection", projection] # Maybe add --sort "date DESC"

        raw_output = self._execute_adb_query_command(query_cmd)
        if raw_output is None:
            logging.error("Failed to query call logs provider. Skipping.")
            print("Error: Could not query call logs. See logs.")
            return

        parsed_logs = self._parse_content_query_output(raw_output)
        if not parsed_logs:
            logging.info("No call logs found or output was not parsable.")
            print("No call logs found or data unreadable.")
            with open(call_logs_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["number", "type", "date_ms", "duration_s", "name", "formatted_date", "call_type_label"])
            return

        call_type_map = {
            "1": "Incoming", "2": "Outgoing", "3": "Missed",
            "4": "Voicemail", "5": "Rejected", "6": "Blocked", "7": "Answered Externally"
        }

        with open(call_logs_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["number", "type", "date_ms", "duration_s", "name", "formatted_date", "call_type_label"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in parsed_logs:
                row_data = {
                    "number": row.get("number"),
                    "type": row.get("type"),
                    "date_ms": row.get("date"),
                    "duration_s": row.get("duration"),
                    "name": row.get("name", ""), # Name can be null
                    "formatted_date": self._format_timestamp_ms(row.get("date")),
                    "call_type_label": call_type_map.get(row.get("type"), "Unknown")
                }
                writer.writerow(row_data)

        logging.info(f"Call logs extraction complete. Saved to {call_logs_file}")
        print(f"Call logs data saved to {call_logs_file}")


    def extract_sms(self):
        logging.info("Starting SMS messages extraction...")
        if not self.content_provider_dir: return

        sms_file = os.path.join(self.content_provider_dir, "sms_messages.csv")
        # content://sms/ provides inbox, sent, drafts, outbox
        # Other URIs: content://sms/inbox, content://sms/sent, content://sms/draft, content://sms/outbox
        uri = "content://sms/"
        projection = "_id,thread_id,address,person,date,body,type,read,status,service_center"
        query_cmd = ["shell", "content", "query", "--uri", uri, "--projection", projection] # Maybe add --sort "date DESC"

        raw_output = self._execute_adb_query_command(query_cmd)
        if raw_output is None:
            logging.error("Failed to query SMS provider. Skipping.")
            print("Error: Could not query SMS messages. See logs.")
            return

        parsed_sms = self._parse_content_query_output(raw_output)
        if not parsed_sms:
            logging.info("No SMS messages found or output was not parsable.")
            print("No SMS messages found or data unreadable.")
            with open(sms_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["_id", "thread_id", "address", "person_id", "date_ms", "body", "type", "read_status", "message_status", "service_center", "formatted_date", "message_type_label"])
            return

        sms_type_map = {"1": "Inbox", "2": "Sent", "3": "Draft", "4": "Outbox", "5": "Failed", "6": "Queued"}
        read_map = {"0": "Unread", "1": "Read"}
        status_map = { # Based on Telephony.Sms.STATUS_* constants, might vary
            "-1": "None", "0": "Complete", "32": "Pending", "64": "Failed"
        }

        with open(sms_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["_id", "thread_id", "address", "person_id", "date_ms", "body", "type",
                          "read_status", "message_status", "service_center",
                          "formatted_date", "message_type_label", "read_label", "status_label"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in parsed_sms:
                row_data = {
                    "_id": row.get("_id"),
                    "thread_id": row.get("thread_id"),
                    "address": row.get("address"),
                    "person_id": row.get("person"), # person is contact_id from contacts
                    "date_ms": row.get("date"),
                    "body": row.get("body"),
                    "type": row.get("type"),
                    "read_status": row.get("read"),
                    "message_status": row.get("status"),
                    "service_center": row.get("service_center"),
                    "formatted_date": self._format_timestamp_ms(row.get("date")),
                    "message_type_label": sms_type_map.get(row.get("type"), "Unknown"),
                    "read_label": read_map.get(row.get("read"), "Unknown"),
                    "status_label": status_map.get(row.get("status"), "Unknown")
                }
                writer.writerow(row_data)

        logging.info(f"SMS messages extraction complete. Saved to {sms_file}")
        print(f"SMS messages data saved to {sms_file}")

    def _execute_adb_command(self, adb_command_list, timeout=60):
        """
        Executes a generic ADB command.
        'adb_command_list' should start with the adb executable, then adb arguments.
        Example: [self.adb_path, "backup", "-f", "backup.ab", "com.whatsapp"]
        Returns the subprocess.CompletedProcess object or None on error/timeout.
        """
        if not self.adb_path: # Should be caught by __init__ but good check
            logging.error("ADB path not set. Cannot execute command.")
            return None

        # Ensure adb_command_list[0] is self.adb_path if not already set by caller
        # For this helper, we assume the caller constructs the full command including self.adb_path
        # Example: backup_command = [self.adb_path, "backup", "-f", str(adb_backup_file), "-noapk", "com.whatsapp"]
        # So, adb_command_list here would be that full list.

        logging.info(f"Executing ADB command: {' '.join(adb_command_list)}")
        try:
            result = subprocess.run(
                adb_command_list,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False, # We check returncode manually
                errors='ignore'
            )
            if result.returncode != 0:
                logging.error(f"ADB command failed. RC: {result.returncode}. Command: {' '.join(adb_command_list)}")
                logging.error(f"Stderr: {result.stderr.strip()}")
                logging.error(f"Stdout: {result.stdout.strip()}")
            else:
                logging.info(f"ADB command successful. Stdout: {result.stdout.strip()[:200]}") # Log snippet of stdout
            return result
        except subprocess.TimeoutExpired:
            logging.error(f"ADB command timed out after {timeout}s: {' '.join(adb_command_list)}")
            return None
        except FileNotFoundError: # Should not happen if self.adb_path is correct
            logging.error(f"ADB command not found ({adb_command_list[0]}). Please ensure ADB is correctly configured.")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred executing ADB command {' '.join(adb_command_list)}: {e}", exc_info=True)
            return None

    def extract_whatsapp_data_guided(self):
        """Orchestrates the guided extraction of WhatsApp key and databases."""
        logging.info("Starting WhatsApp Key/Database Extraction (Guided Manual Process)...")
        self.whatsapp_dir = Path(self.output_dir) / "whatsapp_extraction"
        os.makedirs(self.whatsapp_dir, exist_ok=True)
        logging.info(f"WhatsApp extraction data will be saved in: {self.whatsapp_dir}")

        # Phase 1: Preparation - User Instructions
        print("\n--- WhatsApp Key/DB Extraction: Phase 1 (User Preparation) ---")
        print("IMPORTANT: This process involves uninstalling and reinstalling WhatsApp on your Android device.")
        print("It is CRUCIAL that you first BACK UP your current WhatsApp chats using the in-app Google Drive (or other cloud) backup feature if you wish to restore them later.")
        logging.info("Requesting user to backup current WhatsApp data via cloud.")
        input("Press Enter to continue ONLY after you have backed up your current WhatsApp data through its settings menu...")

        print("\n--- WhatsApp Extraction: Step 2 (Download Old APK & Uninstall Current WhatsApp) ---")
        print("Please download an old version of WhatsApp APK (e.g., version 2.11.431).")
        print("This specific version is known to be compatible with the ADB backup method for extracting the key.")
        print("A common source for such APKs is whatcrypt.com (though use any trusted source):")
        print("  http://www.whatcrypt.com/WhatsApp-2.11.431.apk")
        print("After downloading the old APK to your computer or device, please UNINSTALL your current WhatsApp application from your Android device.")
        logging.info("Requesting user to download old WhatsApp APK (e.g., 2.11.431) and uninstall current version.")
        input("Press Enter after downloading the old APK and uninstalling your current WhatsApp from the device...")

        print("\n--- WhatsApp Extraction: Step 3 (Install Old APK & Setup - CRITICAL STEP) ---")
        print("Please manually INSTALL the downloaded old WhatsApp APK (e.g., 2.11.431) onto your device.")
        print("After installation, open this old version of WhatsApp.")
        print("Verify your phone number. This is necessary for WhatsApp to create the local data files.")
        print("IMPORTANT: If this old version prompts you to restore chats from a cloud backup (e.g., Google Drive), choose SKIP or DECLINE.")
        print("DO NOT RESTORE FROM CLOUD BACKUP AT THIS STAGE. The goal is an empty, activated old version of WhatsApp.")
        logging.info("Requesting user to install old APK, verify number, and SKIP any cloud restore prompts.")
        input("Press Enter after installing the old WhatsApp, verifying your number, and SKIPPING any cloud restore prompts from the old version...")

        # Phase 2: Perform ADB Backup (Script-driven)
        logging.info("Starting ADB backup for com.whatsapp.")
        print("\n--- WhatsApp Extraction: Step 4 (Performing ADB Backup) ---")
        adb_backup_file = self.whatsapp_dir / "whatsapp_backup.ab"
        # Ensure self.adb_path is used for the command
        backup_command = [self.adb_path, "backup", "-f", str(adb_backup_file), "-noapk", "com.whatsapp"]

        print("Attempting to backup WhatsApp data via ADB. This may take several minutes.")
        print("Please check your device screen: you MUST CONFIRM the backup operation if prompted.")
        print("You may be asked to 'Allow USB debugging' if not already set, and then to 'Back up my data'.")
        print("DO NOT enter a password for the backup; leave it blank and tap 'Back up my data'.")

        # Using the new generic helper
        backup_result = self._execute_adb_command(backup_command, timeout=900) # 15 minutes timeout

        if backup_result is None or backup_result.returncode != 0 or not adb_backup_file.exists() or adb_backup_file.stat().st_size == 0:
            logging.error(f"ADB backup failed or produced an empty file. Return code: {backup_result.returncode if backup_result else 'N/A'}.")
            if adb_backup_file.exists(): logging.error(f"Backup file size: {adb_backup_file.stat().st_size}")
            print("\nError: ADB backup failed, was cancelled, or the backup file is empty/invalid.")
            print("Please check your device screen for any error messages during the backup attempt.")
            print("Ensure 'USB debugging (Security settings)' or 'ADB debugging in charge only mode' is enabled in Developer Options if available, as this is sometimes required for ADB backup.")
            print(f"The incomplete backup file (if created) is at: {adb_backup_file}")
            print("Cannot proceed with extraction from backup.")
            # Offer to skip to final restoration instructions
            if input("Do you want to skip to the final restoration instructions? (yes/no): ").lower() == 'yes':
                self._whatsapp_final_user_instructions()
            return

        logging.info(f"ADB backup successful: {adb_backup_file} (Size: {adb_backup_file.stat().st_size} bytes)")
        print(f"ADB backup of WhatsApp data appears successful: {adb_backup_file}")

        # Phase 3: Extract Data from ADB Backup (Script-driven with Java tool)
        print("\n--- WhatsApp Extraction: Step 5 (Unpacking Backup & Extracting Files) ---")
        java_path = self._find_java_executable()
        # Use the generic _find_tool for abe.jar
        abe_jar_path_str = self._find_tool("abe.jar")
        abe_jar_path = Path(abe_jar_path_str) if abe_jar_path_str else None


        if not java_path:
            logging.error("Java executable not found in PATH or JAVA_HOME.")
            print("Error: Java executable not found. Please ensure Java JRE/JDK is installed and 'java' is in your system's PATH or JAVA_HOME is set correctly. The .ab backup file has been saved but cannot be unpacked by this script.")
            self._whatsapp_final_user_instructions()
            return
        if not abe_jar_path or not abe_jar_path.exists():
            logging.error(f"abe.jar not found. Searched using _find_tool. Path: {abe_jar_path}")
            print(f"Error: abe.jar not found. Please place abe.jar (Android Backup Extractor) in the script's directory ('{Path(__file__).resolve().parent}') or a './bin' subdirectory. The .ab backup file has been saved but cannot be unpacked.")
            self._whatsapp_final_user_instructions()
            return

        logging.info(f"Found Java: {java_path}")
        logging.info(f"Found abe.jar: {abe_jar_path}")

        unpacked_tar_file = self.whatsapp_dir / "whatsapp_backup.tar"
        unpack_cmd = [java_path, "-jar", str(abe_jar_path), "unpack", str(adb_backup_file), str(unpacked_tar_file)]

        logging.info(f"Attempting to unpack .ab file using: {' '.join(unpack_cmd)}")
        print("Attempting to unpack the backup file (whatsapp_backup.ab) using Android Backup Extractor (abe.jar)... This may take a moment.")

        try:
            process = subprocess.run(unpack_cmd, capture_output=True, text=True, timeout=300, check=False, errors='ignore')
            if process.returncode == 0 and unpacked_tar_file.exists() and unpacked_tar_file.stat().st_size > 0:
                logging.info(f"Successfully unpacked .ab file to .tar. ABE Output (first 500 chars): {process.stdout[:500]}")
                print("Successfully unpacked .ab file to .tar format.")
            else:
                logging.error(f"Failed to unpack .ab file with abe.jar. Return code: {process.returncode}.")
                logging.error(f"ABE stdout: {process.stdout.strip()}")
                logging.error(f"ABE stderr: {process.stderr.strip()}")
                print("Error: Failed to unpack whatsapp_backup.ab using abe.jar.")
                print("This can happen if the backup was password-protected (this script requires no password),")
                print("or if there's an issue with abe.jar, Java version, or the backup file itself.")
                print("Please check the logs for ABE output. The .ab file is saved.")
                self._whatsapp_final_user_instructions()
                return
        except subprocess.TimeoutExpired:
            logging.error("Timeout expired while unpacking .ab file using abe.jar.")
            print("Error: Timeout while unpacking .ab file. The .ab file is saved.")
            self._whatsapp_final_user_instructions()
            return
        except Exception as e:
            logging.error(f"An exception occurred while unpacking .ab file: {e}", exc_info=True)
            print(f"An error occurred during abe.jar execution: {e}. The .ab file is saved.")
            self._whatsapp_final_user_instructions()
            return

        # Extract from TAR file
        extract_to_dir = self.whatsapp_dir / "_unpacked_tar_contents"
        try:
            os.makedirs(extract_to_dir, exist_ok=True)
            logging.info(f"Extracting contents of {unpacked_tar_file} to {extract_to_dir}")
            print(f"Extracting files from {unpacked_tar_file.name}...")
            found_key = False; found_msgstore = False; found_wa = False

            with tarfile.open(unpacked_tar_file, "r") as tar:
                # tar.extractall(path=extract_to_dir) # Potentially unsafe if TAR contains ".."
                # Safer extraction:
                for member in tar.getmembers():
                    member_path = os.path.join(extract_to_dir, member.name)
                    # Security: Prevent path traversal attacks.
                    if not os.path.abspath(member_path).startswith(os.path.abspath(extract_to_dir)):
                        logging.warning(f"Skipping potentially unsafe path in TAR: {member.name}")
                        continue
                    if member.isfile(): # Ensure it's a file
                        tar.extract(member, path=extract_to_dir)
                    elif member.isdir(): # Create directory if it's a directory entry
                        os.makedirs(member_path, exist_ok=True)


            logging.info("TAR extraction complete. Searching for key and database files...")

            # Define destination paths for the primary files
            key_file_dest = self.whatsapp_dir / "key"
            msgstore_db_dest = self.whatsapp_dir / "msgstore.db"
            wa_db_dest = self.whatsapp_dir / "wa.db"

            # Define common paths within the TAR where these files might be found
            # (Relative to the root of the extracted TAR contents)
            possible_paths = {
                "key": ["apps/com.whatsapp/f/key", "apps/com.whatsapp/files/key", "shared/0/WhatsApp/Databases/key"], # Legacy and current paths
                "msgstore.db": ["apps/com.whatsapp/db/msgstore.db", "shared/0/WhatsApp/Databases/msgstore.db"],
                "wa.db": ["apps/com.whatsapp/db/wa.db", "shared/0/WhatsApp/Databases/wa.db"] # For contact names
            }

            for file_type_key, paths_in_tar_list in possible_paths.items():
                for path_in_tar in paths_in_tar_list:
                    # Path.joinpath() is good for constructing paths
                    full_member_path = extract_to_dir / Path(path_in_tar)
                    if full_member_path.exists() and full_member_path.is_file():
                        # Determine destination path based on file_type_key
                        if file_type_key == "key": dest_path = key_file_dest
                        elif file_type_key == "msgstore.db": dest_path = msgstore_db_dest
                        elif file_type_key == "wa.db": dest_path = wa_db_dest
                        else: continue # Should not happen

                        shutil.copy2(str(full_member_path), str(dest_path))
                        logging.info(f"Found and copied {file_type_key} from {full_member_path} to {dest_path}")
                        print(f"{file_type_key.capitalize()} file extracted to {dest_path.name} in the WhatsApp extraction folder.")
                        if file_type_key == "key": found_key = True
                        if file_type_key == "msgstore.db": found_msgstore = True
                        if file_type_key == "wa.db": found_wa = True
                        break # Found for this file_type_key, move to next type

            if not found_key:
                logging.warning("'key' file not found in the backup tar.")
                print("Warning: 'key' file (for decryption) was not found in the backup.")
            if not found_msgstore:
                logging.warning("'msgstore.db' file not found in the backup tar.")
                print("Warning: 'msgstore.db' (main chat database) was not found in the backup.")
            if not found_wa: # wa.db is helpful but not always critical
                logging.info("'wa.db' (contacts/names database) not found in the backup tar. This is sometimes okay.")
                print("Info: 'wa.db' (for contact names) was not found. This is optional for basic decryption.")

        except tarfile.TarError as e:
            logging.error(f"Error extracting from tar file {unpacked_tar_file.name}: {e}", exc_info=True)
            print(f"Error: Could not extract files from {unpacked_tar_file.name}. It might be corrupted. Check logs.")
            self._whatsapp_final_user_instructions()
            return
        except Exception as e:
            logging.error(f"An unexpected error occurred during TAR processing: {e}", exc_info=True)
            print(f"An unexpected error occurred while processing the TAR file: {e}. Check logs.")
            self._whatsapp_final_user_instructions()
            return
        finally:
            # Cleanup temporary extracted tar contents and the .tar file itself
            if extract_to_dir.exists():
                try:
                    shutil.rmtree(extract_to_dir)
                    logging.info(f"Cleaned up temporary directory: {extract_to_dir}")
                except OSError as e:
                    logging.error(f"Error removing temporary directory {extract_to_dir}: {e}")
            if unpacked_tar_file.exists():
                try:
                    os.remove(unpacked_tar_file)
                    logging.info(f"Cleaned up temporary tar file: {unpacked_tar_file}")
                except OSError as e:
                    logging.error(f"Error removing temporary tar file {unpacked_tar_file}: {e}")

        # Phase 4: User Restoration Instructions
        self._whatsapp_final_user_instructions()

    def _whatsapp_final_user_instructions(self):
        """Displays the final instructions for restoring the latest WhatsApp and chat backup."""
        logging.info("Requesting user to restore latest WhatsApp and their original chat backup.")
        print("\n--- WhatsApp Extraction: Step 6 (Restore Latest WhatsApp & Your Chats) ---")
        print("The key/DB extraction process from the old WhatsApp version is now complete (or attempted).")
        print("\nPlease now UNINSTALL the old WhatsApp APK (e.g., 2.11.431) from your device.")
        print("Then, REINSTALL the latest version of WhatsApp from the Google Play Store (or your preferred app store).")
        print("During the setup of this new, latest WhatsApp, RESTORE your chats from the Google Drive (or other cloud) backup you made in the very first step.")
        print("This will bring your WhatsApp back to its normal state with your latest chats.")
        input("Press Enter after reinstalling the latest WhatsApp and restoring your chat backup from the cloud...")
        print(f"\nProcess finished. Any extracted WhatsApp files (key, msgstore.db, wa.db) are located in: {self.whatsapp_dir}")
        logging.info(f"WhatsApp guided extraction process finished. Files (if any) are in {self.whatsapp_dir}")


    def extract_targeted_app_data(self, package_names_list=None):
        logging.info("Starting targeted application data extraction...")
        default_packages = ["com.android.chrome", "org.telegram.messenger", "com.facebook.katana"] # Example list

        if package_names_list is None or not package_names_list:
            logging.info(f"No specific package names provided. Using default list for targeted app data extraction: {default_packages}")
            package_names_to_process = default_packages
            if not self.is_root: # For non-root, default list might be too broad or fail often with adb backup
                logging.warning("Running targeted app extraction with default list on a non-rooted device. Many backups might fail or yield no useful data.")
                # Consider using a more restricted default list for non-root, or none at all.
                # For now, will proceed with the same default list but users should be aware.
        else:
            logging.info(f"Using user-provided list for targeted app data extraction: {package_names_list}")
            package_names_to_process = package_names_list

        for package_name in package_names_to_process:
            logging.info(f"Processing targeted data extraction for package: {package_name}")
            print(f"\n[APP DATA] Attempting extraction for {package_name}...")

            if self.is_root:
                logging.info(f"Attempting ROOT-based extraction for {package_name}.")
                package_root_data_dir = Path(self.output_dir) / "rooted_app_data" / package_name
                data_data_dest = package_root_data_dir / "data_data"
                data_media_dest = package_root_data_dir / "data_media_0"

                os.makedirs(data_data_dest, exist_ok=True)
                os.makedirs(data_media_dest, exist_ok=True)

                # Pull /data/data/<package_name>
                source_path_data = f"/data/data/{package_name}"
                logging.info(f"Pulling (root): {source_path_data} to {data_data_dest}")
                pull_data_cmd = [self.adb_path, "pull", source_path_data, str(data_data_dest.parent)] # Pull into parent of data_data_dest
                pull_data_result = self._execute_adb_command(pull_data_cmd, timeout=900) # 15 mins
                if pull_data_result and pull_data_result.returncode == 0:
                    logging.info(f"Successfully pulled {source_path_data} to {data_data_dest.parent}")
                    print(f"  [ROOT] Successfully pulled {source_path_data} to {data_data_dest.parent}")
                else:
                    logging.warning(f"Failed to pull {source_path_data}. RC: {pull_data_result.returncode if pull_data_result else 'N/A'}. Check logs.")
                    print(f"  [ROOT] Failed to pull {source_path_data}. It might not exist or permissions denied despite root.")

                # Pull /data/media/0/<package_name>
                source_path_media = f"/data/media/0/{package_name}"
                logging.info(f"Pulling (root): {source_path_media} to {data_media_dest}")
                pull_media_cmd = [self.adb_path, "pull", source_path_media, str(data_media_dest.parent)]
                pull_media_result = self._execute_adb_command(pull_media_cmd, timeout=900)
                if pull_media_result and pull_media_result.returncode == 0:
                    logging.info(f"Successfully pulled {source_path_media} to {data_media_dest.parent}")
                    print(f"  [ROOT] Successfully pulled {source_path_media} to {data_media_dest.parent}")
                else:
                    logging.warning(f"Failed to pull {source_path_media}. RC: {pull_media_result.returncode if pull_media_result else 'N/A'}. This path may not exist for all apps.")
                    print(f"  [ROOT] Failed to pull {source_path_media} or it does not exist.")

            else: # Non-root fallback: ADB Backup
                logging.info(f"Root access not available for {package_name}. Attempting non-root ADB backup (opportunistic).")
                print("  [NON-ROOT] Root access not available. Attempting ADB backup (this is opportunistic and may not work for all apps or may yield limited data).")

                package_backup_data_dir = Path(self.output_dir) / "app_backup_data" / package_name
                os.makedirs(package_backup_data_dir, exist_ok=True)
                adb_backup_file = package_backup_data_dir / f"{package_name}_backup.ab"

                backup_command = [self.adb_path, "backup", "-f", str(adb_backup_file), "-noapk", package_name]
                print(f"    Attempting ADB backup for {package_name}. Please CONFIRM the backup on your device if prompted (no password needed).")

                backup_result = self._execute_adb_command(backup_command, timeout=900) # 15 mins

                if backup_result is None or backup_result.returncode != 0 or not adb_backup_file.exists() or adb_backup_file.stat().st_size == 0:
                    logging.error(f"ADB backup for {package_name} failed or produced an empty/invalid file. RC: {backup_result.returncode if backup_result else 'N/A'}")
                    if adb_backup_file.exists(): logging.error(f"Backup file size for {package_name}: {adb_backup_file.stat().st_size}")
                    print(f"    Error: ADB backup for {package_name} failed or was cancelled. Some apps do not allow backup.")
                    continue # Skip to next package

                logging.info(f"ADB backup successful for {package_name}: {adb_backup_file} (Size: {adb_backup_file.stat().st_size} bytes)")
                print(f"    ADB backup for {package_name} appears successful: {adb_backup_file.name}")

                # Unpack using ABE
                java_path = self._find_java_executable()
                abe_jar_path_str = self._find_tool("abe.jar")
                abe_jar_path = Path(abe_jar_path_str) if abe_jar_path_str else None

                if not java_path or not (abe_jar_path and abe_jar_path.exists()):
                    logging.warning(f"Java or abe.jar not found. Skipping unpacking of {adb_backup_file.name}. The .ab file is saved.")
                    print(f"    Warning: Java or abe.jar not found. Cannot unpack {adb_backup_file.name}. The raw backup file is saved.")
                    continue

                unpacked_tar_file = package_backup_data_dir / f"{package_name}_backup.tar"
                unpack_cmd = [java_path, "-jar", str(abe_jar_path), "unpack", str(adb_backup_file), str(unpacked_tar_file)]
                logging.info(f"Attempting to unpack {adb_backup_file.name} using: {' '.join(unpack_cmd)}")
                print(f"    Attempting to unpack {adb_backup_file.name}...")

                try:
                    process = subprocess.run(unpack_cmd, capture_output=True, text=True, timeout=300, check=False, errors='ignore')
                    if not (process.returncode == 0 and unpacked_tar_file.exists() and unpacked_tar_file.stat().st_size > 0):
                        logging.error(f"Failed to unpack {adb_backup_file.name} with abe.jar. RC: {process.returncode}. STDOUT: {process.stdout.strip()}. STDERR: {process.stderr.strip()}")
                        print(f"    Error: Failed to unpack {adb_backup_file.name}. Check logs. The .ab file is saved.")
                        continue
                    logging.info(f"Successfully unpacked {adb_backup_file.name} to .tar.")
                    print(f"    Successfully unpacked {adb_backup_file.name} to {unpacked_tar_file.name}.")

                    # Extract from TAR
                    extract_to_dir = package_backup_data_dir / "_unpacked_tar_contents"
                    os.makedirs(extract_to_dir, exist_ok=True)
                    logging.info(f"Extracting contents of {unpacked_tar_file.name} to {extract_to_dir}")
                    print(f"    Extracting files from {unpacked_tar_file.name} into _unpacked_tar_contents/ folder...")
                    with tarfile.open(unpacked_tar_file, "r") as tar:
                        for member in tar.getmembers(): # Safer extraction
                            member_path_in_tar = Path(member.name)
                            # Ensure the path is relative and does not try to escape the extraction directory
                            # Create a safe target path
                            target_path = extract_to_dir.joinpath(*member_path_in_tar.parts).resolve()
                            if not target_path.is_relative_to(extract_to_dir.resolve()):
                                logging.warning(f"Skipping potentially unsafe path in TAR for {package_name}: {member.name}")
                                continue

                            if member.isfile():
                                os.makedirs(target_path.parent, exist_ok=True)
                                with tar.extractfile(member) as source, open(target_path, "wb") as dest:
                                    shutil.copyfileobj(source, dest)
                            elif member.isdir():
                                os.makedirs(target_path, exist_ok=True)

                    logging.info(f"TAR extraction complete for {package_name} into {extract_to_dir}.")
                    print(f"    Extraction from TAR complete. Data saved in: {extract_to_dir}")
                    # Optional: Clean up .tar file
                    # if unpacked_tar_file.exists(): os.remove(unpacked_tar_file)

                except subprocess.TimeoutExpired:
                    logging.error(f"Timeout expired while unpacking {adb_backup_file.name}.")
                    print(f"    Error: Timeout unpacking {adb_backup_file.name}. The .ab file is saved.")
                except tarfile.TarError as e:
                    logging.error(f"Error extracting tar file for {package_name}: {e}", exc_info=True)
                    print(f"    Error: Could not extract from {unpacked_tar_file.name}. It might be corrupted.")
                except Exception as e:
                    logging.error(f"An exception occurred during ABE unpacking or TAR extraction for {package_name}: {e}", exc_info=True)
                    print(f"    An error occurred during unpacking/extraction for {package_name}: {e}")

        logging.info("Targeted application data extraction process completed.")
        print("\n[APP DATA] Targeted application data extraction finished.")


    def _parse_chrome_bookmarks_recursive(self, node, path_parts, bookmarks_list):
        """Helper function to recursively parse Chrome bookmark nodes."""
        if node.get('type') == 'url':
            bookmarks_list.append({
                'name': node.get('name', ''),
                'url': node.get('url', ''),
                'folder_path': '/'.join(path_parts)
            })
        elif node.get('type') == 'folder':
            current_path = path_parts + [node.get('name', 'Unnamed Folder')]
            for child in node.get('children', []):
                self._parse_chrome_bookmarks_recursive(child, current_path, bookmarks_list)

    def parse_chrome_data(self, package_name="com.android.chrome"):
        logging.info(f"Starting Chrome data parsing for package: {package_name}")
        print(f"\n[CHROME PARSER] Attempting to parse data for {package_name}...")

        parsed_app_output_dir = Path(self.output_dir) / "parsed_app_data" / package_name
        os.makedirs(parsed_app_output_dir, exist_ok=True)

        # Determine Chrome Profile Path from previously extracted data
        profile_path_candidates = [
            Path(self.output_dir) / "rooted_app_data" / package_name / "data_data" / "app_chrome" / "Default",
            Path(self.output_dir) / "app_backup_data" / package_name / "_unpacked_tar_contents" / "apps" / package_name / "app_chrome" / "Default",
            # Fallback for some structures where 'Default' might be directly under 'app_webview' or 'files'
            Path(self.output_dir) / "rooted_app_data" / package_name / "data_data" / "app_webview" / "Default",
            Path(self.output_dir) / "app_backup_data" / package_name / "_unpacked_tar_contents" / "apps" / package_name / "app_webview" / "Default",
        ]

        profile_path = None
        for candidate in profile_path_candidates:
            # A more reliable check might be for multiple key files, e.g., History and Bookmarks
            if candidate.exists() and (candidate / "History").exists():
                profile_path = candidate
                logging.info(f"Found Chrome profile directory for {package_name} at: {profile_path}")
                print(f"  Found Chrome profile directory: {profile_path}")
                break

        if not profile_path:
            logging.warning(f"Chrome profile directory ('Default') not found for {package_name} in expected extracted locations. Skipping Chrome parsing.")
            print(f"  Warning: Chrome profile directory not found for {package_name}. Cannot parse Chrome data.")
            return

        # 1. Parse History SQLite Database
        history_db_path = profile_path / "History"
        history_csv_path = parsed_app_output_dir / "chrome_history.csv"
        if history_db_path.exists():
            logging.info(f"Parsing Chrome History from: {history_db_path}")
            try:
                conn = sqlite3.connect(f"file:{history_db_path}?mode=ro", uri=True) # Read-only connection
                cursor = conn.cursor()
                query = """
                    SELECT
                        datetime(last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') AS last_visit_time,
                        url,
                        title,
                        visit_count,
                        typed_count
                    FROM urls
                    ORDER BY last_visit_time DESC;
                """
                cursor.execute(query)
                rows = cursor.fetchall()
                headers = ["last_visit_time", "url", "title", "visit_count", "typed_count"]
                with open(history_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(headers)
                    writer.writerows(rows)
                logging.info(f"Chrome History successfully parsed to {history_csv_path} ({len(rows)} rows).")
                print(f"  Successfully parsed Chrome History to {history_csv_path.name} ({len(rows)} rows).")
            except sqlite3.Error as e:
                logging.error(f"SQLite error while parsing Chrome History {history_db_path}: {e}", exc_info=True)
                print(f"  Error: Could not parse Chrome History database: {e}")
            except Exception as e:
                logging.error(f"Unexpected error parsing Chrome History {history_db_path}: {e}", exc_info=True)
                print(f"  Error: Unexpected issue parsing Chrome History: {e}")
            finally:
                if 'conn' in locals() and conn:
                    conn.close()
        else:
            logging.warning(f"Chrome History file not found at: {history_db_path}")
            print(f"  Warning: Chrome History file not found at expected location.")

        # 2. Parse Bookmarks JSON File
        bookmarks_file_path = profile_path / "Bookmarks"
        bookmarks_csv_path = parsed_app_output_dir / "chrome_bookmarks.csv"
        bookmarks_json_dump_path = parsed_app_output_dir / "chrome_bookmarks_full.json"
        if bookmarks_file_path.exists():
            logging.info(f"Parsing Chrome Bookmarks from: {bookmarks_file_path}")
            try:
                with open(bookmarks_file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Dump pretty-printed JSON
                with open(bookmarks_json_dump_path, 'w', encoding='utf-8') as f_json:
                    json.dump(data, f_json, indent=4)
                logging.info(f"Full Chrome Bookmarks JSON dumped to {bookmarks_json_dump_path}")
                print(f"  Full Chrome Bookmarks JSON dumped to {bookmarks_json_dump_path.name}")

                # Extract to CSV
                bookmarks_list = []
                if 'roots' in data:
                    for root_name, root_node in data['roots'].items():
                        self._parse_chrome_bookmarks_recursive(root_node, [root_name], bookmarks_list)

                if bookmarks_list:
                    headers = ["name", "url", "folder_path"]
                    with open(bookmarks_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                        writer = csv.DictWriter(csvfile, fieldnames=headers)
                        writer.writeheader()
                        writer.writerows(bookmarks_list)
                    logging.info(f"Chrome Bookmarks successfully parsed to {bookmarks_csv_path} ({len(bookmarks_list)} bookmarks).")
                    print(f"  Successfully parsed Chrome Bookmarks to {bookmarks_csv_path.name} ({len(bookmarks_list)} bookmarks).")
                else:
                    logging.info("No individual bookmarks found or structure not as expected in Bookmarks JSON.")
                    print("  Info: No individual bookmark entries extracted to CSV (structure might differ or empty).")

            except json.JSONDecodeError as e:
                logging.error(f"JSON decoding error while parsing Chrome Bookmarks {bookmarks_file_path}: {e}", exc_info=True)
                print(f"  Error: Could not parse Chrome Bookmarks JSON: {e}")
            except Exception as e:
                logging.error(f"Unexpected error parsing Chrome Bookmarks {bookmarks_file_path}: {e}", exc_info=True)
                print(f"  Error: Unexpected issue parsing Chrome Bookmarks: {e}")
        else:
            logging.warning(f"Chrome Bookmarks file not found at: {bookmarks_file_path}")
            print(f"  Warning: Chrome Bookmarks file not found at expected location.")

        # 3. Parse Cookies SQLite Database
        # Common paths for Cookies DB relative to profile_path
        cookies_db_candidates = [profile_path / "Cookies", profile_path / "Network" / "Cookies"]
        cookies_db_path = None
        for candidate in cookies_db_candidates:
            if candidate.exists():
                cookies_db_path = candidate
                break

        cookies_csv_path = parsed_app_output_dir / "chrome_cookies.csv"
        if cookies_db_path:
            logging.info(f"Parsing Chrome Cookies from: {cookies_db_path}")
            try:
                conn = sqlite3.connect(f"file:{cookies_db_path}?mode=ro", uri=True)
                cursor = conn.cursor()
                query = """
                    SELECT
                        datetime(creation_utc/1000000-11644473600, 'unixepoch', 'localtime') AS creation_time,
                        datetime(last_access_utc/1000000-11644473600, 'unixepoch', 'localtime') AS last_access_time,
                        datetime(last_update_utc/1000000-11644473600, 'unixepoch', 'localtime') AS last_update_time,
                        host_key,
                        name,
                        value,
                        path,
                        datetime(expires_utc/1000000-11644473600, 'unixepoch', 'localtime') AS expires_time,
                        is_secure,
                        is_httponly,
                        case samesite
                            when 0 then 'Unspecified'
                            when 1 then 'NoSameSite'
                            when 2 then 'Lax'
                            when 3 then 'Strict'
                            else 'Unknown'
                        end as samesite_policy,
                        source_scheme,
                        is_persistent
                    FROM cookies
                    ORDER BY last_access_time DESC;
                """
                cursor.execute(query)
                rows = cursor.fetchall()
                headers = ["creation_time", "last_access_time", "last_update_time", "host_key", "name", "value", "path",
                           "expires_time", "is_secure", "is_httponly", "samesite_policy", "source_scheme", "is_persistent"]
                with open(cookies_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(headers)
                    writer.writerows(rows)
                logging.info(f"Chrome Cookies successfully parsed to {cookies_csv_path} ({len(rows)} cookies).")
                print(f"  Successfully parsed Chrome Cookies to {cookies_csv_path.name} ({len(rows)} cookies).")
            except sqlite3.Error as e:
                logging.error(f"SQLite error while parsing Chrome Cookies {cookies_db_path}: {e}", exc_info=True)
                print(f"  Error: Could not parse Chrome Cookies database: {e}")
            except Exception as e:
                logging.error(f"Unexpected error parsing Chrome Cookies {cookies_db_path}: {e}", exc_info=True)
                print(f"  Error: Unexpected issue parsing Chrome Cookies: {e}")
            finally:
                if 'conn' in locals() and conn:
                    conn.close()
        else:
            logging.warning(f"Chrome Cookies file not found in expected locations within profile: {profile_path}")
            print(f"  Warning: Chrome Cookies file not found at expected locations.")

        logging.info(f"Chrome data parsing attempt finished for {package_name}.")
        print(f"[CHROME PARSER] Finished parsing attempt for {package_name}.")


    def check_and_set_root_status(self):
        if self.root_status_checked:
            logging.info(f"Root status already checked. Current status: {'ROOT' if self.is_root else 'USER'}")
            return self.is_root

        logging.info("Attempting to check and set ADB root status...")
        self.root_status_checked = True # Mark as checked now

        # Check initial ID without attempting adb root first
        initial_id_result = self._execute_adb_command([self.adb_path, "shell", "id"], timeout=10)
        if initial_id_result and initial_id_result.stdout and "uid=0" in initial_id_result.stdout.lower():
            logging.info(f"ADB is already running as root. UID: {initial_id_result.stdout.strip()}")
            self.is_root = True
            self.root_enabled_by_script = False # It was already root, not by this script instance
            return True

        logging.info("Current ADB session is not root. Attempting to restart ADB as root via 'adb root'...")
        # Attempt 'adb root'
        root_attempt_result = self._execute_adb_command([self.adb_path, "root"], timeout=20)

        if root_attempt_result is None: # Command execution failed (e.g. timeout, adb error before returning)
            logging.warning("`adb root` command execution failed or timed out. Assuming no root can be obtained.")
            return False

        # Log output of 'adb root'
        # Some devices return "adbd is already running as root" even if 'id' says otherwise initially (less common).
        # Others might say "restarting adbd as root" or give an error if not possible.
        root_stdout = root_attempt_result.stdout.strip() if root_attempt_result.stdout else "No stdout"
        root_stderr = root_attempt_result.stderr.strip() if root_attempt_result.stderr else "No stderr"
        logging.info(f"`adb root` command output: STDOUT='{root_stdout}', STDERR='{root_stderr}'")

        if "cannot run as root in production builds" in root_stdout or \
           "cannot run as root in production builds" in root_stderr or \
           "disabled" in root_stdout or "disabled" in root_stderr : # Common messages on locked devices
            logging.warning("`adb root` command indicates root is disabled on this production build. Root access not available.")
            self.is_root = False
            return False

        # If `adb root` command itself indicates it's already root, but initial `id` check didn't confirm.
        # This can happen if `adb root` was run before and adbd is still root but shell context wasn't.
        # Re-check `id` after 'adb root' attempt.
        if "adbd is already running as root" in root_stdout or "adbd is already running as root" in root_stderr:
             logging.info("`adb root` command reports adbd already root. Verifying shell UID again.")
             # No need to set root_enabled_by_script to True here, as it was already root.
        else:
            # If `adb root` implies a change (e.g. "restarting adbd as root" or no specific error),
            # then this script instance is attempting to enable it.
            logging.info("`adb root` command processed. Waiting for device to reconnect...")
            time.sleep(5) # Essential delay for adbd to restart
            wait_result = self._execute_adb_command([self.adb_path, "wait-for-device"], timeout=30)
            if wait_result is None or wait_result.returncode != 0:
                logging.warning("Device did not reconnect after `adb root` attempt or `wait-for-device` failed. Assuming no root.")
                self.is_root = False
                return False
            logging.info("Device reconnected after `adb root` attempt.")
            # If adb root was attempted and device reconnected, mark that script potentially enabled it
            # This will be confirmed by the 'id' check below.
            # self.root_enabled_by_script = True # Tentatively true, confirmed by 'id'

        # Final verification of root status
        id_result = self._execute_adb_command([self.adb_path, "shell", "id"], timeout=10)
        if id_result and id_result.stdout and "uid=0" in id_result.stdout.lower():
            logging.info(f"Successfully running ADB as root. UID: {id_result.stdout.strip()}")
            self.is_root = True
            # If it wasn't root before the 'adb root' command, then this script enabled it.
            # We need to compare with the initial state before setting root_enabled_by_script.
            # For simplicity now: if `adb root` was called and now it is root, assume script action.
            # A more precise way would be to check if `is_root` was false before `adb root` call.
            if not ("adbd is already running as root" in root_stdout or "adbd is already running as root" in root_stderr):
                 self.root_enabled_by_script = True # Script initiated this root session
            return True
        else:
            log_msg = f"Failed to confirm root after `adb root` attempt. UID: {id_result.stdout.strip() if id_result and id_result.stdout else 'Not available'}."
            if id_result and id_result.stderr:
                log_msg += f" Stderr: {id_result.stderr.strip()}"
            logging.warning(log_msg)
            self.is_root = False
            self.root_enabled_by_script = False # Reset if root was not achieved
            return False

    def revert_adb_to_user(self):
        # Only unroot if script specifically enabled it and it's currently root.
        # Or, more simply for now, if --attempt-root was used and device is root.
        if self.is_root and self.root_enabled_by_script: # More precise condition
            logging.info("Attempting to revert ADB to user mode (adb unroot)...")
            unroot_result = self._execute_adb_command([self.adb_path, "unroot"], timeout=20)

            if unroot_result is None:
                logging.warning("`adb unroot` command execution failed or timed out.")
                return

            unroot_stdout = unroot_result.stdout.strip() if unroot_result.stdout else "No stdout"
            unroot_stderr = unroot_result.stderr.strip() if unroot_result.stderr else "No stderr"
            logging.info(f"`adb unroot` command output: STDOUT='{unroot_stdout}', STDERR='{unroot_stderr}'")

            logging.info("Waiting for device to reconnect after `adb unroot`...")
            time.sleep(5) # Essential delay
            wait_result = self._execute_adb_command([self.adb_path, "wait-for-device"], timeout=30)

            if wait_result is None or wait_result.returncode != 0:
                logging.warning("Device did not reconnect after `adb unroot` or `wait-for-device` failed.")
            else:
                logging.info("Device reconnected after `adb unroot`.")

            # Verify not root anymore
            id_result = self._execute_adb_command([self.adb_path, "shell", "id"], timeout=10)
            if id_result and id_result.stdout and "uid=0" not in id_result.stdout.lower():
                logging.info(f"Successfully reverted ADB to user mode. UID: {id_result.stdout.strip()}")
            else:
                logging.warning(f"Failed to confirm ADB reverted to user mode. UID: {id_result.stdout.strip() if id_result and id_result.stdout else 'Not available'}")

            self.is_root = False # Assume unroot worked or state is no longer root
            self.root_enabled_by_script = False
        elif self.is_root:
            logging.info("ADB is root, but was not enabled by this script instance. Skipping `adb unroot`.")
        else:
            logging.info("ADB not running as root or root status not checked. No need to unroot.")


    # Placeholder for advanced_data_capture if it's intended to be a module, currently it's always run if device connected.
    # For CLI, it should also be an option. For now, keeping its original behavior within the main sequence.
    def advanced_data_capture(self, duration=30):
        """Captures screen recording and various logs."""
        logging.info("Starting advanced data capture...")
        capture_dir = os.path.join(self.output_dir, "advanced_captures") # Renamed for clarity
        os.makedirs(capture_dir, exist_ok=True)

        # Screen recording using scrcpy
        if self.scrcpy_path:
            screen_record_file = os.path.join(capture_dir, "screen_record.mp4")
            logging.info(f"Starting screen recording for {duration} seconds. Output: {screen_record_file}")
            print(f"Starting screen recording for {duration} seconds (scrcpy)...")

            scrcpy_cmd = [
                self.scrcpy_path,
                "--record", str(screen_record_file),
                f"--time-limit={duration}", # Corrected format
                "--show-touches",
                "--stay-awake",
                "--power-off-on-close", # Turn screen off when scrcpy closes
                # "--no-display" # Optional: if you don't want the mirror window locally
            ]
            try:
                logging.info(f"Executing scrcpy: {' '.join(scrcpy_cmd)}")
                # Using Popen for scrcpy if we want to do other things simultaneously,
                # but for a timed recording, `run` with a timeout is simpler.
                # Ensure scrcpy process is properly terminated if timeout occurs.
                process = subprocess.Popen(scrcpy_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    stdout, stderr = process.communicate(timeout=duration + 10) # Timeout slightly longer than recording
                    return_code = process.returncode

                    if return_code == 0:
                        logging.info(f"Screen recording successfully saved to {screen_record_file}. Output: {stdout.decode(errors='ignore').strip()}")
                        print(f"Screen recording saved to {screen_record_file}")
                    else:
                        logging.error(f"scrcpy screen recording failed. Return code: {return_code}\nStdout: {stdout.decode(errors='ignore').strip()}\nStderr: {stderr.decode(errors='ignore').strip()}")
                        print(f"Error during screen recording. Check logs: {self.output_dir}/aegis_extraction.log")

                except subprocess.TimeoutExpired:
                    logging.warning(f"scrcpy command timed out. Attempting to terminate.")
                    process.terminate() # Try to terminate gracefully
                    try:
                        process.wait(timeout=5) # Wait a bit for termination
                    except subprocess.TimeoutExpired:
                        process.kill() # Force kill if terminate doesn't work
                        logging.warning("scrcpy process killed due to not terminating after timeout.")
                    stdout, stderr = process.communicate() # Get any final output
                    logging.warning(f"Recording might be incomplete at {screen_record_file}. Stdout: {stdout.decode(errors='ignore')}, Stderr: {stderr.decode(errors='ignore')}")
                    print(f"Screen recording command timed out. It might be incomplete at {screen_record_file}")

            except FileNotFoundError:
                logging.error(f"scrcpy command not found at {self.scrcpy_path}.")
                print(f"Error: scrcpy command not found at {self.scrcpy_path}.")
            except Exception as e:
                logging.error(f"An unexpected error occurred during screen recording: {e}", exc_info=True)
                print(f"An unexpected error occurred during screen recording: {e}")
        else:
            logging.warning("scrcpy not found, skipping screen recording.")
            print("scrcpy not found, skipping screen recording.")

        # Log capture (logcat)
        # Consider clearing logs first: adb logcat -c
        try:
            logging.info("Clearing existing logcat buffer before capture...")
            subprocess.run([self.adb_path, "logcat", "-c"], timeout=10, check=False) # check=False as it might fail if logs are empty
        except Exception as e:
            logging.warning(f"Could not clear logcat buffer (non-critical): {e}")

        logcat_commands = {
            "full_logcat_verbose.txt": [self.adb_path, "logcat", "-d", "*:V"], # General verbose log
            "main_logcat.txt": [self.adb_path, "logcat", "-d", "-b", "main"],
            "events_logcat.txt": [self.adb_path, "logcat", "-d", "-b", "events"],
            # "radio_logcat.txt": [self.adb_path, "logcat", "-d", "-b", "radio"], # Contains sensitive info like phone numbers
        }

        print(f"Capturing various logcat outputs. This may take a moment...")
        time.sleep(2) # Small delay for logs to start flowing if needed after clearing

        for filename, cmd in logcat_commands.items():
            log_file_path = os.path.join(capture_dir, filename)
            logging.info(f"Capturing logcat: {' '.join(cmd)} TO {log_file_path}")
            try:
                # Using a moderate timeout for logcat dump
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60, errors='ignore')
                with open(log_file_path, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
                logging.info(f"Logcat '{filename}' saved to {log_file_path} ({len(result.stdout)} bytes)")
                if len(result.stdout) < 100: # Arbitrary small number
                     logging.warning(f"Logcat '{filename}' seems very small. It might be empty or filtered.")
                print(f"Logcat '{filename}' saved.")
            except subprocess.CalledProcessError as e:
                logging.error(f"Logcat command for '{filename}' failed: {e.cmd}, RC: {e.returncode}\nStderr: {e.stderr.strip()}")
                print(f"Error capturing '{filename}'. It might require specific permissions or settings. Stderr: {e.stderr.strip()}")
            except subprocess.TimeoutExpired:
                logging.warning(f"Logcat command for '{filename}' timed out. Logs might be incomplete.")
                print(f"Warning: Logcat for '{filename}' timed out. Logs might be incomplete.")
            except Exception as e:
                logging.error(f"An unexpected error during log capture for '{filename}': {e}", exc_info=True)
                print(f"An unexpected error occurred during log capture for '{filename}': {e}")

        logging.info("Advanced data capture process completed.")
        print(f"Advanced data captures (screen recording, logs) finished. Check {capture_dir} and main log.")


if __name__ == "__main__":
    # Initial print to console, before logging is fully configured
    print(f"Starting Aegis Android Extractor at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}...")

    parser = argparse.ArgumentParser(
        description="Aegis Android Extraction Tool - Extracts data from connected Android devices.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Extraction Modules
    parser.add_argument(
        '--all',
        action='store_true',
        help="Run all available extraction modules (device info, file pull, contacts, call logs, SMS, WhatsApp guided, advanced capture)."
    )
    parser.add_argument(
        '--device-info', '-di',
        action='store_true',
        help="Extract comprehensive device hardware and software information."
    )
    parser.add_argument(
        '--pull-files', '-pf',
        action='store_true',
        help="Enable pulling files/directories from the device. Use --pull-paths to specify, or defaults will be used."
    )
    parser.add_argument(
        '--pull-paths',
        nargs='*', # 0 or more arguments
        metavar='DEVICE_PATH',
        help="Space-separated list of full paths on device to pull (e.g., /sdcard/DCIM /sdcard/Download/MyFile.txt). "
             "If --pull-files is set but --pull-paths is not provided or is empty, default common directories are pulled."
    )
    parser.add_argument(
        '--contacts', '-c',
        action='store_true',
        help="Extract contacts from the device's content provider."
    )
    parser.add_argument(
        '--call-logs', '-cl',
        action='store_true',
        help="Extract call logs from the device's content provider."
    )
    parser.add_argument(
        '--sms', '-s',
        action='store_true',
        help="Extract SMS/MMS messages from the device's content provider."
    )
    parser.add_argument(
        '--whatsapp', '-wa',
        action='store_true',
        help="Run the guided process for WhatsApp key and database extraction."
    )
    parser.add_argument(
        '--advanced-capture', '-ac',
        action='store_true',
        help="Perform advanced data capture (screen recording, logcat dumps)."
    )
    parser.add_argument(
        '--scrcpy-duration',
        type=int,
        default=15, # Default duration for screen recording if -ac is chosen
        metavar='SECONDS',
        help="Duration in seconds for screen recording if --advanced-capture is selected (default: 15)."
    )

    # Configuration Options
    parser.add_argument(
        '--output-dir', '-o',
        type=str,
        metavar='DIRECTORY_PATH',
        help="Base directory to save all extraction output. A timestamped folder will be created inside this directory. "
             "If not specified, output is saved in a timestamped folder in the script's current directory."
    )
    parser.add_argument(
        '--adb-path',
        type=str,
        metavar='FILE_PATH',
        help="Override path to the ADB (Android Debug Bridge) executable."
    )
    parser.add_argument(
        '--scrcpy-path',
        type=str,
        metavar='FILE_PATH',
        help="Override path to the scrcpy executable (for screen recording)."
    )

    args = parser.parse_args()

    # Instantiate extractor with potential overrides
    extractor = AegisExtractor(
        base_output_dir_cli=args.output_dir,
        adb_path_override=args.adb_path,
        scrcpy_path_override=args.scrcpy_path
    )

    # ADB path is critical, AegisExtractor __init__ exits if not found.
    # Logging is configured within AegisExtractor's __init__.

    # Determine which modules to run
    run_all = args.all
    run_device_info = args.device_info or run_all
    run_pull_files = args.pull_files or run_all
    run_contacts = args.contacts or run_all
    run_call_logs = args.call_logs or run_all
    run_sms = args.sms or run_all
    run_whatsapp = args.whatsapp or run_all
    run_advanced_capture = args.advanced_capture or run_all

    # Check if any extraction module is selected
    any_module_selected = any([
        run_device_info, run_pull_files, run_contacts,
        run_call_logs, run_sms, run_whatsapp, run_advanced_capture
    ])

    if not any_module_selected:
        print("No extraction module selected. Please specify at least one module to run (e.g., --device-info, --all) or use -h for help.")
        parser.print_help()
        exit(0) # Exit gracefully, not an error

    logging.info("=== Starting Aegis Android Extraction based on CLI arguments ===")
    print("\n[INFO] Starting Aegis extraction sequence based on CLI arguments...")

    if extractor.check_connection():
        logging.info("Device connection confirmed.")

        if run_device_info:
            print("\n[PHASE] Extracting Device Info...")
            extractor.extract_device_info()

        if run_pull_files:
            print("\n[PHASE] Pulling Files from Device...")
            # If --pull-paths is provided (even if empty list), use it.
            # If --pull-paths is not provided at all (args.pull_paths is None),
            # pull_data will use its internal defaults.
            # If --pull-paths is provided but empty (e.g. --pull-files --pull-paths),
            # pull_data should also use its defaults.
            paths_to_pull_arg = args.pull_paths
            if args.pull_paths is not None and not args.pull_paths: # Explicitly given as empty list
                 paths_to_pull_arg = None # Treat as "use defaults"
            extractor.pull_data(directories_to_pull=paths_to_pull_arg)

        if run_contacts:
            print("\n[PHASE] Extracting Contacts...")
            extractor.extract_contacts()

        if run_call_logs:
            print("\n[PHASE] Extracting Call Logs...")
            extractor.extract_call_logs()

        if run_sms:
            print("\n[PHASE] Extracting SMS Messages...")
            extractor.extract_sms()

        if run_whatsapp:
            print("\n[PHASE] Guided WhatsApp Key/Database Extraction...")
            extractor.extract_whatsapp_data_guided()

        if run_advanced_capture:
            print("\n[PHASE] Advanced Data Capture (Screen Recording & Logs)...")
            extractor.advanced_data_capture(duration=args.scrcpy_duration)

    else:
        logging.warning("No device connected or device not authorized. Most operations will be skipped.")
        print("\n[ERROR] No device connected or device not authorized. Please check USB connection, enable USB debugging, and authorize the connection on your device. Then, re-run the script with desired options.")

    logging.info("=== Aegis Extraction Sequence Finished ===")
    print(f"\n[INFO] Aegis Android Extractor run completed at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    print(f"[INFO] All outputs and the main log file are in: {extractor.output_dir}")
    logging.shutdown()

def main_cli(): # Renamed from main to avoid conflict if any other main exists, though not in this file.
    # Initial print to console, before logging is fully configured by AegisExtractor
    print(f"Starting Aegis Android Extractor CLI at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}...")

    # Argument parsing and core logic moved into this function

    parser = argparse.ArgumentParser(
        description="Aegis Android Extraction Tool - Extracts data from connected Android devices.",
        formatter_class=argparse.RawTextHelpFormatter # Preserves formatting in help messages
    )

    # --- Extraction Modules ---
    module_group = parser.add_argument_group('Extraction Modules')
    module_group.add_argument(
        '--all',
        action='store_true',
        help="Run all available extraction modules."
    )
    module_group.add_argument(
        '--device-info', '-di',
        action='store_true',
        help="Extract comprehensive device hardware/software information."
    )
    module_group.add_argument(
        '--pull-files', '-pf',
        action='store_true',
        help="Enable pulling files/directories. Use --pull-paths to specify, or defaults will be used."
    )
    module_group.add_argument(
        '--pull-paths',
        nargs='*',
        metavar='DEVICE_PATH',
        help="Space-separated list of full paths on device to pull (e.g., /sdcard/DCIM /sdcard/log.txt). "
             "Effective only with --pull-files. If --pull-files is set but --pull-paths is absent or empty, "
             "default common directories are pulled."
    )
    module_group.add_argument(
        '--contacts', '-c',
        action='store_true',
        help="Extract contacts."
    )
    module_group.add_argument(
        '--call-logs', '-cl',
        action='store_true',
        help="Extract call logs."
    )
    module_group.add_argument(
        '--sms', '-s',
        action='store_true',
        help="Extract SMS/MMS messages."
    )
    module_group.add_argument(
        '--whatsapp', '-wa',
        action='store_true',
        help="Run guided WhatsApp key/database extraction process."
    )
    module_group.add_argument(
        '--advanced-capture', '-ac',
        action='store_true',
        help="Perform advanced data capture (e.g., screen recording, logcat dumps)."
    )
    module_group.add_argument(
        '--scrcpy-duration',
        type=int,
        default=15,
        metavar='SECONDS',
        help="Duration in seconds for screen recording if --advanced-capture is selected (default: 15)."
    )
    module_group.add_argument(
        '--app-data',
        nargs='*',
        metavar='PACKAGE_NAME',
        help="Extract data for specific app(s) using root pull (if available) or ADB backup. "
             "Provide space-separated package names (e.g., com.example.app1 com.example.app2). "
             "If provided with no arguments, a default list of apps will be attempted."
    )
    module_group.add_argument(
        '--parse-chrome',
        action='store_true',
        help="Parse extracted Google Chrome data (History, Bookmarks, Cookies). "
             "Requires Chrome data to have been extracted first (e.g., via --app-data com.android.chrome or --all)."
    )

    # --- Configuration Options ---
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument(
        '--attempt-root',
        action='store_true',
        help="Attempt to restart ADB with root privileges for operations that might require it."
    )
    config_group.add_argument(
        '--output-dir', '-o',
        type=str,
        metavar='DIRECTORY_PATH',
        help="Base directory to save all extraction output. A timestamped folder will be created inside this. "
             "Default: Timestamped folder in script's directory."
    )
    config_group.add_argument(
        '--adb-path',
        type=str,
        metavar='FILE_PATH',
        help="Override path to the ADB (Android Debug Bridge) executable."
    )
    config_group.add_argument(
        '--scrcpy-path',
        type=str,
        metavar='FILE_PATH',
        help="Override path to the scrcpy executable (for screen recording)."
    )

    args = parser.parse_args()

    # Instantiate extractor with potential overrides from CLI
    extractor = AegisExtractor(
        base_output_dir_cli=args.output_dir,
        adb_path_override=args.adb_path,
        scrcpy_path_override=args.scrcpy_path
    )
    # Logging is now configured within AegisExtractor's __init__

    # Attempt to gain root if requested, before checking connection or running modules
    if args.attempt_root:
        print("\n[PHASE] Attempting to check/gain root access...")
        if extractor.check_and_set_root_status():
            print(f"ADB is running with root privileges (UID=0). Current root status: {extractor.is_root}")
        else:
            print(f"ADB is running with user privileges. Current root status: {extractor.is_root}")
            if not extractor.is_root:
                 print("Warning: Root access not obtained. Some extractions might be limited.")
        logging.info(f"Root status after check/attempt: {extractor.is_root}. Script enabled root: {extractor.root_enabled_by_script}")


    # Determine which modules to run
    run_all = args.all
    run_device_info = args.device_info or run_all
    run_pull_files = args.pull_files or run_all
    run_contacts = args.contacts or run_all
    run_call_logs = args.call_logs or run_all
    run_sms = args.sms or run_all
    run_whatsapp = args.whatsapp or run_all
    run_advanced_capture = args.advanced_capture or run_all
    run_app_data = args.app_data is not None or run_all # True if --app-data flag is present or --all
    run_parse_chrome = args.parse_chrome or run_all # Parse Chrome if explicitly asked or --all

    any_module_selected = any([
        run_device_info, run_pull_files, run_contacts,
        run_call_logs, run_sms, run_whatsapp, run_advanced_capture,
        run_app_data, run_parse_chrome # Considered a module selection
    ])

    if not any_module_selected:
        print("No extraction module selected. Please specify at least one module to run (e.g., --device-info, --all, --app-data, --parse-chrome). Use -h for help.")
        parser.print_help()
        # Logging might not be fully set if __init__ had issues, but attempt shutdown.
        if logging.getLogger().hasHandlers(): logging.shutdown()
        exit(0)

    logging.info("=== Starting Aegis Android Extraction (CLI Invoked) ===")
    print("\n[INFO] Aegis extraction sequence starting based on CLI arguments...")

    if extractor.check_connection():
        logging.info("Device connection confirmed.")

        if run_device_info:
            print("\n[PHASE] Extracting Device Info...")
            extractor.extract_device_info()

        if run_pull_files:
            print("\n[PHASE] Pulling Files from Device...")
            # Handle pull_paths: None if not provided or empty, otherwise the list.
            # pull_data method expects None or a non-empty list to override defaults.
            # An empty list from argparse (if --pull-paths is used with no actual paths)
            # should be treated as "use defaults", so pass None.
            paths_to_pull_arg = args.pull_paths
            if args.pull_paths is not None and not args.pull_paths: # Explicitly --pull-paths with no args
                paths_to_pull_arg = None
            extractor.pull_data(directories_to_pull=paths_to_pull_arg)

        if run_contacts:
            print("\n[PHASE] Extracting Contacts...")
            extractor.extract_contacts()

        if run_call_logs:
            print("\n[PHASE] Extracting Call Logs...")
            extractor.extract_call_logs()

        if run_sms:
            print("\n[PHASE] Extracting SMS Messages...")
            extractor.extract_sms()

        if run_whatsapp:
            print("\n[PHASE] Guided WhatsApp Key/Database Extraction...")
            extractor.extract_whatsapp_data_guided()

        if run_advanced_capture:
            print("\n[PHASE] Advanced Data Capture (Screen Recording & Logs)...")
            extractor.advanced_data_capture(duration=args.scrcpy_duration)

        if run_app_data:
            print("\n[PHASE] Targeted Application Data Extraction...")
            # If --all was used, args.app_data would be None.
            # If --app-data was used without package names, args.app_data is [].
            # If --app-data com.example.app, args.app_data is ['com.example.app'].
            # The method extract_targeted_app_data handles None or [] by using defaults.
            app_data_packages_to_extract = args.app_data # This could be None, an empty list, or a list of packages
            if run_all and args.app_data is None:
                # If --all is on, and --app-data was not used, extract_targeted_app_data will use its defaults (which should include chrome for run_parse_chrome with --all to work)
                app_data_packages_to_extract = None
            elif args.app_data is not None and not args.app_data: # --app-data specified with no packages
                app_data_packages_to_extract = None # Triggers default list in the method

            extractor.extract_targeted_app_data(package_names_list=app_data_packages_to_extract)

        # Chrome parsing should run after app data extraction if com.android.chrome was targeted
        # or if --all was used (implying Chrome data might have been extracted by default).
        if run_parse_chrome:
            # Check if Chrome data was likely extracted to avoid parsing non-existent files
            chrome_package_name = "com.android.chrome"
            was_chrome_extracted_explicitly = app_data_packages_to_extract and chrome_package_name in app_data_packages_to_extract
            is_chrome_in_defaults_for_all = run_all and (app_data_packages_to_extract is None) # Assumes Chrome is in defaults if --all and no specific --app-data

            # A simpler check: just call parse_chrome_data. The method itself checks if data exists.
            # This avoids complex logic here about whether Chrome data *should* have been extracted.
            print("\n[PHASE] Parsing Google Chrome Data...")
            extractor.parse_chrome_data(package_name=chrome_package_name)

    else:
        logging.warning("No device connected or device not authorized. Operations will be skipped.")
        print("\n[ERROR] No device connected or device not authorized. Please check USB connection, enable USB debugging, and authorize the connection on your device. Then, re-run the script with desired options.")

    logging.info("=== Aegis Extraction Sequence Finished ===")
    print(f"\n[INFO] Aegis Android Extractor run completed at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    print(f"[INFO] All outputs and the main log file are in: {extractor.output_dir}")

    # Revert to user mode if root was attempted and script enabled it
    if args.attempt_root: # Only if --attempt-root was used
        extractor.revert_adb_to_user()

    # Ensure all log handlers are closed properly
    if logging.getLogger().hasHandlers():
        logging.shutdown()

if __name__ == "__main__":
    main_cli()
```
