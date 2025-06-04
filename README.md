# advanced-extraction-tool
An advanced offline data extraction tool with forensic-level features, modern GUI, and encryption support.

## Enhanced Log Analyzer (`log_analyzer.py`)

**Overview:**
`log_analyzer.py` is a powerful Python script for parsing, filtering, and displaying Android's `logcat -v threadtime` formatted logs. It allows for real-time analysis from `adb logcat` or processing of saved log files, with options for console highlighting and structured output to CSV or JSON formats. This tool helps in debugging and analyzing log data by focusing on relevant entries.

**Usage:**

*   **Live analysis with `adb logcat`:**
    ```bash
    adb logcat -v threadtime [adb_options] | python log_analyzer.py [script_options]
    ```
    *(Note: On Windows, you might need `python.exe` or `py` instead of `python`)*

*   **Analysis from a log file:**
    ```bash
    python log_analyzer.py --input-file <path_to_log_file> [script_options]
    ```

**Command-Line Arguments:**

*   `--input-file FILE`: Path to a log file to read from. If not provided, reads from stdin.
*   `--min-priority {V,D,I,W,E,F}`: Minimum log priority to display (Verbose, Debug, Info, Warning, Error, Fatal). Case-insensitive.
*   `--tag TAG`: Log tags to include. Can be specified multiple times (e.g., `--tag MyApp --tag YourService`). Only messages with these tags are shown.
*   `--pid PID`: Process IDs to include. Can be specified multiple times (e.g., `--pid 1234 --pid 5678`).
*   `--keyword KEYWORD`: Keywords to search for in the log message. Case-insensitive. Can be specified multiple times (e.g., `--keyword error --keyword critical`). Only messages containing at least one keyword are shown.
*   `--highlight-keyword KEYWORD`: Keywords to highlight in the console output (makes the line bold). Case-insensitive. Can be specified multiple times. This applies on top of other filters.
*   `--output-csv CSV_FILE`: Path to save filtered logs as a CSV file. Includes a header row.
*   `--output-json JSON_FILE`: Path to save filtered logs (as parsed objects) in a JSON file.

**Examples:**

1.  **Show only errors and warnings from live `adb logcat`:**
    ```bash
    adb logcat -v threadtime | python log_analyzer.py --min-priority W
    ```

2.  **Show logs from tag "MyApp" and PID 1234, highlighting messages containing "database":**
    ```bash
    adb logcat -v threadtime | python log_analyzer.py --tag MyApp --pid 1234 --highlight-keyword database
    ```

3.  **Read from `my_logs.txt`, filter for messages containing "NetworkFailure" or "Exception", and save to CSV and JSON:**
    ```bash
    python log_analyzer.py --input-file my_logs.txt --keyword NetworkFailure --keyword Exception --output-csv filtered_logs.csv --output-json filtered_logs.json
    ```

4.  **Show all logs from `adb logcat` but highlight messages from tag "AudioFlinger" in bold (useful for spotting specific tag activity):**
    ```bash
    adb logcat -v threadtime | python log_analyzer.py --highlight-keyword AudioFlinger --tag AudioFlinger
    ```
    *(Note: Added `--tag AudioFlinger` to also filter by it, if only highlighting for this tag is desired among all logs, one might adjust filters accordingly or rely on visual scanning of bolded lines.)*

## Automated Artifact Extractor (`artifact_extractor.py`)

**Overview:**
`artifact_extractor.py` is a command-line tool designed to automate the extraction of common forensic artifacts from a connected Android device. It uses the Android Debug Bridge (ADB) to pull files, directories, and execute commands based on a predefined database of known artifacts.

**Prerequisites:**

*   **Android Debug Bridge (`adb.exe`):** The script requires `adb.exe` to be accessible. It will look for `adb.exe` in the same directory as the script, in the repository root, and then in the system's PATH.
*   **Root Access:** Many valuable forensic artifacts are stored in locations on the Android device that require root access. While the script will attempt to extract all specified artifacts, those requiring root may fail if the connected device is not rooted or ADB does not have root privileges.
*   **USB Debugging:** Ensure USB Debugging is enabled on the target Android device.

**Usage:**

The basic command structure is:
```bash
python artifact_extractor.py --output <output_directory> [options]
```
*(Note: On Windows, you might need `python.exe` or `py` instead of `python`)*

**Command-Line Arguments:**

*   `--output DIRECTORY`: **(Required)** Specifies the base directory where all extracted artifacts will be saved. A subdirectory for the target device will be created here.
*   `--artifacts ARTIFACT_KEYS`: A comma-separated list of specific artifact keys to extract (e.g., `sms_mms_db,contacts_db,build_prop`). Use `--list-artifacts` to see available keys.
*   `--all`: If specified, the script will attempt to extract all artifacts defined in its internal database.
*   `--list-artifacts`: Lists all available artifact keys and their display names from the internal database, then exits.
*   `--device SERIAL`: Specify the target device serial number. This is required if multiple Android devices/emulators are connected. If only one device is connected, the script will auto-detect it.
*   `-v, --verbose`: Enables verbose output, which includes printing the ADB commands being executed and more detailed information about the extraction process.

**Listing Available Artifacts:**

To see a list of all artifacts the script knows how to extract, run:
```bash
python artifact_extractor.py --list-artifacts
```
This will output a list of keys (e.g., `contacts_db`, `build_prop`) and their user-friendly display names (e.g., "Contacts Database", "Build Properties").

**Examples:**

1.  **Extract specific artifacts to `./extracted_data`:**
    ```bash
    python artifact_extractor.py --output ./extracted_data --artifacts "build_prop,device_properties,installed_packages"
    ```

2.  **Extract all defined artifacts from device `emulator-5554` with verbose output:**
    ```bash
    python artifact_extractor.py --output ./all_device_artifacts --all --device emulator-5554 --verbose
    ```

3.  **List all available artifacts:**
    ```bash
    python artifact_extractor.py --list-artifacts
    ```

**Output Structure:**

Extracted artifacts are organized within the specified output directory as follows:
```
<output_directory>/
└── <device_serial_number>/  (Directory named after the device's serial)
    ├── User Data/
    │   ├── contacts2.db
    │   └── mmssms.db
    ├── Device Information/
    │   ├── build.prop
    │   └── device_properties.txt
    ├── System Configuration/
    │   └── WifiConfigStore.xml
    └── Media_SD Card/
        └── DCIM/
            └── (pulled DCIM contents)
    └── ... (other categories)
```
Each artifact is saved into a subdirectory corresponding to its category (e.g., "User Data", "Device Information", "Media/SD Card"). This helps in keeping the extracted data organized.

## File Hash Generator & Verifier (`hash_verifier.py`)

**Overview:**
`hash_verifier.py` is a utility script for generating cryptographic hashes for files within a directory or for a single file. It can also verify files against a previously generated hash list, helping to ensure data integrity. It supports multiple hash algorithms like MD5, SHA1, SHA256, and SHA512.

**Usage:**
The script uses sub-commands (`hash` or `verify`) to perform actions:
```bash
python hash_verifier.py [hash|verify] [options]
```
*(Note: On Windows, you might need `python.exe` or `py` instead of `python`)*

**Hash File Format:**
The script generates and expects hash files in a simple text format:
*   Each line representing a file contains the hexadecimal hash value followed by two spaces, then the relative filepath (using `/` as a separator).
    Example: `a1b2c3d4...  path/to/file.txt`
*   The file can contain a header line to indicate the hash algorithm used:
    `# HASH_TYPE: <algorithm>` (e.g., `# HASH_TYPE: sha256`)
    This header is used by the `verify` command to auto-detect the hash type.
*   Other lines starting with `#` are treated as comments and ignored during verification.

**`hash` Command:**
This command is used to generate hash values for files.

*   **Arguments:**
    *   `target_path`: (Positional) The path to the file or directory to be hashed. If it's a directory, the script will recursively find and hash all files within it.
    *   `--output HASH_FILE`: (Optional) File path to save the generated hash list. If not provided, the output will be printed to the standard output (console).
    *   `--hashtype {md5,sha1,sha256,sha512}`: (Optional) Specifies the hash algorithm to use. Defaults to `sha256`.

**`verify` Command:**
This command is used to verify the integrity of files against a provided hash list.

*   **Arguments:**
    *   `hash_file`: (Positional) Path to the hash list file (previously generated by the `hash` command or in a compatible format).
    *   `--base-dir BASE_DIR`: (Optional) The base directory from which the relative filepaths in the hash list should be resolved. If not provided, it defaults to the directory containing the `hash_file`.
    *   `--hashtype {md5,sha1,sha256,sha512}`: (Optional) Specifies the hash algorithm used in the `hash_file`. If not provided, the script attempts to auto-detect it from the `# HASH_TYPE:` header in the hash file. If the header is missing and this argument is not given, it defaults to `sha256` (with a warning). This argument can also be used to override the type specified in the header.

**Examples:**

1.  **Generate SHA256 hashes for `./my_project_files` and save to `project_hashes.sha256`:**
    ```bash
    python hash_verifier.py hash ./my_project_files --output project_hashes.sha256 --hashtype sha256
    ```

2.  **Verify files based on `project_hashes.sha256`. Assumes `project_hashes.sha256` is in the current directory and files listed within it are relative to `./my_project_files`:**
    ```bash
    python hash_verifier.py verify ./project_hashes.sha256 --base-dir ./my_project_files
    ```
    If `project_hashes.sha256` was in `output/` and paths inside it were relative to `my_project_files` (which was in the CWD):
    ```bash
    python hash_verifier.py verify ./output/project_hashes.sha256 --base-dir ./my_project_files
    ```

3.  **Generate MD5 hashes for a single file `archive.zip` and print to console:**
    ```bash
    python hash_verifier.py hash ./archive.zip --hashtype md5
    ```

The `verify` command will output the status for each file (OK, FAILED, NOT_FOUND, HASH_ERROR, IS_DIRECTORY) and a final summary.

## Timeline Generator (`timeline_generator.py`)

**Overview:**
`timeline_generator.py` processes directories of files (typically extracted Android artifacts) to create a chronological timeline of events. It currently focuses on parsing filesystem metadata (modification, access, change, and birth times) and is designed to be extensible with more artifact-specific parsers (e.g., for application databases, logs).

**Input:**
The script expects an input directory (`input_dir`) which should contain the files you want to analyze. This is typically a directory created by `artifact_extractor.py` (e.g., `extraction_output/device_id/`) or any other collection of files for which you want to generate a timeline based on their metadata.

**Output Formats:**
The generated timeline can be saved in several formats, determined by the extension of the `--output` filename:
*   `.csv` (Default): Comma Separated Values. Includes a header row and is suitable for import into spreadsheets or other analysis tools.
*   `.txt`: Human-readable plain text, with fields separated by `|`.
*   `.jsonl`: JSON Lines, where each event is a JSON object on a new line. This format is useful for programmatic processing.
If no extension or an unsupported extension is provided for the output file, it defaults to `.txt`. The default output filename is `timeline.csv`.

**Command-Line Arguments:**

*   `input_dir`: (Positional, Required) The path to the input directory containing files to be processed.
*   `--output OUTPUT_FILE`: (Optional) Specifies the name and format of the output file. Defaults to `timeline.csv`.
*   `--start-date YYYY-MM-DD[THH:MM:SS]`: (Optional) Filters events to include only those occurring on or after this UTC date/time.
*   `--end-date YYYY-MM-DD[THH:MM:SS]`: (Optional) Filters events to include only those occurring on or before this UTC date/time. If only a date is given (YYYY-MM-DD), it's treated as the end of that day.
*   `--logcat-year YEAR`: (Optional) Year to assume for Logcat entries if their timestamps don't include a year. (For future Logcat parser)
*   `--logcat-timezone TZ_NAME`: (Optional) Source timezone for Logcat entries (e.g., 'America/New_York'). Defaults to 'UTC'. (For future Logcat parser)
*   `--fs-timestamps {m,a,c,b,all}`: (Optional) Comma-separated list of filesystem timestamps to include:
    *   `m`: Modification time
    *   `a`: Access time
    *   `c`: Metadata change time (or creation time on Windows)
    *   `b`: Birth/Creation time (if available on the OS)
    *   `all`: Equivalent to "m,a,c,b"
    Defaults to `"m,c,a,b"`.
*   `-v, --verbose`: (Optional) Enables verbose output, showing more details about the processing steps.

### Supported Artifacts
The script currently supports parsing the following artifacts found within the input directory:

*   **File System Metadata:** Extracts Modification, Access, Change, and Birth times (if available via `os.stat()`) for all files.
*   **SMS/MMS Messages (`mmssms.db`):**
    *   Extracts sender/receiver address, message body (for SMS), type (sent/received), and primary and sent timestamps.
    *   For MMS, extracts metadata like subject, message box type, and timestamps. (Full text content from MMS parts is a potential future enhancement).
*   **Call Logs (`calllog.db`):**
    *   Extracts caller/callee number and name (if available), call type (Incoming, Outgoing, Missed, etc.), duration, and timestamp.
*   **Google Chrome History (`History` file, typically from `.../app_chrome/Default/`):**
    *   Extracts visited URL, page title, visit count, and the last visit timestamp.

The script identifies these database files by their common names (e.g., `mmssms.db`, `calllog.db`, `History`). Ensure the extracted artifact directory structure (from `artifact_extractor.py` or manual extraction) preserves these names. Parsers for additional artifacts are planned for future updates.

**Examples:**

1.  **Generate a timeline from `./extracted_device_data/` and save to the default `timeline.csv`:**
    ```bash
    python timeline_generator.py ./extracted_device_data/
    ```

2.  **Generate a timeline, filtering for events between 2023-01-15 (inclusive) and 2023-01-16 at noon (inclusive), and output to `events_jan15_16.txt`:**
    ```bash
    python timeline_generator.py ./extracted_device_data/ --start-date 2023-01-15 --end-date 2023-01-16T12:00:00 --output events_jan15_16.txt
    ```

3.  **Generate a timeline including only file modification and access timestamps, saving as JSON Lines:**
    ```bash
    python timeline_generator.py ./extracted_device_data/ --fs-timestamps m,a --output fs_mac_timeline.jsonl
    ```

## HTML Report Generator (`report_generator.py`)

**Overview:**
`report_generator.py` processes an artifact extraction directory (typically generated by `artifact_extractor.py`) and creates a consolidated HTML report summarizing the findings. This provides a user-friendly overview of the extracted data.

**Input:**
The script requires a single positional argument:
*   `input_dir`: The path to the root directory of the extracted artifacts for a specific device (e.g., `./extraction_output/my_device_123/`). This directory should contain subdirectories like `Device Information/`, `User Data/`, etc., as created by `artifact_extractor.py`.

**Output:**
The script generates a single HTML file.
*   **Filename:** By default, the report is named `report_<input_dir_basename>.html` (e.g., `report_my_device_123.html`) and saved in the current working directory. This can be overridden using the `--output` argument.
*   **Content:** The HTML report includes several sections:
    *   **Device Information:** Key properties like model, manufacturer, Android version, and serial number. Also includes the count of installed packages.
    *   **Key Artifacts Status:** A summary table showing whether common artifact files/directories (e.g., `mmssms.db`, `calllog.db`, Chrome `History`, DCIM folder) were found in the input directory, along with their size or item count if applicable.
    *   **Communications Summary:** Counts and recent samples for SMS messages, MMS messages (metadata), and call logs.
    *   **Browsing Summary (Chrome):** Total URL and visit counts from Chrome, along with tables for most frequently visited and most recently visited sites.

**Command-Line Arguments:**

*   `input_dir`: (Positional, Required) Path to the base directory of extracted artifacts for the device.
*   `--output REPORT_HTML`: (Optional) Specifies the output filename for the HTML report. If not provided, a default name is generated based on the input directory name (e.g., `report_<input_dir_basename>.html`).
*   `--title TITLE`: (Optional) Sets a custom title for the HTML report. If not provided, a default title including the input directory basename is used.
*   `--max-sample-items N`: (Optional) The maximum number of sample items (e.g., recent SMS, calls, browser history entries) to display in the report tables. Defaults to 5.

**Examples:**

1.  **Generate a report from an extracted artifact directory with default settings:**
    ```bash
    python report_generator.py ./extraction_output/my_device_123/
    ```
    *(This will create a report named `report_my_device_123.html` in the current directory.)*

2.  **Generate a report with a custom title and output filename:**
    ```bash
    python report_generator.py ./extraction_output/another_device/ --output Investigation_Report.html --title "Report for Another Device"
    ```

## PCAP File Analyzer (`pcap_analyzer.py`)

**Overview:**
`pcap_analyzer.py` analyzes PCAP or PCAPng network capture files to provide various summaries and insights into the captured traffic. It uses the `dpkt` library for packet parsing and can identify Ethernet, IP (v4/v6), TCP, UDP, ICMP, ARP packets, and perform basic analysis for DNS queries, HTTP requests (stateless), and TLS Server Name Indication (SNI).

**Prerequisites:**
*   **dpkt Library:** This script requires the `dpkt` library to be installed. You can install it using pip:
    ```bash
    pip install dpkt
    ```

**Usage:**
The basic command to run the script is:
```bash
python pcap_analyzer.py <pcap_file> [options]
```
*(Note: On Windows, you might need `python.exe` or `py` instead of `python`)*

**Command-Line Arguments:**

*   `pcap_file`: (Positional, Required) The path to the PCAP or PCAPng file to be analyzed.
*   `--output-dir OUTPUT_DIR`: (Optional) Directory where generated CSV summary files will be saved. If not specified, CSV files are not generated.
*   `--filter BPF_FILTER`: (Optional) A BPF (Berkeley Packet Filter) filter string to apply to the packets. (Note: This is currently a placeholder and not implemented in the parsing logic; filtering would occur post-parsing if implemented here, or ideally during capture).
*   `--ip-top-n N`: (Optional) Specifies the number of top source and destination IP addresses to display in summaries. Defaults to 10.
*   `--dns-top-n N`: (Optional) Specifies the number of top DNS queried names to display. Defaults to 10.
*   `--http-top-n N`: (Optional) Specifies the number of top HTTP hosts (from Host headers) to display. Defaults to 10.
*   `--conv-top-n N`: (Optional) Specifies the number of top network conversations (by packet count) to display. Defaults to 10.
*   `--tls-top-n N`: (Optional) Specifies the number of top TLS SNI (Server Name Indication) hostnames to display. Defaults to 10.
*   `-v, --verbose`: (Optional) Enables verbose output, which includes printing details for each processed packet (or a limited number if not verbose) and more detailed processing messages.

**Console Output:**
The script prints several summaries to the console:
*   **Overall Summary Statistics:** Total packets, total bytes, capture duration, average packet size, average data rate, and linktype distribution.
*   **Protocol Distribution:** Counts for Layer 2 Ethernet types, IP versions (IPv4, IPv6, ARP), Transport layer protocols (TCP, UDP, ICMP, etc.), and Application layer protocols (heuristically identified by common ports like DNS/53, HTTP/80, TLS/443).
*   **Top IP Addresses:** Lists of the most frequent source and destination IP addresses.
*   **Top Conversations:** Summaries of the most active network conversations (by packet count), showing source/destination IPs and ports, protocol, packet/byte counts per direction, duration, and a summary of TCP flags.
*   **Top DNS Queries:** List of the most frequently queried DNS names.
*   **Top HTTP Hosts:** List of the most frequently accessed HTTP hosts (from Host headers).
*   **Top TLS SNI Hostnames:** List of the most frequent Server Name Indications from TLS Client Hello messages.

**CSV Outputs (if `--output-dir` is specified):**
If an output directory is provided, the script generates the following CSV files containing more detailed data:
*   `summary_stats.csv`: Key-value pairs of the overall statistics.
*   `protocol_distribution.csv`: Detailed counts for each protocol category.
*   `ip_source_summary.csv`: All source IP addresses and their packet counts.
*   `ip_destination_summary.csv`: All destination IP addresses and their packet counts.
*   `conversations.csv`: Detailed information for all identified network conversations.
*   `dns_queries.csv`: A log of all DNS queries found (timestamp, query ID, name, type).
*   `dns_top_queried_names.csv`: The top N queried DNS names and their counts.
*   `http_requests.csv`: A log of (a sample of) detected HTTP requests.
*   `http_top_hosts.csv`: The top N HTTP hosts and their access counts.
*   `tls_client_hellos_sni.csv`: A log of (a sample of) TLS Client Hello messages that included an SNI.
*   `tls_top_sni.csv`: The top N SNI hostnames and their occurrence counts.

**Examples:**

1.  **Analyze `network_traffic.pcap` and print summaries to the console:**
    ```bash
    python pcap_analyzer.py network_traffic.pcap
    ```

2.  **Analyze `capture.pcapng`, save all generated CSV files to `./analysis_output`, and show verbose console output:**
    ```bash
    python pcap_analyzer.py capture.pcapng --output-dir ./analysis_output --verbose
    ```
    *(This will create files like `./analysis_output/summary_stats.csv`, `./analysis_output/conversations.csv`, etc.)*
