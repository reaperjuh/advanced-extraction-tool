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
