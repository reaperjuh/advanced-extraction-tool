import argparse
import re
import sys
import csv
import json

# --- ANSI Escape Codes for Highlighting ---
COLORS = {
    'V': '\033[94m',  # Blue for Verbose
    'D': '\033[96m',  # Cyan for Debug
    'I': '\033[92m',  # Green for Info
    'W': '\033[93m',  # Yellow for Warning
    'E': '\033[91m',  # Red for Error
    'F': '\033[91m\033[1m',  # Bright Red (Red + Bold) for Fatal
    'DEFAULT': '\033[0m' # Default color (reset)
}
BOLD = '\033[1m'
RESET = '\033[0m'
# --- End ANSI Escape Codes ---

# Define log priorities
LOG_PRIORITIES = {
    'V': 0, 'D': 1, 'I': 2, 'W': 3, 'E': 4, 'F': 5
}

# Regex for threadtime log format
LOG_REGEX = re.compile(
    r"^(?P<date>\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    # Optional TID: (?:\[\s*\d+\s*\]\s+)?
    r"(?P<priority>[VDIWEF])/"
    r"(?P<tag>[^(\s]+)\s*"
    r"\(\s*(?P<pid>\d+)\s*\):\s+"
    r"(?P<message>[\s\S]*)$" # Allow message to contain newlines
)

def parse_log_line(line):
    """Parses a single log line and returns a dictionary of its components."""
    match = LOG_REGEX.match(line)
    if match:
        parsed = match.groupdict()
        if parsed.get('pid'):
            parsed['pid'] = parsed['pid'].strip()
        return parsed
    return None

def is_log_line_visible(parsed_log, args):
    """Checks if a parsed log line should be displayed based on filter arguments."""
    if not parsed_log:
        return False

    if args.min_priority:
        current_priority_val = LOG_PRIORITIES.get(parsed_log['priority'])
        min_priority_val = LOG_PRIORITIES.get(args.min_priority.upper())
        if current_priority_val is None or min_priority_val is None or \
           current_priority_val < min_priority_val:
            return False

    if args.tag and parsed_log.get('tag') not in args.tag:
        return False

    if args.pid and parsed_log.get('pid') not in args.pid:
        return False

    if args.keyword:
        message_lower = parsed_log.get('message', '').lower()
        if not any(kw.lower() in message_lower for kw in args.keyword):
            return False
    return True

def format_log_for_console(original_line, parsed_log, args):
    """Formats a log line for console output with highlighting."""
    if not sys.stdout.isatty(): # No colors if not a TTY
        return original_line

    priority_color = COLORS.get(parsed_log['priority'], COLORS['DEFAULT'])
    line_style = ""

    # Check for highlight-keyword
    if args.highlight_keyword:
        message_lower = parsed_log.get('message', '').lower()
        if any(hkw.lower() in message_lower for hkw in args.highlight_keyword):
            line_style = BOLD # Apply bold style

    return f"{line_style}{priority_color}{original_line}{RESET}"


def main():
    parser = argparse.ArgumentParser(description="Analyzes Android 'threadtime' logcat output.")
    parser.add_argument(
        '--input-file',
        type=str,
        help="Path to a log file to read from. If not provided, reads from stdin."
    )
    parser.add_argument(
        '--min-priority',
        type=str,
        choices=['V', 'D', 'I', 'W', 'E', 'F', 'v', 'd', 'i', 'w', 'e', 'f'],
        help="Minimum log priority to display (V, D, I, W, E, F)."
    )
    parser.add_argument(
        '--tag',
        type=str,
        action='append',
        help="Log tags to include (can be specified multiple times)."
    )
    parser.add_argument(
        '--pid',
        type=str,
        action='append',
        help="Process IDs to include (can be specified multiple times)."
    )
    parser.add_argument(
        '--keyword',
        type=str,
        action='append',
        help="Keywords to search for in the log message (case-insensitive, can be specified multiple times)."
    )
    parser.add_argument(
        '--highlight-keyword',
        type=str,
        action='append',
        help="Keywords to highlight in the output (case-insensitive, makes line bold, TTY only)."
    )
    parser.add_argument(
        '--output-csv',
        type=str,
        help="Path to save filtered logs as a CSV file."
    )
    parser.add_argument(
        '--output-json',
        type=str,
        help="Path to save filtered logs as a JSON file."
    )

    args = parser.parse_args()

    if args.min_priority:
        args.min_priority = args.min_priority.upper()

    input_source = None
    csv_writer = None
    csv_file = None
    json_data = []

    try:
        if args.input_file:
            input_source = open(args.input_file, 'r', encoding='utf-8')
        else:
            input_source = sys.stdin

        if args.output_csv:
            csv_file = open(args.output_csv, 'w', newline='', encoding='utf-8')
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(['date', 'time', 'priority', 'tag', 'pid', 'message'])

        for line in input_source:
            original_line = line.rstrip('\n')
            parsed_log = parse_log_line(original_line)

            if parsed_log and is_log_line_visible(parsed_log, args):
                # Console output
                print(format_log_for_console(original_line, parsed_log, args))

                # CSV output
                if csv_writer:
                    csv_writer.writerow([
                        parsed_log['date'], parsed_log['time'], parsed_log['priority'],
                        parsed_log['tag'], parsed_log['pid'], parsed_log['message']
                    ])

                # JSON output
                if args.output_json:
                    json_data.append(parsed_log)

        if args.output_json and json_data:
            with open(args.output_json, 'w', encoding='utf-8') as f_json:
                json.dump(json_data, f_json, indent=4)

    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if args.input_file and input_source and input_source is not sys.stdin:
            input_source.close()
        if csv_file:
            csv_file.close()

if __name__ == '__main__':
    main()
