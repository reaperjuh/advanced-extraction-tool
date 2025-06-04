import os
import argparse
import datetime
import csv
import json
import sys
try:
    import zoneinfo # Python 3.9+
except ImportError:
    try:
        from backports import zoneinfo # Fallback for older Python
    except ImportError:
        print("Warning: zoneinfo module not found, and backports.zoneinfo is not installed. Timezone features will be limited to UTC. Consider 'pip install backports.zoneinfo' for timezone support in older Python versions.", file=sys.stderr)
        zoneinfo = None # Ensure zoneinfo exists, even if it's None

# --- Timestamp Conversion Utilities ---
def epoch_seconds_to_utc_datetime(epoch_seconds):
    try:
        return datetime.datetime.fromtimestamp(epoch_seconds, tz=datetime.timezone.utc)
    except (OSError, OverflowError, ValueError, TypeError) as e: # Added TypeError
        # print(f"Warning: Could not convert epoch seconds '{epoch_seconds}': {e}", file=sys.stderr)
        return None

def epoch_milliseconds_to_utc_datetime(epoch_milliseconds):
    try:
        return datetime.datetime.fromtimestamp(epoch_milliseconds / 1000.0, tz=datetime.timezone.utc)
    except (OSError, OverflowError, ValueError, TypeError) as e: # Added TypeError
        # print(f"Warning: Could not convert epoch milliseconds '{epoch_milliseconds}': {e}", file=sys.stderr)
        return None

def webkit_to_utc_datetime(webkit_timestamp_microseconds):
    try:
        webkit_epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return webkit_epoch_start + datetime.timedelta(microseconds=webkit_timestamp_microseconds)
    except (OverflowError, ValueError, TypeError) as e: # Added TypeError
        # print(f"Warning: Could not convert WebKit timestamp '{webkit_timestamp_microseconds}': {e}", file=sys.stderr)
        return None

def logcat_timestamp_to_utc_datetime(log_date_str, log_time_str, year, source_tz_str='UTC'):
    try:
        naive_dt_str = f"{year}-{log_date_str} {log_time_str}"
        naive_dt = datetime.datetime.strptime(naive_dt_str, "%Y-%m-%d %H:%M:%S.%f")

        if zoneinfo and source_tz_str and source_tz_str.upper() != 'UTC':
            try:
                source_tz = zoneinfo.ZoneInfo(source_tz_str)
                localized_dt = naive_dt.replace(tzinfo=source_tz)
                return localized_dt.astimezone(datetime.timezone.utc)
            except zoneinfo.ZoneInfoNotFoundError:
                # print(f"Warning: Timezone '{source_tz_str}' not found. Assuming UTC for logcat entry '{log_date_str} {log_time_str}'.", file=sys.stderr)
                return naive_dt.replace(tzinfo=datetime.timezone.utc)
        else:
            return naive_dt.replace(tzinfo=datetime.timezone.utc)
    except ValueError as e: # strptime errors
        # print(f"Warning: Could not parse logcat timestamp '{log_date_str} {log_time_str}' with year {year}: {e}", file=sys.stderr)
        return None
    except TypeError as e: # Other potential type errors with date/time components
        # print(f"Warning: Type error in logcat timestamp conversion for '{log_date_str} {log_time_str}': {e}", file=sys.stderr)
        return None


# --- Date/Time Parsing for Filters ---
def parse_filter_datetime(datetime_str):
    if not datetime_str:
        return None
    try:
        return datetime.datetime.fromisoformat(datetime_str)
    except ValueError:
        try:
            return datetime.datetime.strptime(datetime_str, "%Y-%m-%d")
        except ValueError as e:
            print(f"Error: Invalid date/time format for filter '{datetime_str}'. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS. Details: {e}", file=sys.stderr)
            return None

# --- Filesystem Metadata Parser ---
def parse_filesystem_metadata(filepath, selected_fs_timestamps_str="m,c,a,b"):
    selected_timestamps = selected_fs_timestamps_str.lower().split(',')
    events = []
    try:
        stat_info = os.stat(filepath)
        ts_map = {
            'm': ('File Modified', stat_info.st_mtime),
            'a': ('File Accessed', stat_info.st_atime),
            'c': ('File Metadata Changed', stat_info.st_ctime)
        }
        if hasattr(stat_info, 'st_birthtime'): # Check if birthtime attribute exists
             ts_map['b'] = ('File Created (Birth)', stat_info.st_birthtime)

        for type_char, (desc, ts_value) in ts_map.items():
            if type_char in selected_timestamps:
                dt_utc = epoch_seconds_to_utc_datetime(ts_value)
                if dt_utc:
                    events.append({
                        'timestamp_utc': dt_utc, 'source_type': 'File System', 'event_type': desc,
                        'short_description': f'{os.path.basename(filepath)} ({type_char.upper()})',
                        'full_path': os.path.abspath(filepath), 'source_name': os.path.basename(filepath),
                        'details': {'size': stat_info.st_size, 'mode': oct(stat_info.st_mode)[2:]}
                    })
    except OSError as e:
        print(f"Error stating file '{filepath}': {e}", file=sys.stderr)
    return events

# --- Argument Parser Setup ---
def setup_parser():
    parser = argparse.ArgumentParser(description="Generate a timeline from various data sources.")
    parser.add_argument("input_dir", help="Input directory containing files to process.")
    parser.add_argument("--output", default="timeline.csv", help="Output file name (default: timeline.csv). Supports .csv, .txt, .jsonl.")
    date_format_help = "YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"
    parser.add_argument("--start-date", help=f"Filter events on or after this UTC date/time ({date_format_help}).")
    parser.add_argument("--end-date", help=f"Filter events on or before this UTC date/time ({date_format_help}).")
    parser.add_argument("--logcat-year", type=int, help="Year for logcat entries if not in log.")
    parser.add_argument("--logcat-timezone", default="UTC", help="Source timezone for logcat entries (default: UTC).")
    parser.add_argument("--fs-timestamps", default="m,c,a,b", help="Filesystem timestamps: m,c,a,b (default: 'm,c,a,b').")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    return parser

# --- Main Block ---
if __name__ == '__main__':
    parser = setup_parser()
    args = parser.parse_args()

    timeline_events = []

    if not os.path.isdir(args.input_dir):
        print(f"Error: Input directory '{args.input_dir}' not found or not a directory.", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"Timeline Generation Tool\nInput directory: {os.path.abspath(args.input_dir)}\nOutput file: {os.path.abspath(args.output)}")
        if args.start_date: print(f"Start date filter: {args.start_date}")
        if args.end_date: print(f"End date filter: {args.end_date}")
        print(f"Filesystem timestamps: {args.fs_timestamps}\n" + "-" * 30, file=sys.stderr)

    parsed_start_date = parse_filter_datetime(args.start_date) if args.start_date else None
    parsed_end_date = parse_filter_datetime(args.end_date) if args.end_date else None

    if args.start_date and parsed_start_date is None: sys.exit(1)
    if args.end_date and parsed_end_date is None: sys.exit(1)

    if parsed_end_date and parsed_end_date.hour == 0 and parsed_end_date.minute == 0 and parsed_end_date.second == 0:
        parsed_end_date = datetime.datetime.combine(parsed_end_date.date(), datetime.time.max)

    if args.verbose: print(f"Scanning directory: {args.input_dir}...", file=sys.stderr)

    file_count = 0
    for root_dir, _, files in os.walk(args.input_dir):
        for filename in files:
            current_filepath = os.path.join(root_dir, filename)
            if args.verbose and file_count > 0 and file_count % 1000 == 0:
                 print(f"  Processed {file_count} files for FS metadata...", file=sys.stderr)

            fs_events = parse_filesystem_metadata(current_filepath, args.fs_timestamps)
            timeline_events.extend(fs_events)
            file_count +=1

    if args.verbose: print(f"Collected {len(timeline_events)} raw events from {file_count} files.", file=sys.stderr)

    if parsed_start_date or parsed_end_date:
        if args.verbose: print("Applying date filters...", file=sys.stderr)
        original_event_count = len(timeline_events)
        if parsed_start_date:
            timeline_events = [e for e in timeline_events if e['timestamp_utc'] and e['timestamp_utc'].replace(tzinfo=None) >= parsed_start_date]
        if parsed_end_date:
            timeline_events = [e for e in timeline_events if e['timestamp_utc'] and e['timestamp_utc'].replace(tzinfo=None) <= parsed_end_date]
        if args.verbose: print(f"{len(timeline_events)} events remaining after date filtering (removed {original_event_count - len(timeline_events)}).", file=sys.stderr)

    timeline_events.sort(key=lambda e: e['timestamp_utc'] if e['timestamp_utc'] else datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))

    output_filename = args.output
    file_ext = os.path.splitext(output_filename)[1].lower()

    if args.verbose: print(f"Writing {len(timeline_events)} events to {output_filename} (format: {file_ext or 'default to .txt'})", file=sys.stderr)

    try:
        with open(output_filename, 'w', newline='', encoding='utf-8') as f_out:
            if file_ext == '.csv':
                writer = csv.writer(f_out)
                header = ["Timestamp (UTC)", "Source Type", "Event Type", "Short Description", "Full Path", "Source Name", "Details (JSON)"]
                writer.writerow(header)
                for event in timeline_events:
                    ts_iso = event['timestamp_utc'].isoformat() if event['timestamp_utc'] else "N/A"
                    details_json = json.dumps(event.get('details', {}))
                    writer.writerow([
                        ts_iso, event.get('source_type', ''), event.get('event_type', ''),
                        event.get('short_description', ''), event.get('full_path', ''),
                        event.get('source_name', ''), details_json
                    ])
            elif file_ext == '.txt' or not file_ext :
                if not file_ext and args.verbose:
                    print(f"Info: No specific output extension, defaulting to .txt format for '{output_filename}'", file=sys.stderr)
                for event in timeline_events:
                    ts_iso = event['timestamp_utc'].isoformat() if event['timestamp_utc'] else "N/A"
                    details_str = json.dumps(event.get('details', {}))
                    f_out.write(f"{ts_iso} | {event.get('source_type', ''):<15} | {event.get('event_type', ''):<25} | {event.get('short_description', ''):<50} | Path: {event.get('full_path', '')} | Details: {details_str}\n")
            elif file_ext == '.jsonl':
                 for event in timeline_events:
                    event_copy = event.copy()
                    if event_copy.get('timestamp_utc'):
                        event_copy['timestamp_utc'] = event_copy['timestamp_utc'].isoformat()
                    f_out.write(json.dumps(event_copy) + '\n')
            else:
                print(f"Warning: Unsupported output file extension '{file_ext}'. Defaulting to TXT format.", file=sys.stderr)
                for event in timeline_events:
                    ts_iso = event['timestamp_utc'].isoformat() if event['timestamp_utc'] else "N/A"
                    details_str = json.dumps(event.get('details', {}))
                    f_out.write(f"{ts_iso} | {event.get('source_type', ''):<15} | {event.get('event_type', ''):<25} | {event.get('short_description', ''):<50} | Path: {event.get('full_path', '')} | Details: {details_str}\n")

        if args.verbose: print(f"Timeline successfully written to {os.path.abspath(output_filename)}", file=sys.stderr)

    except IOError as e:
        print(f"Error writing output to file '{output_filename}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during output generation: {e}", file=sys.stderr)
        sys.exit(1)

    if args.verbose: print("\nTimeline generation process finished.", file=sys.stderr)
