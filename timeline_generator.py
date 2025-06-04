import os
import argparse
import datetime
import csv
import json
import sys
import sqlite3
try:
    import zoneinfo # Python 3.9+
except ImportError:
    try:
        from backports import zoneinfo # Fallback for older Python
    except ImportError:
        print("Warning: zoneinfo module not found, and backports.zoneinfo is not installed. Timezone features will be limited to UTC. Consider 'pip install backports.zoneinfo' for timezone support in older Python versions.", file=sys.stderr)
        zoneinfo = None

# --- Timestamp Conversion Utilities ---
def epoch_seconds_to_utc_datetime(epoch_seconds):
    if epoch_seconds is None: return None
    try:
        return datetime.datetime.fromtimestamp(epoch_seconds, tz=datetime.timezone.utc)
    except (OSError, OverflowError, ValueError, TypeError) as e:
        return None

def epoch_milliseconds_to_utc_datetime(epoch_milliseconds):
    if epoch_milliseconds is None: return None
    try:
        return datetime.datetime.fromtimestamp(epoch_milliseconds / 1000.0, tz=datetime.timezone.utc)
    except (OSError, OverflowError, ValueError, TypeError) as e:
        return None

def webkit_to_utc_datetime(webkit_timestamp_microseconds):
    if webkit_timestamp_microseconds is None: return None
    try:
        webkit_epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        # Ensure input is treated as integer for timedelta
        return webkit_epoch_start + datetime.timedelta(microseconds=int(webkit_timestamp_microseconds))
    except (OverflowError, ValueError, TypeError) as e:
        return None

def logcat_timestamp_to_utc_datetime(log_date_str, log_time_str, year, source_tz_str='UTC'):
    if None in [log_date_str, log_time_str, year]: return None
    try:
        naive_dt_str = f"{year}-{log_date_str} {log_time_str}"
        naive_dt = datetime.datetime.strptime(naive_dt_str, "%Y-%m-%d %H:%M:%S.%f")
        if zoneinfo and source_tz_str and source_tz_str.upper() != 'UTC':
            try:
                source_tz = zoneinfo.ZoneInfo(source_tz_str)
                localized_dt = naive_dt.replace(tzinfo=source_tz)
                return localized_dt.astimezone(datetime.timezone.utc)
            except zoneinfo.ZoneInfoNotFoundError:
                return naive_dt.replace(tzinfo=datetime.timezone.utc)
        else:
            return naive_dt.replace(tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError) as e:
        return None

# --- Date/Time Parsing for Filters ---
def parse_filter_datetime(datetime_str):
    if not datetime_str: return None
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
        if hasattr(stat_info, 'st_birthtime'):
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
        if verbose_flag_for_parsers: print(f"Error stating file '{filepath}': {e}", file=sys.stderr) # Use global verbose
    return events

# --- SMS/MMS Database Parser ---
def parse_sms_mms_db(db_path, verbose=False):
    events = []
    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT address, date, date_sent, type, body, sub_id, thread_id FROM sms")
            for row in cursor.fetchall():
                timestamp_primary = epoch_milliseconds_to_utc_datetime(row['date'])
                timestamp_sent = epoch_milliseconds_to_utc_datetime(row['date_sent']) if row['date_sent'] and row['date_sent'] > 0 else None
                event_type_detail = {1: "Received", 2: "Sent"}.get(row['type'], f"Type {row['type']}")
                short_desc = f"SMS {event_type_detail} - From/To: {row['address'] if row['address'] else 'N/A'}"
                details = {'address': row['address'], 'body': row['body'], 'type_code': row['type'],
                           'sub_id': row['sub_id'], 'thread_id': row['thread_id']}
                if timestamp_primary:
                    events.append({'timestamp_utc': timestamp_primary, 'source_type': 'SMS/MMS',
                        'event_type': f'SMS {event_type_detail}', 'short_description': short_desc,
                        'full_path': db_path, 'source_name': "mmssms.db (sms table)", 'details': details})
                if timestamp_sent and timestamp_sent != timestamp_primary:
                    events.append({'timestamp_utc': timestamp_sent, 'source_type': 'SMS/MMS',
                        'event_type': f'SMS Sent (Reported)', 'short_description': short_desc,
                        'full_path': db_path, 'source_name': "mmssms.db (sms table - date_sent)", 'details': details})
        except sqlite3.Error as e:
            if verbose: print(f"Error querying SMS table in {db_path}: {e}", file=sys.stderr)
        try:
            cursor.execute("SELECT _id, thread_id, date, date_sent, msg_box, sub, ct_l FROM mms")
            for row in cursor.fetchall():
                timestamp_primary = epoch_seconds_to_utc_datetime(row['date'])
                timestamp_sent = epoch_seconds_to_utc_datetime(row['date_sent']) if row['date_sent'] and row['date_sent'] > 0 else None
                event_type_detail = {1: "Received", 2: "Sent", 3: "Draft", 4: "Outbox"}.get(row['msg_box'], f"MsgBox {row['msg_box']}")
                short_desc = f"MMS {event_type_detail} - Subject: {row['sub'] if row['sub'] else 'N/A'}"
                details = {'mms_id': row['_id'], 'thread_id': row['thread_id'], 'subject': row['sub'],
                           'content_location': row['ct_l'], 'msg_box_code': row['msg_box']}
                if timestamp_primary:
                    events.append({'timestamp_utc': timestamp_primary, 'source_type': 'SMS/MMS',
                        'event_type': f'MMS {event_type_detail}', 'short_description': short_desc,
                        'full_path': db_path, 'source_name': "mmssms.db (mms table)", 'details': details})
                if timestamp_sent and timestamp_sent != timestamp_primary:
                     events.append({'timestamp_utc': timestamp_sent, 'source_type': 'SMS/MMS',
                        'event_type': f'MMS Sent (Reported)', 'short_description': short_desc,
                        'full_path': db_path, 'source_name': "mmssms.db (mms table - date_sent)", 'details': details})
        except sqlite3.Error as e:
            if verbose: print(f"Error querying MMS table in {db_path}: {e}", file=sys.stderr)
        conn.close()
    except sqlite3.Error as e:
        if verbose: print(f"Error connecting to or reading SMS/MMS DB {db_path}: {e}", file=sys.stderr)
    except Exception as e:
        if verbose: print(f"Unexpected error parsing SMS/MMS DB {db_path}: {e}", file=sys.stderr)
    return events

# --- Call Log Database Parser ---
def parse_calllog_db(db_path, verbose=False):
    events = []
    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        query = "SELECT name, number, date, duration, type, geocoded_location, countryiso FROM calls ORDER BY date"
        try:
            cursor.execute(query)
            for row in cursor.fetchall():
                timestamp_utc = epoch_milliseconds_to_utc_datetime(row['date'])
                if timestamp_utc is None:
                    if verbose: print(f"Skipping call log entry with invalid date: {row['date']} in {db_path}", file=sys.stderr)
                    continue
                call_type_map = {1: "Incoming", 2: "Outgoing", 3: "Missed", 4: "Voicemail", 5: "Rejected", 6: "Blocked", 7: "Answered Externally"}
                call_type_code = row['type']
                event_type_detail = call_type_map.get(call_type_code, f"Type {call_type_code}")
                display_number = row['number'] if row['number'] else 'N/A'
                display_name = row['name'] if row['name'] and str(row['name']).strip() else display_number
                short_desc = f"Call {event_type_detail} - {display_name}"
                details_dict = {'number': row['number'], 'name': row['name'], 'duration_seconds': row['duration'],
                                'call_type_code': call_type_code, 'geocoded_location': row['geocoded_location'],
                                'country_iso': row['countryiso']}
                details = {k: v for k, v in details_dict.items() if v is not None}
                events.append({'timestamp_utc': timestamp_utc, 'source_type': 'Call Log',
                    'event_type': f'Call {event_type_detail}', 'short_description': short_desc,
                    'full_path': db_path, 'source_name': os.path.basename(db_path), 'details': details})
        except sqlite3.Error as e:
            if verbose: print(f"Error querying 'calls' table in {db_path}: {e}. Common columns might be missing.", file=sys.stderr)
        conn.close()
    except sqlite3.Error as e:
        if verbose: print(f"Error connecting to or reading Call Log DB {db_path}: {e}", file=sys.stderr)
    except Exception as e:
        if verbose: print(f"Unexpected error parsing Call Log DB {db_path}: {e}", file=sys.stderr)
    return events

# --- Chrome History Database Parser ---
def parse_chrome_history_db(db_path, verbose=False):
    events = []
    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        query = "SELECT id, url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time"
        try:
            cursor.execute(query)
            for row in cursor.fetchall():
                timestamp_utc = webkit_to_utc_datetime(row['last_visit_time'])
                if timestamp_utc is None:
                    if verbose: print(f"Skipping Chrome history entry with invalid last_visit_time: {row['last_visit_time']} for url ID {row['id']} in {db_path}", file=sys.stderr)
                    continue

                event_type_detail = "URL Visited (Last)"
                url_for_desc = row['url'] if row['url'] else ""
                short_desc = f"Visited: {url_for_desc[:100]}"

                details_dict = {'url': row['url'], 'title': row['title'], 'visit_count': row['visit_count']}
                details = {k: v for k, v in details_dict.items() if v is not None}

                events.append({
                    'timestamp_utc': timestamp_utc,
                    'source_type': 'Chrome History',
                    'event_type': event_type_detail,
                    'short_description': short_desc,
                    'full_path': db_path,
                    'source_name': os.path.basename(db_path), # Typically 'History'
                    'details': details
                })
        except sqlite3.Error as e:
            if verbose: print(f"Error querying 'urls' table in Chrome History DB {db_path}: {e}", file=sys.stderr)
        conn.close()
    except sqlite3.Error as e:
        if verbose: print(f"Error connecting to or reading Chrome History DB {db_path}: {e}", file=sys.stderr)
    except Exception as e:
        if verbose: print(f"Unexpected error parsing Chrome History DB {db_path}: {e}", file=sys.stderr)
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
verbose_flag_for_parsers = False # Module-level flag for parsers to use

if __name__ == '__main__':
    parser = setup_parser()
    args = parser.parse_args()

    if args.verbose: # Set the global verbose flag if -v is used
        verbose_flag_for_parsers = True

    timeline_events = []

    if not os.path.isdir(args.input_dir):
        print(f"Error: Input directory '{args.input_dir}' not found or not a directory.", file=sys.stderr)
        sys.exit(1)

    if verbose_flag_for_parsers:
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

    if verbose_flag_for_parsers: print(f"Scanning directory: {args.input_dir}...", file=sys.stderr)

    file_count = 0
    for root_dir, _, files in os.walk(args.input_dir):
        for filename in files:
            current_filepath = os.path.join(root_dir, filename)
            if verbose_flag_for_parsers and file_count > 0 and file_count % 1000 == 0:
                 print(f"  Processed {file_count} files...", file=sys.stderr)

            fs_events = parse_filesystem_metadata(current_filepath, args.fs_timestamps) # Pass verbose flag
            timeline_events.extend(fs_events)
            file_count +=1

            fn_lower = filename.lower()
            if fn_lower == "mmssms.db":
                if verbose_flag_for_parsers: print(f"Processing SMS/MMS database: {current_filepath}", file=sys.stderr)
                sms_mms_events = parse_sms_mms_db(current_filepath, verbose_flag_for_parsers)
                timeline_events.extend(sms_mms_events)
                if verbose_flag_for_parsers: print(f"  Found {len(sms_mms_events)} events from {filename}", file=sys.stderr)
            elif fn_lower == "calllog.db":
                if verbose_flag_for_parsers: print(f"Processing Call Log database: {current_filepath}", file=sys.stderr)
                calllog_events = parse_calllog_db(current_filepath, verbose_flag_for_parsers)
                timeline_events.extend(calllog_events)
                if verbose_flag_for_parsers: print(f"  Found {len(calllog_events)} events from {filename}", file=sys.stderr)
            elif fn_lower == "history" and ("chrome" in root_dir.lower() or "chromium" in root_dir.lower()):
                 if verbose_flag_for_parsers: print(f"Processing Chrome History database: {current_filepath}", file=sys.stderr)
                 chrome_events = parse_chrome_history_db(current_filepath, verbose_flag_for_parsers)
                 timeline_events.extend(chrome_events)
                 if verbose_flag_for_parsers: print(f"  Found {len(chrome_events)} events from {filename}", file=sys.stderr)

    if verbose_flag_for_parsers: print(f"Collected {len(timeline_events)} raw events from {file_count} files and parsed artifacts.", file=sys.stderr)

    if parsed_start_date or parsed_end_date:
        if verbose_flag_for_parsers: print("Applying date filters...", file=sys.stderr)
        original_event_count = len(timeline_events)
        if parsed_start_date:
            timeline_events = [e for e in timeline_events if e['timestamp_utc'] and e['timestamp_utc'].replace(tzinfo=None) >= parsed_start_date]
        if parsed_end_date:
            timeline_events = [e for e in timeline_events if e['timestamp_utc'] and e['timestamp_utc'].replace(tzinfo=None) <= parsed_end_date]
        if verbose_flag_for_parsers: print(f"{len(timeline_events)} events remaining after date filtering (removed {original_event_count - len(timeline_events)}).", file=sys.stderr)

    timeline_events.sort(key=lambda e: e['timestamp_utc'] if e['timestamp_utc'] else datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))

    output_filename = args.output
    file_ext = os.path.splitext(output_filename)[1].lower()

    if verbose_flag_for_parsers: print(f"Writing {len(timeline_events)} events to {output_filename} (format: {file_ext or 'default to .txt'})", file=sys.stderr)

    try:
        with open(output_filename, 'w', newline='', encoding='utf-8') as f_out:
            if file_ext == '.csv':
                writer = csv.writer(f_out)
                header = ["Timestamp (UTC)", "Source Type", "Event Type", "Short Description", "Full Path", "Source Name", "Details (JSON)"]
                writer.writerow(header)
                for event in timeline_events:
                    ts_iso = event['timestamp_utc'].isoformat() if event['timestamp_utc'] else "N/A"
                    details_json = json.dumps(event.get('details', {}))
                    writer.writerow([ ts_iso, event.get('source_type', ''), event.get('event_type', ''),
                        event.get('short_description', ''), event.get('full_path', ''),
                        event.get('source_name', ''), details_json ])
            elif file_ext == '.txt' or not file_ext :
                if not file_ext and verbose_flag_for_parsers:
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
        if verbose_flag_for_parsers: print(f"Timeline successfully written to {os.path.abspath(output_filename)}", file=sys.stderr)
    except IOError as e:
        print(f"Error writing output to file '{output_filename}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during output generation: {e}", file=sys.stderr)
        sys.exit(1)
    if verbose_flag_for_parsers: print("\nTimeline generation process finished.", file=sys.stderr)
