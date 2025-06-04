import os
import argparse
import hashlib
import sys
import re

# --- Global Constants ---
SUPPORTED_HASH_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']
DEFAULT_HASH_ALGORITHM = 'sha256'
BLOCK_SIZE = 65536  # 64KB for reading file chunks

# --- Hash Calculation ---
def calculate_file_hash(filepath, algorithm):
    if algorithm not in SUPPORTED_HASH_ALGORITHMS:
        print(f"Error: Unsupported hash algorithm '{algorithm}'. Supported: {SUPPORTED_HASH_ALGORITHMS}", file=sys.stderr)
        return None
    hasher = hashlib.new(algorithm)
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(BLOCK_SIZE):
                hasher.update(chunk)
        return hasher.hexdigest()
    except IOError as e:
        print(f"Error reading file '{filepath}': {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred while hashing '{filepath}': {e}", file=sys.stderr)
        return None

# --- Path Processing for Hashing (Generator) ---
def process_path_for_hashing(target_path, algorithm):
    if os.path.isfile(target_path):
        digest = calculate_file_hash(target_path, algorithm)
        yield digest, os.path.basename(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for filename in files:
                full_path = os.path.join(root, filename)
                if not os.path.islink(full_path) or os.path.exists(full_path):
                    relative_path = os.path.relpath(full_path, target_path)
                    digest = calculate_file_hash(full_path, algorithm)
                    yield digest, relative_path
                elif os.path.islink(full_path) and not os.path.exists(full_path) :
                     print(f"Warning: Skipping broken symbolic link '{full_path}'.", file=sys.stderr)
    else:
        print(f"Error: Path '{target_path}' is not a valid file or directory.", file=sys.stderr)
        return

# --- Hash File Parsing for Verification ---
def parse_hash_file_and_get_type(hash_file_path):
    """
    Parses a hash file, extracting entries and detecting the hash type.
    """
    detected_hash_type = None
    hash_entries = []
    # Try with two spaces first (more specific, common for *sum tools)
    pattern_two_spaces = re.compile(r"([a-f0-9]+)\s\s+(.+)", re.IGNORECASE)
    # Fallback to one or more spaces
    pattern_one_plus_spaces = re.compile(r"([a-f0-9]+)\s+(.+)", re.IGNORECASE)

    try:
        with open(hash_file_path, 'r', encoding='utf-8') as f:
            for line_num, line_content in enumerate(f, 1):
                line = line_content.strip()
                if not line or line.startswith('# HASH_TYPE: FILE_INFO:'): # Skip empty lines or specific Aegis comments
                    if line.startswith("# HASH_TYPE:"):
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            ht = parts[1].strip().lower()
                            if ht in SUPPORTED_HASH_ALGORITHMS:
                                detected_hash_type = ht
                            # else: print(f"Warning: Unknown hash type '{ht}' in header.", file=sys.stderr) # Optional
                    continue # Move to next line after processing header or skipping comment/empty

                match = pattern_two_spaces.match(line)
                if not match:
                    match = pattern_one_plus_spaces.match(line) # Try fallback pattern

                if match:
                    hash_entries.append({'hash': match.group(1).lower(), 'path': match.group(2).strip()})
                elif line.startswith("#"): # Allow other general comments
                    continue
                else:
                    print(f"Warning: Malformed line skipped at {os.path.basename(hash_file_path)}:{line_num}: {line_content.rstrip()}", file=sys.stderr)
        return detected_hash_type, hash_entries
    except IOError as e:
        print(f"Error reading hash file '{hash_file_path}': {e}", file=sys.stderr)
        return None, [] # Indicate error by returning None for hash_type

# --- Argument Parser Setup ---
def setup_parser():
    parser = argparse.ArgumentParser(description="Generate or verify file hashes.")
    subparsers = parser.add_subparsers(dest='command', title='commands', help='Available commands', required=True)
    hash_parser = subparsers.add_parser('hash', help="Generate hashes for files/directories.")
    hash_parser.add_argument('target_path', help="Path to the file or directory to hash.")
    hash_parser.add_argument('--output', metavar='HASH_FILE', help="File to save hashes. Stdout if not set.")
    hash_parser.add_argument('--hashtype', choices=SUPPORTED_HASH_ALGORITHMS, default=DEFAULT_HASH_ALGORITHM, help=f"Hash algorithm (default: {DEFAULT_HASH_ALGORITHM}).")

    verify_parser = subparsers.add_parser('verify', help="Verify files against a hash list.")
    verify_parser.add_argument('hash_file', help="Path to the hash list file.")
    verify_parser.add_argument('--base-dir', metavar='BASE_DIR', help="Base directory for resolving filepaths. Defaults to hash file's directory.")
    verify_parser.add_argument('--hashtype', choices=SUPPORTED_HASH_ALGORITHMS, default=None, help=f"Hash algorithm (default: auto-detect or {DEFAULT_HASH_ALGORITHM}).")
    return parser

# --- Main Execution ---
if __name__ == '__main__':
    parser = setup_parser()
    args = parser.parse_args()

    if args.command == 'hash':
        output_stream = None
        try:
            output_stream = open(args.output, 'w', encoding='utf-8') if args.output else sys.stdout
            output_stream.write(f"# HASH_TYPE: {args.hashtype}\n")
            files_processed_count = 0
            for digest, rel_path in process_path_for_hashing(args.target_path, args.hashtype):
                files_processed_count += 1
                if digest:
                    output_stream.write(f"{digest}  {rel_path.replace(os.sep, '/')}\n")
                else:
                    print(f"Error: Could not hash file '{rel_path}'. See previous errors.", file=sys.stderr)
            if files_processed_count == 0 and not (not os.path.exists(args.target_path) or os.path.isdir(args.target_path)):
                 print(f"Warning: No files found or processed in '{args.target_path}'.", file=sys.stderr)
        except IOError as e:
            print(f"Error writing to output file '{args.output}': {e}", file=sys.stderr)
        except Exception as e:
            print(f"An unexpected error occurred during hashing: {e}", file=sys.stderr)
        finally:
            if args.output and output_stream is not sys.stdout and output_stream and not output_stream.closed:
                output_stream.close()

    elif args.command == 'verify':
        detected_hash_type, hash_entries = parse_hash_file_and_get_type(args.hash_file)

        if detected_hash_type is None and not hash_entries: # Indicates IO error in parse_hash_file
            sys.exit(1)
        if not hash_entries:
            print("Warning: No valid hash entries found in the hash file.", file=sys.stderr)
            sys.exit(0)

        effective_hash_type = DEFAULT_HASH_ALGORITHM
        if args.hashtype:
            effective_hash_type = args.hashtype
            if detected_hash_type and detected_hash_type != effective_hash_type.lower():
                print(f"Warning: User-specified hash type '{effective_hash_type}' overrides detected type '{detected_hash_type}' from file.", file=sys.stderr)
        elif detected_hash_type:
            effective_hash_type = detected_hash_type
        else:
            print(f"Warning: Hash type not specified and not detected in file. Assuming {DEFAULT_HASH_ALGORITHM}.", file=sys.stderr)

        effective_hash_type = effective_hash_type.lower()
        if effective_hash_type not in SUPPORTED_HASH_ALGORITHMS:
            print(f"Error: Hash type '{effective_hash_type}' is not supported. Supported: {SUPPORTED_HASH_ALGORITHMS}", file=sys.stderr)
            sys.exit(1)

        base_dir_for_verification = os.path.abspath(args.base_dir) if args.base_dir else os.path.abspath(os.path.dirname(args.hash_file))
        print(f"Verifying files against '{args.hash_file}' (using {effective_hash_type.upper()})")
        print(f"Base directory for files: {base_dir_for_verification}\n")

        processed_count = 0; matched_count = 0; failed_count = 0; not_found_count = 0; hash_error_count = 0

        for entry in hash_entries:
            processed_count += 1
            expected_hash = entry['hash'].lower()
            # Normalize relative path from file (could have / or \), then join with base_dir
            relative_filepath_parts = entry['path'].replace('\\', '/').split('/')
            current_file_path = os.path.join(base_dir_for_verification, *relative_filepath_parts)
            current_file_path = os.path.normpath(current_file_path) # Normalize the joined path

            display_path = entry['path'] # Path as it appeared in the hash file

            if not os.path.exists(current_file_path):
                print(f"{display_path}: NOT_FOUND")
                not_found_count += 1
            elif os.path.isdir(current_file_path):
                print(f"{display_path}: IS_DIRECTORY (Skipped)")
                # Optionally, count this as a specific type of error or warning
            else:
                current_hash = calculate_file_hash(current_file_path, effective_hash_type)
                if current_hash is None:
                    print(f"{display_path}: HASH_ERROR (Could not read or hash)")
                    hash_error_count += 1
                elif current_hash.lower() == expected_hash:
                    print(f"{display_path}: OK")
                    matched_count += 1
                else:
                    print(f"{display_path}: FAILED")
                    failed_count += 1

        print("\n--- Verification Summary ---")
        print(f"Files Processed:      {processed_count}")
        print(f"Matched:              {matched_count}")
        print(f"Failed (hash mismatch): {failed_count}")
        print(f"Not Found:            {not_found_count}")
        print(f"Hash Errors (read/algo): {hash_error_count}")

        if processed_count == matched_count and processed_count > 0:
            print("\nAll files verified successfully.")
        elif matched_count > 0 and (failed_count > 0 or not_found_count > 0 or hash_error_count > 0):
            print("\nSome files failed verification or were not found.")
        elif processed_count == 0 : # Should have been caught earlier by empty hash_entries
             print("\nNo files were processed from the hash list.")
        else: # All processed files had some issue
            print("\nVerification completed with issues. See details above.")

        # Exit with non-zero status if any issues were found
        if failed_count > 0 or not_found_count > 0 or hash_error_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)
