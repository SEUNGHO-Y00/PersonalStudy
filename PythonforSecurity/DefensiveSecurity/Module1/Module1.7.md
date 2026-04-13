## 1.7 File Handling

### 1.7.1 The open Built-in

### 1.7.2 Text vs Binary

### 1.7.3 Reading Patterns

### 1.7.4 Writing Patterns

### 1.7.5 File Positioning

### 1.7.6 The pathlib Module

### 1.7.7 Directory and Metadata Operations

### 1.7.8 Temporary Files and Atomic Writes

### 1.7.9 Memory-Mapped Files

### 1.7.10 Common Structured Formats

### 1.7.11 Exception Handling

### 1.7.12 Performance Guidelines

### 1.7.13 Security Checklist

### 1.7.14 Exercises

1. Chunked Copier
* Implement copy(src, dst, chunk_size=262144) that copies any size file using binary reads and writes, reporting bytes per second.

```python
import time
import shutil

def copy_chunked(src, dst, chunk_size=262144):
    """
    Copies a file using binary reads and writes in specified chunk sizes,
    reporting the transfer rate.
    """
    start_time = time.perf_counter()
    total_bytes = 0

    try:
        with open(src, 'rb') as f_src:
            with open(dst, 'wb') as f_dst:
                while True:
                    chunk = f_src.read(chunk_size)
                    if not chunk:
                        break
                    f_dst.write(chunk)
                    total_bytes += len(chunk)
    except FileNotFoundError:
        print(f"Error: Source file '{src}' not found.")
        return
    except IOError as e:
        print(f"Error during file operation: {e}")
        return

    end_time = time.perf_counter()
    duration = end_time - start_time

    if duration > 0:
        bytes_per_second = total_bytes / duration
        print(f"Copied {total_bytes} bytes in {duration:.2f} seconds.")
        print(f"Rate: {bytes_per_second / 1024 / 1024:.2f} MiB/s")
    else:
        print(f"Copied {total_bytes} bytes instantly.")

# Example Usage:
# Create a dummy source file first
with open("source.bin", "wb") as f:
    f.write(b'\x00' * 1024 * 1024 * 10) # 10 MiB dummy file

copy_chunked("source.bin", "destination.bin")

# Clean up
import os
os.remove("source.bin")
os.remove("destination.bin")
```

2. Line Reverser
* Read input.txt and create output.txt where line order is reversed but internal character order is preserved.

```python
def reverse_lines(input_path, output_path):
    """
    Reads a file and writes its lines in reverse order to a new file.
    """
    try:
        with open(input_path, 'r') as f_in:
            lines = f_in.readlines()
        
        # Reverse the list of lines
        lines.reverse()

        with open(output_path, 'w') as f_out:
            f_out.writelines(lines)
        print(f"Lines reversed successfully from '{input_path}' to '{output_path}'.")

    except IOError as e:
        print(f"Error during file operation: {e}")

# Example Usage:
# Create dummy input file
with open("input.txt", "w") as f:
    f.write("First line\n")
    f.write("Second line\n")
    f.write("Third line\n")

reverse_lines("input.txt", "output.txt")

# Verify the output (optional)
with open("output.txt", "r") as f:
    print("\nContents of output.txt:")
    print(f.read())

# Clean up
import os
os.remove("input.txt")
os.remove("output.txt")
```

3. Safe Config Writer
* Write a function save_json(path, obj) that atomically writes pretty-printed JSON by using NamedTemporaryFile and os.replace.

```python
import json
import os
import tempfile

def save_json_atomically(path, obj):
    """
    Writes a dictionary to a JSON file atomically using a temporary file.
    """
    # Use NamedTemporaryFile to get a safe, temporary location in the same directory
    with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=os.path.dirname(path) or '.') as temp_file:
        try:
            # Write all data to the temporary file
            json.dump(obj, temp_file, indent=4)
            temp_file.flush()
            os.fsync(temp_file.fileno()) # Ensure data is written to disk
        except Exception as e:
            # If anything fails, close and delete the temp file immediately
            temp_file.close()
            os.unlink(temp_file.name)
            raise IOError(f"Failed to write to temporary file: {e}")

    # If writing succeeded, safely replace the original file
    os.replace(temp_file.name, path)
    print(f"Configuration saved safely to '{path}'.")

# Example Usage:
config_data = {
    "hostname": "router-a",
    "interfaces": ["eth0", "eth1"],
    "settings": {"timeout": 30}
}
save_json_atomically("config.json", config_data)

# Verify the output (optional)
with open("config.json", "r") as f:
    print("\nContents of config.json:")
    print(f.read())

# Clean up
os.remove("config.json")
```

4. Directory Tree Size
* Using pathlib, compute total size (in bytes) of all regular files under a directory, skipping symlinks.

```python
from pathlib import Path

def get_dir_size(directory_path):
    """
    Computes the total size (in bytes) of all regular files within a directory.
    """
    path = Path(directory_path)
    if not path.is_dir():
        raise ValueError(f"Path is not a valid directory: {directory_path}")

    total_size = 0
    # Use rglob('*') for a recursive search of all items
    for item in path.rglob('*'):
        # Check if it is a file and not a symlink
        if item.is_file() and not item.is_symlink():
            total_size += item.stat().st_size
    return total_size

# Example Usage:
# Create dummy files in a temporary structure
os.makedirs("temp_dir/subdir", exist_ok=True)
with open("temp_dir/file1.txt", "w") as f: f.write("12345")
with open("temp_dir/subdir/file2.bin", "wb") as f: f.write(b'\x00' * 100)

size = get_dir_size("temp_dir")
print(f"Total size of 'temp_dir': {size} bytes") # Expected: 105 bytes

# Clean up (requires a helper to remove non-empty dir)
import shutil
shutil.rmtree("temp_dir")
```

5. CSV Aggregator
* Combine every .csv in a folder into a single combined.csv with an additional column source_file indicating origin.

```python
import csv
import os
import glob

def aggregate_csvs(folder_path, output_filename="combined.csv"):
    """
    Combines all CSV files in a folder into one, adding a source_file column.
    """
    output_path = os.path.join(folder_path, output_filename)
    all_files = glob.glob(os.path.join(folder_path, "*.csv"))
    
    if not all_files:
        print(f"No CSV files found in {folder_path}")
        return

    # Use a set to track if the header has been written to the combined file
    header_written = False
    with open(output_path, 'w', newline='') as outfile:
        writer = csv.writer(outfile)

        for filename in all_files:
            with open(filename, 'r', newline='') as infile:
                reader = csv.reader(infile)
                header = next(reader)
                
                # Write the header only once for the output file
                if not header_written:
                    writer.writerow(header + ["source_file"])
                    header_written = True

                # Write data rows, appending the source filename
                for row in reader:
                    writer.writerow(row + [os.path.basename(filename)])
    
    print(f"Aggregated {len(all_files)} files into {output_path}")

# Example Usage:
os.makedirs("csv_data", exist_ok=True)
with open("csv_data/fileA.csv", "w", newline="") as f:
    f.write("ID,Value\n1,100\n2,200\n")
with open("csv_data/fileB.csv", "w", newline="") as f:
    f.write("ID,Value\n3,300\n4,400\n")

aggregate_csvs("csv_data")

# Verify the output (optional)
with open("csv_data/combined.csv", "r") as f:
    print("\nContents of combined.csv:")
    print(f.read())

# Clean up
shutil.rmtree("csv_data")
```

6. Memory-Mapped Patch
* Open a large binary file with mmap, locate all occurrences of the byte sequence b"\x90\x90\x90\x90", and overwrite them with b"\xCC\xCC\xCC\xCC".

```python
import mmap
import os
import contextlib

def patch_binary_file_mmap(filepath, find_bytes, replace_bytes):
    """
    Locates occurrences of a byte sequence in a file using mmap and replaces them.
    """
    if len(find_bytes) != len(replace_bytes):
        print("Error: Find and replace byte sequences must be the same length.")
        return

    try:
        # Open in read/write binary mode
        with open(filepath, "r+b") as f:
            # Memory map the file
            with contextlib.closing(mmap.mmap(f.fileno(), 0)) as mm:
                print(f"Opened {filepath} with mmap. File size: {len(mm)} bytes.")
                
                offset = 0
                count = 0
                # Find the first occurrence
                offset = mm.find(find_bytes, offset)
                
                while offset != -1:
                    print(f"Found sequence at offset {offset}. Patching...")
                    # Overwrite the bytes in the mapped memory
                    mm[offset:offset + len(replace_bytes)] = replace_bytes
                    count += 1
                    # Search for the next occurrence, starting after the current patch
                    offset = mm.find(find_bytes, offset + len(replace_bytes))
                
                # mmap is automatically flushed to disk upon close by context manager
                print(f"Patching complete. Total occurrences replaced: {count}.")

    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example Usage:
# Create a dummy large binary file with sequences to find
test_file = "large_binary.bin"
with open(test_file, "wb") as f:
    f.write(b'data' + b"\x90\x90\x90\x90" + b'more_data' + b"\x90\x90\x90\x90" + b'end')

patch_binary_file_mmap(
    filepath=test_file,
    find_bytes=b"\x90\x90\x90\x90",
    replace_bytes=b"\xCC\xCC\xCC\xCC"
)

# Verify the changes (optional)
with open(test_file, "rb") as f:
    print("\nContents after patching:")
    print(f.read())

# Clean up
os.remove(test_file)
```
