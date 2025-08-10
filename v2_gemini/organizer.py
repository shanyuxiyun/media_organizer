import os
import subprocess
import threading
import hashlib
import time
import re
from datetime import datetime
from dataclasses import dataclass
import shutil
from queue import Queue

@dataclass
class FileEntry:
    path: str
    hash: str
    datetime: str | None

class PhotoOrganizer:
    def __init__(self, input_dir, output_dir, exiftool_path, logger, progress_callback=None, dry_run=False):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.exiftool_path = exiftool_path
        self.logger = logger
        self.progress_callback = progress_callback
        self.dry_run = dry_run
        self.file_queue = Queue()
        self.file_list = []
        self.processed_files = 0
        self.file_data = {}
        self.duplicate_files = []
        self.processed_file_entries = [] # New list to store FileEntry objects
        self.moved_files = 0
        self.processed_moves_count = 0
        self.no_exif_files = 0
        self.source_file_types = {}
        self.dest_file_types = {}
        self.lock = threading.Lock()
        self.pause_event = threading.Event()
        self.cancel_event = threading.Event()

    def analyze_files(self):
        self.logger("Starting file analysis...")
        self._discover_files()
        self.logger(f"Found {len(self.file_list)} files to analyze.")
        self._start_analysis_workers()

    def _discover_files(self):
        for root, _, files in os.walk(self.input_dir):
            for file in files:
                file_path = os.path.join(root, file)
                self.file_list.append(file_path)
                self.file_queue.put(file_path)
                ext = os.path.splitext(file)[1].lower()
                with self.lock:
                    self.source_file_types[ext] = self.source_file_types.get(ext, 0) + 1

    def _start_analysis_workers(self):
        num_threads = os.cpu_count() or 4
        self.logger(f"Starting {num_threads} analysis worker threads.")
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=self._analysis_worker, daemon=True)
            thread.start()
            threads.append(thread)

        self.file_queue.join()
        self.logger("File analysis complete.")
        # self.logger(f"Found {len(self.duplicate_files)} duplicate files.") # This will be calculated in process_files
        self.process_files()

    def process_files(self):
        self.logger("Starting file processing...")
        duplicates_dir = os.path.join(self.output_dir, "duplicates")
        no_exif_dir = os.path.join(self.output_dir, "no_exif")
        if not self.dry_run:
            os.makedirs(duplicates_dir, exist_ok=True)
            os.makedirs(no_exif_dir, exist_ok=True)

        processed_hashes = set()
        self.duplicate_files = [] # Reset for accurate count

        for entry in self.processed_file_entries:
            if entry.hash in processed_hashes:
                # This is a duplicate of a file we've already processed as unique
                self._move_file_to_duplicates(entry.path, duplicates_dir)
                self.duplicate_files.append(entry.path) # Keep track of all duplicates
            else:
                # This is the first time we see this hash, treat as unique
                processed_hashes.add(entry.hash)
                if entry.datetime:
                    self._process_file_with_exif(entry.path, entry.datetime, entry.hash)
                else:
                    self._move_file_to_no_exif(entry.path, no_exif_dir)

        self.logger(f"Found {len(self.duplicate_files)} duplicate files.") # Log after processing

        if not self.dry_run:
            self._remove_empty_dirs()

        self.logger("File processing complete.")

    def _remove_empty_dirs(self):
        self.logger("Removing empty directories from the source...")
        for dirpath, _, _ in os.walk(self.input_dir, topdown=False):
            if not os.listdir(dirpath):
                try:
                    os.rmdir(dirpath)
                    self.logger(f"Removed empty directory: {dirpath}")
                except OSError as e:
                    self.logger(f"Error removing directory {dirpath}: {e}")

    def _process_file_with_exif(self, file_path, date_time_str, file_hash):
        try:
            dt_object = datetime.strptime(date_time_str, '%Y:%m:%d %H:%M:%S')
            dest_dir = os.path.join(self.output_dir, dt_object.strftime('%Y'), dt_object.strftime('%m'))
            new_filename = dt_object.strftime('%Y%m%d_%H%M%S') + os.path.splitext(file_path)[1]
            dest_path = os.path.join(dest_dir, new_filename)

            if not self.dry_run:
                os.makedirs(dest_dir, exist_ok=True)
                if os.path.exists(dest_path):
                    existing_file_hash = self._calculate_hash(dest_path)
                    self.logger(f"  -> Conflict: Comparing hash of '{os.path.basename(file_path)}' ({file_hash}) with existing '{os.path.basename(dest_path)}' ({existing_file_hash})")
                    if existing_file_hash == file_hash:
                        duplicates_dir = os.path.join(self.output_dir, "duplicates")
                        self._move_file_to_duplicates(file_path, duplicates_dir)
                        return
                    else:
                        count = 1
                        base, ext = os.path.splitext(new_filename)
                        while os.path.exists(dest_path):
                            dest_path = os.path.join(dest_dir, f"{base}_{count}{ext}")
                            count += 1
                shutil.move(file_path, dest_path)
            
            self.logger(f"Moved: {os.path.basename(file_path)} -> {os.path.relpath(dest_path, self.output_dir)}")
            with self.lock:
                self.moved_files += 1
                self.processed_moves_count += 1
                ext = os.path.splitext(dest_path)[1].lower()
                self.dest_file_types[ext] = self.dest_file_types.get(ext, 0) + 1
                if self.progress_callback:
                    self.progress_callback(self.processed_moves_count, len(self.processed_file_entries), phase="move")

        except Exception as e:
            self.logger(f"Error processing {file_path} with exif: {e}")

    def _move_file_to_no_exif(self, file_path, no_exif_dir):
        dest_path = os.path.join(no_exif_dir, os.path.basename(file_path))
        if not self.dry_run:
            shutil.move(file_path, dest_path)
        self.logger(f"Moved (no EXIF): {os.path.basename(file_path)} -> no_exif/{os.path.basename(file_path)}")
        with self.lock:
            self.no_exif_files += 1
            self.processed_moves_count += 1
            ext = os.path.splitext(file_path)[1].lower()
            self.dest_file_types[ext] = self.dest_file_types.get(ext, 0) + 1
            if self.progress_callback:
                self.progress_callback(self.processed_moves_count, len(self.processed_file_entries), phase="move")

    def _move_file_to_duplicates(self, file_path, duplicates_dir):
        dest_path = os.path.join(duplicates_dir, os.path.basename(file_path))
        if not self.dry_run:
            count = 1
            while os.path.exists(dest_path):
                base, ext = os.path.splitext(os.path.basename(file_path))
                dest_path = os.path.join(duplicates_dir, f"{base}_{count}{ext}")
                count += 1
            shutil.move(file_path, dest_path)
        self.logger(f"Moved (duplicate): {os.path.basename(file_path)} -> duplicates/{os.path.basename(dest_path)}")
        with self.lock:
            self.processed_moves_count += 1
            ext = os.path.splitext(file_path)[1].lower()
            self.dest_file_types[ext] = self.dest_file_types.get(ext, 0) + 1
            if self.progress_callback:
                self.progress_callback(self.processed_moves_count, len(self.processed_file_entries), phase="move")

    def get_statistics(self):
        return {
            "total_files": len(self.file_list),
            "processed_files": self.processed_files,
            "moved_files": self.moved_files,
            "duplicate_files": len(self.duplicate_files),
            "no_exif_files": self.no_exif_files,
            "source_file_types": self.source_file_types,
            "dest_file_types": self.dest_file_types
        }

    def _analysis_worker(self):
        while True:
            if self.cancel_event.is_set():
                break

            if self.pause_event.is_set():
                time.sleep(0.1)
                continue

            try:
                file_path = self.file_queue.get(timeout=0.1)
            except queue.Empty:
                with self.lock:
                    if self.processed_files == len(self.file_list):
                        break # All files processed, worker can exit
                time.sleep(0.1) # Wait a bit before checking again
                continue

            try:
                self._process_file(file_path)
            finally:
                self.file_queue.task_done()

    def _process_file(self, file_path):
        try:
            self.logger(f"Analyzing: {os.path.basename(file_path)}")
            file_hash = self._calculate_hash(file_path)

            date_time = self._get_exif_datetime(file_path)
            if not date_time:
                date_time = self._get_datetime_from_filename(file_path)
                if date_time:
                    self.logger(f"  -> Found DateTime from filename: {date_time}")

            with self.lock:
                self.processed_file_entries.append(FileEntry(path=file_path, hash=file_hash, datetime=date_time))
                if date_time:
                    self.logger(f"  -> Found DateTime: {date_time}")
                else:
                    self.logger(f"  -> DateTime not found.")

        except Exception as e:
            self.logger(f"Error processing {file_path}: {e}")
        finally:
            with self.lock:
                self.processed_files += 1
            if self.progress_callback:
                self.progress_callback(self.processed_files, len(self.file_list))

    def _get_datetime_from_filename(self, file_path):
        filename = os.path.basename(file_path)
        patterns = [
            (re.compile(r'(?:IMG|VID|PANO)_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})(?:\(\d+\))?'), 'groups'),
            (re.compile(r'(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})(?:\(\d+\))?'), 'groups'),
            (re.compile(r'Screenshot_(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})(?:\(\d+\))?'), 'groups'),
            (re.compile(r'WIN_(\d{4})(\d{2})(\d{2})_(\d{2})_(\d{2})_(\d{2})(?:\(\d+\))?'), 'groups'),
            (re.compile(r'(?:mmexport|video_|wx_camera_)(\d{10,13})'), 'ts'),
        ]

        for pattern, p_type in patterns:
            match = pattern.search(filename)
            if not match:
                continue

            try:
                if p_type == 'groups':
                    y, m, d, H, M, S = (int(g) for g in match.groups())
                    dt = datetime(y, m, d, H, M, S)
                    return dt.strftime('%Y:%m:%d %H:%M:%S')
                
                elif p_type == 'ts':
                    ts_str = match.group(1)
                    ts = int(ts_str)
                    if len(ts_str) == 13:
                        ts /= 1000
                    
                    if not (0 <= ts < 32503680000): # Sanity check for valid timestamp range
                        continue

                    dt = datetime.fromtimestamp(ts)
                    return dt.strftime('%Y:%m:%d %H:%M:%S')

            except (ValueError, TypeError, OSError):
                self.logger(f"  -> Found a date-like pattern in '{filename}' but it was invalid.")
                continue
                
        return None

    def _calculate_hash(self, file_path):
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _get_exif_datetime(self, file_path):
        try:
            exiftool_cmd = self.exiftool_path if self.exiftool_path else 'exiftool'
            preferred_tags = ['DateTimeOriginal', 'CreateDate', 'CreationDate', 'TrackCreateDate', 'MediaCreateDate']
            cmd = [exiftool_cmd]
            for tag in preferred_tags:
                cmd.append(f'-{tag}')
            cmd.append("-s3")
            cmd.append(file_path)

            result = subprocess.run(cmd, capture_output=True, text=True, check=False, creationflags=subprocess.CREATE_NO_WINDOW)

            if result.returncode not in [0, 1]:
                self.logger(f"Exiftool error for {os.path.basename(file_path)}: {result.stderr}")
                return None

            output_lines = result.stdout.strip().split('\n')
            if output_lines and output_lines[0]:
                date_str = output_lines[0]
                if date_str.startswith('0000:00:00'):
                    return None
                if len(date_str) >= 19:
                    return date_str[:19].replace("-", ":")
            return None

        except FileNotFoundError:
            self.logger(f"Error: '{exiftool_cmd}' not found. Please specify the full path or add it to your system's PATH.")
            self.cancel_event.set()
            return None
        except Exception as e:
            self.logger(f"Error getting EXIF for {os.path.basename(file_path)}: {e}")
            return None