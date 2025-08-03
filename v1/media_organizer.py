import sys
import os
import shutil
import hashlib
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from queue import Queue

from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QFileDialog, QTextEdit, QProgressBar,
    QCheckBox
)
from PyQt6.QtCore import Qt, QRunnable, QThreadPool, pyqtSignal, QObject

SUPPORTED_EXTS = {
    'image': {'.jpg', '.jpeg', '.png', '.heic', '.gif', '.bmp', '.tiff', '.webp'},
    'video': {'.mp4', '.mov', '.avi', '.mkv', '.wmv', '.flv', '.mpeg', '.mpg'}
}

def compute_sha256(path, chunk_size=4 * 1024 * 1024):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
    except Exception:
        return None
    return h.hexdigest()

def run_exiftool(exiftool_path, file_path):
    try:
        # 获取尽可能早的时间：DateTimeOriginal, CreateDate, FileModifyDate
        proc = subprocess.run(
            [exiftool_path, "-j", "-datetimeoriginal", "-createdate", "-filemodifydate", str(file_path)],
            capture_output=True, text=True, timeout=20
        )
        if proc.returncode != 0 or not proc.stdout:
            return None
        import json
        data = json.loads(proc.stdout)[0]
        # 优先顺序
        for tag in ("DateTimeOriginal", "CreateDate", "FileModifyDate"):
            if tag in data and data[tag]:
                # exiftool 的时间可能格式: 2024:05:13 12:54:19
                raw = data[tag]
                try:
                    dt = datetime.strptime(raw, "%Y:%m:%d %H:%M:%S")
                except ValueError:
                    # 可能已有时区 2024:05:13 12:54:19+00:00
                    try:
                        dt = datetime.fromisoformat(raw.replace(':', '-', 2))
                    except Exception:
                        continue
                return dt
        return None
    except Exception:
        return None

def safe_makedirs(path):
    os.makedirs(path, exist_ok=True)

class Signals(QObject):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)  # done, total
    summary = pyqtSignal(dict)
    finished = pyqtSignal()

class FileTask(QRunnable):
    def __init__(self, file_path: Path, config, shared_state, signals: Signals):
        super().__init__()
        self.file_path = file_path
        self.config = config
        self.shared = shared_state
        self.signals = signals

    def run(self):
        if self.shared['cancelled']:
            return
        with self.shared['pause_cond']:
            while self.shared['paused']:
                self.shared['pause_cond'].wait()
        # 1. 计算哈希（先缓存避免重复计算）
        sha = compute_sha256(self.file_path)
        if sha is None:
            self.signals.log.emit(f"[WARN] 无法读取文件内容计算哈希: {self.file_path}")
            # treat as unique but still process metadata
        # duplicate detection (content-based)
        is_duplicate_content = False
        with self.shared['hash_lock']:
            existing = self.shared['hashes'].get(sha)
            if sha and existing:
                is_duplicate_content = True
                self.shared['duplicates'].append(self.file_path)
            else:
                if sha:
                    self.shared['hashes'][sha] = self.file_path

        # 2. 获取时间元数据
        dt = run_exiftool(self.config['exiftool_path'], self.file_path)
        if dt is None:
            target_folder = self.config['output_root'] / 'failed_metadata'
            target_folder.mkdir(parents=True, exist_ok=True)
            dest = target_folder / self.file_path.name
            reason = "无法获取元数据"
            self._move_or_simulate(dest, reason)
            self._increment_done()
            return

        # 3. 构造目标路径
        year = dt.strftime("%Y")
        month = dt.strftime("%m")
        time_str = dt.strftime("%Y%m%d_%H%M%S")
        ext = self.file_path.suffix.lower()
        base_name = f"{time_str}{ext}"
        dir_path = self.config['output_root'] / year / month
        with self.shared['targetname_lock']:
            safe_makedirs(dir_path)
        dest = dir_path / base_name

        # 4. 冲突与重复处理
        if is_duplicate_content:
            # 内容重复：移动到 duplicates 内容重复目录
            target_folder = self.config['output_root'] / 'duplicates'
            safe_makedirs(target_folder)
            dest = target_folder / self.file_path.name
            # 如果已经存在同内容又同名，加后缀
            dest = self._resolve_name_conflict(dest)
            self._move_or_simulate(dest, "内容重复")
            self._increment_done()
            return

        # 同名判断
        if dest.exists():
            same = False
            if sha:
                # 比较内容
                existing_sha = compute_sha256(dest)
                if existing_sha == sha:
                    same = True
            if same:
                target_folder = self.config['output_root'] / 'duplicates'
                safe_makedirs(target_folder)
                dest = target_folder / dest.name
                dest = self._resolve_name_conflict(dest)
                self._move_or_simulate(dest, "同名且内容相同（归入重复）")
            else:
                # same name but different content -> 加后缀序号
                base = dest.stem
                idx = 1
                while True:
                    newname = f"{base}_{idx}{ext}"
                    candidate = dest.with_name(newname)
                    if not candidate.exists():
                        dest = candidate
                        break
                    idx += 1
                self._move_or_simulate(dest, "同名不同内容，加后缀")
        else:
            self._move_or_simulate(dest, "正常移动/重命名")

        self._increment_done()

    def _resolve_name_conflict(self, dest: Path):
        if not dest.exists():
            return dest
        base = dest.stem
        ext = dest.suffix
        idx = 1
        while True:
            newname = f"{base}_{idx}{ext}"
            candidate = dest.with_name(newname)
            if not candidate.exists():
                return candidate
            idx += 1

    def _move_or_simulate(self, dest: Path, reason: str):
        if self.config['dry_run']:
            self.signals.log.emit(f"[DRY-RUN] {reason}: {self.file_path} -> {dest}")
        else:
            try:
                safe_makedirs(dest.parent)
                shutil.move(str(self.file_path), str(dest))
                self.signals.log.emit(f"[OK] {reason}: {self.file_path} -> {dest}")
                with self.shared['moved_lock']:
                    self.shared['moved_count'] += 1
            except Exception as e:
                self.signals.log.emit(f"[ERROR] 移动失败 {self.file_path} -> {dest}: {e}")

    def _increment_done(self):
        with self.shared['done_lock']:
            self.shared['done'] += 1
        self.signals.progress.emit(self.shared['done'], self.shared['total'])

class Controller:
    def __init__(self, config, signals: Signals):
        self.config = config
        self.signals = signals
        self.threadpool = QThreadPool()
        self.shared = {
            'hashes': {},  # sha -> first seen path
            'hash_lock': threading.Lock(),
            'targetname_lock': threading.Lock(),
            'done_lock': threading.Lock(),
            'moved_lock': threading.Lock(),
            'duplicates': [],
            'done': 0,
            'total': 0,
            'moved_count': 0,
            'cancelled': False,
            'paused': False,
            'pause_cond': threading.Condition(),
        }

    def start(self):
        start_time = time.time()
        all_files = list(self._gather_files())
        self.shared['total'] = len(all_files)
        self.signals.log.emit(f"[INFO] 发现文件总数: {len(all_files)}")
        for f in all_files:
            if self.shared['cancelled']:
                break
            task = FileTask(f, self.config, self.shared, self.signals)
            self.threadpool.start(task)
        # 等待完成
        self.threadpool.waitForDone()
        duration = time.time() - start_time
        summary = {
            'total_files': self.shared['total'],
            'moved': self.shared['moved_count'],
            'duplicates': len(self.shared['duplicates']),
            'duration_sec': int(duration)
        }
        # 清理空目录（非 dry-run）
        if not self.config['dry_run']:
            self._cleanup_empty_dirs(self.config['input_root'])
        self.signals.summary.emit(summary)
        self.signals.finished.emit()

    def _gather_files(self):
        for root, dirs, files in os.walk(self.config['input_root']):
            for name in files:
                path = Path(root) / name
                if path.suffix.lower() in set().union(*SUPPORTED_EXTS.values()):
                    yield path

    def _cleanup_empty_dirs(self, path: Path):
        for root, dirs, files in os.walk(path, topdown=False):
            if not dirs and not files:
                try:
                    os.rmdir(root)
                    self.signals.log.emit(f"[CLEANUP] 删除空目录: {root}")
                except Exception:
                    pass

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("家庭照片/视频整理器")
        self.resize(900, 600)
        self._build_ui()
        self.controller = None
        self.signals = Signals()
        self._connect_signals()
        self._start_time = None

    def _build_ui(self):
        layout = QVBoxLayout()

        # Inputs
        form_layout = QHBoxLayout()
        self.input_dir = QLineEdit()
        btn_input = QPushButton("选择输入目录")
        btn_input.clicked.connect(self.select_input)
        self.output_dir = QLineEdit()
        btn_output = QPushButton("选择输出目录")
        btn_output.clicked.connect(self.select_output)
        self.exiftool_path = QLineEdit("exiftool")  # 默认系统路径
        btn_exif = QPushButton("exiftool 可执行文件")
        btn_exif.clicked.connect(self.select_exiftool)

        form_layout.addWidget(QLabel("输入目录:"))
        form_layout.addWidget(self.input_dir)
        form_layout.addWidget(btn_input)
        form_layout.addWidget(QLabel("输出目录:"))
        form_layout.addWidget(self.output_dir)
        form_layout.addWidget(btn_output)
        form_layout.addWidget(QLabel("ExifTool:"))
        form_layout.addWidget(self.exiftool_path)
        form_layout.addWidget(btn_exif)
        layout.addLayout(form_layout)

        # Options
        opts = QHBoxLayout()
        self.dry_run_cb = QCheckBox("Dry-run（模拟执行）")
        opts.addWidget(self.dry_run_cb)
        layout.addLayout(opts)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        self.progress_label = QLabel("进度: 0/0")
        layout.addWidget(self.progress_label)

        # Control buttons
        ctrl_layout = QHBoxLayout()
        self.start_btn = QPushButton("开始")
        self.pause_btn = QPushButton("暂停")
        self.cancel_btn = QPushButton("取消")
        self.start_btn.clicked.connect(self.start)
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.cancel_btn.clicked.connect(self.cancel)
        ctrl_layout.addWidget(self.start_btn)
        ctrl_layout.addWidget(self.pause_btn)
        ctrl_layout.addWidget(self.cancel_btn)
        layout.addLayout(ctrl_layout)

        # Log
        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        layout.addWidget(self.log_widget)

        # Summary
        self.summary_label = QLabel("摘要将在完成后显示")
        layout.addWidget(self.summary_label)

        self.setLayout(layout)

    def _connect_signals(self):
        self.signals.log.connect(self.append_log)
        self.signals.progress.connect(self.update_progress)
        self.signals.summary.connect(self.show_summary)
        self.signals.finished.connect(lambda: self.append_log("[完成] 所有任务处理完毕"))

    def select_input(self):
        path = QFileDialog.getExistingDirectory(self, "选择输入目录")
        if path:
            self.input_dir.setText(path)

    def select_output(self):
        path = QFileDialog.getExistingDirectory(self, "选择输出目录")
        if path:
            self.output_dir.setText(path)

    def select_exiftool(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择 exiftool 可执行文件")
        if path:
            self.exiftool_path.setText(path)

    def append_log(self, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_widget.append(f"[{ts}] {text}")

    def update_progress(self, done, total):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(done)
        self.progress_label.setText(f"进度: {done}/{total}")
        # 估计剩余时间
        if self._start_time:
            elapsed = time.time() - self._start_time
            rate = done / elapsed if elapsed > 0 else 0
            remaining = (total - done) / rate if rate > 0 else float('inf')
            self.progress_label.setText(f"进度: {done}/{total} | 已用: {int(elapsed)}s 剩余: {int(remaining)}s")

    def start(self):
        if not self.input_dir.text() or not self.output_dir.text():
            self.append_log("[ERROR] 请选择输入和输出目录")
            return
        input_root = Path(self.input_dir.text())
        output_root = Path(self.output_dir.text())
        exiftool_path = self.exiftool_path.text().strip()
        if not input_root.exists() or not input_root.is_dir():
            self.append_log("[ERROR] 输入目录无效")
            return
        if not output_root.exists():
            try:
                output_root.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.append_log(f"[ERROR] 创建输出目录失败: {e}")
                return
        config = {
            'input_root': input_root,
            'output_root': output_root,
            'exiftool_path': exiftool_path,
            'dry_run': self.dry_run_cb.isChecked()
        }
        self.controller = Controller(config, self.signals)
        self._start_time = time.time()
        threading.Thread(target=self.controller.start, daemon=True).start()
        self.append_log("[INFO] 处理开始")

    def toggle_pause(self):
        if not self.controller:
            return
        with self.controller.shared['pause_cond']:
            self.controller.shared['paused'] = not self.controller.shared['paused']
            if not self.controller.shared['paused']:
                self.controller.shared['pause_cond'].notify_all()
        state = "恢复" if not self.controller.shared['paused'] else "暂停"
        self.append_log(f"[INFO] {state} 处理")

    def cancel(self):
        if not self.controller:
            return
        self.controller.shared['cancelled'] = True
        with self.controller.shared['pause_cond']:
            self.controller.shared['paused'] = False
            self.controller.shared['pause_cond'].notify_all()
        self.append_log("[INFO] 已请求取消，正在等待当前任务安全结束...")

    def show_summary(self, summary: dict):
        text = (
            f"总文件: {summary['total_files']}，"
            f"移动/处理: {summary['moved']}，"
            f"内容重复文件数: {summary['duplicates']}，"
            f"总耗时: {summary['duration_sec']} 秒"
        )
        self.summary_label.setText(text)
        self.append_log("[SUMMARY] " + text)

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
