import os
import hashlib
import csv
import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext
from concurrent.futures import ThreadPoolExecutor
import threading
import collections
import piexif


class FileProcessorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("文件哈希值生成器")
        self.root.geometry("700x600")

        self.directory_to_process = ""
        self.output_file = "file_hashes.csv"
        self.total_files_processed = 0
        self.total_files_found = 0
        self.is_running = False
        self.is_paused = False
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.pause_event.set()

        self.futures = []
        self.results = collections.defaultdict(list)

        self.create_widgets()

    def create_widgets(self):
        # 路径选择框架
        path_frame = ttk.Frame(self.root, padding="10")
        path_frame.pack(fill="x")

        ttk.Label(path_frame, text="选择目录:").pack(side="left")
        self.path_entry = ttk.Entry(path_frame, width=60)
        self.path_entry.pack(side="left", padx=5, expand=True, fill="x")
        ttk.Button(path_frame, text="浏览...", command=self.select_directory).pack(side="left")

        # 进度条
        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", length=680, mode="determinate")
        self.progress_bar.pack(pady=10, padx=10)

        # 状态标签
        self.status_label = ttk.Label(self.root, text="状态: 准备就绪")
        self.status_label.pack(pady=5)

        # 进度标签
        self.progress_label = ttk.Label(self.root, text="已处理 0 / 0 个文件")
        self.progress_label.pack(pady=5)

        # 日志输出框
        self.log_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=15)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

        # 按钮框架
        button_frame = ttk.Frame(self.root, padding="10")
        button_frame.pack(fill="x")
        self.start_button = ttk.Button(button_frame, text="开始处理", command=self.start_processing)
        self.start_button.pack(side="left", expand=True, padx=5)
        self.pause_button = ttk.Button(button_frame, text="暂停", command=self.toggle_pause, state="disabled")
        self.pause_button.pack(side="left", expand=True, padx=5)
        self.stop_button = ttk.Button(button_frame, text="停止", command=self.stop_processing, state="disabled")
        self.stop_button.pack(side="left", expand=True, padx=5)
        ttk.Button(button_frame, text="清空日志", command=self.clear_log).pack(side="right", expand=True, padx=5)

    def select_directory(self):
        """打开文件对话框，让用户选择目录"""
        if self.is_running:
            self.log("程序正在运行中，请等待或停止当前任务。")
            return

        self.directory_to_process = filedialog.askdirectory()
        if self.directory_to_process:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, self.directory_to_process)
            self.log("已选择目录: " + self.directory_to_process)

    def toggle_pause(self):
        """切换暂停/恢复状态"""
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.pause_event.clear()
            self.pause_button.config(text="恢复")
            self.status_label.config(text="状态: 已暂停")
            self.log("任务已暂停。")
        else:
            self.pause_event.set()
            self.pause_button.config(text="暂停")
            self.status_label.config(text="状态: 正在处理文件...")
            self.log("任务已恢复。")

    def stop_processing(self):
        """停止处理"""
        if self.is_running:
            self.stop_event.set()
            self.pause_event.set()  # 确保暂停状态被清除
            self.log("正在停止任务...")

    def log(self, message):
        """向日志框和控制台输出信息"""
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def get_file_hashes(self, file_path):
        """计算文件的哈希值，并处理EXIF信息"""
        if self.stop_event.is_set():
            return None

        self.pause_event.wait()

        full_hash = None
        no_exif_hash = None
        file_size = 0
        block_size = 65536  # 64KB

        try:
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()

            # 1. 计算文件整体哈希值
            hash_full = hashlib.sha256()
            with open(file_path, "rb") as f:
                while True:
                    data = f.read(block_size)
                    if not data:
                        break
                    hash_full.update(data)
            full_hash = hash_full.hexdigest()

            # 2. 计算去除EXIF信息后的哈希值
            if file_ext in ['.jpg', '.jpeg']:
                hash_no_exif = hashlib.sha256()
                with open(file_path, "rb") as f:
                    f.seek(0)
                    if f.read(2) != b'\xff\xd8':
                        no_exif_hash = full_hash
                        self.log(f"警告: {file_path} 不是有效的JPEG文件，跳过EXIF处理。")
                    else:
                        hash_no_exif.update(b'\xff\xd8')
                        exif_found = False

                        while True:
                            marker = f.read(2)
                            if not marker or marker[0] != 0xff:
                                break

                            if marker == b'\xff\xe1':  # APP1 (EXIF) Marker
                                exif_len_bytes = f.read(2)
                                if len(exif_len_bytes) < 2: break
                                exif_length = int.from_bytes(exif_len_bytes, byteorder='big')
                                f.seek(exif_length - 2, 1)
                                exif_found = True
                            elif marker == b'\xff\xd9':  # EOI (End of Image) Marker
                                break
                            else:
                                seg_len_bytes = f.read(2)
                                if len(seg_len_bytes) < 2: break
                                seg_length = int.from_bytes(seg_len_bytes, byteorder='big')
                                f.seek(seg_length - 2, 1)

                        while True:
                            data = f.read(block_size)
                            if not data:
                                break
                            hash_no_exif.update(data)

                        no_exif_hash = hash_no_exif.hexdigest()
                        if not exif_found:
                            self.log(f"警告: {file_path} 没有找到EXIF信息。")

            else:
                no_exif_hash = full_hash

            return (file_path, full_hash, no_exif_hash, file_size)

        except Exception as e:
            self.log(f"错误: 处理 {file_path} 时发生异常 - {e}")
            return (file_path, "ERROR", "ERROR", file_size)

    def process_all_files(self):
        """多线程处理所有文件，并将结果写入CSV"""
        if not self.directory_to_process:
            self.log("请先选择一个目录。")
            self.is_running = False
            self.start_button.config(state="normal")
            return

        self.is_running = True
        self.stop_event.clear()
        self.pause_event.set()
        self.is_paused = False
        self.start_button.config(state="disabled")
        self.pause_button.config(state="normal", text="暂停")
        self.stop_button.config(state="normal")

        self.log("--- 新的任务开始 ---")
        self.status_label.config(text="状态: 正在遍历目录...")

        self.total_files_found = 0
        file_paths = []
        allowed_extensions = {'.jpg', '.jpeg', '.png', '.mp4'}
        for dirpath, _, filenames in os.walk(self.directory_to_process):
            for filename in filenames:
                file_ext = os.path.splitext(filename)[1].lower()
                if file_ext in allowed_extensions:
                    file_paths.append(os.path.join(dirpath, filename))
                    self.total_files_found += 1

        if not file_paths:
            self.log("指定目录中没有找到支持的文件格式。")
            self.cleanup()
            return

        self.log(f"共找到 {self.total_files_found} 个文件，开始处理...")
        self.status_label.config(text="状态: 正在处理文件...")
        self.progress_bar.config(maximum=self.total_files_found)
        self.total_files_processed = 0

        self.output_file = os.path.join(self.directory_to_process, "file_hashes.csv")
        self.log(f"结果将保存到: {self.output_file}")

        all_results = []
        with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
            self.futures = {executor.submit(self.get_file_hashes, file_path) for file_path in file_paths}

            for future in self.futures:
                if self.stop_event.is_set():
                    self.log("任务已终止。")
                    break

                try:
                    result = future.result()
                    if result:
                        all_results.append(result)
                        self.total_files_processed += 1
                        self.update_progress()
                except Exception as e:
                    self.log(f"错误: 获取结果时发生异常 - {e}")

        self.write_results_to_csv(all_results)
        self.cleanup()

    def write_results_to_csv(self, all_results):
        """将所有结果写入 CSV 文件，并找出重复文件记录"""
        from openpyxl import Workbook
        from openpyxl.utils.exceptions import InvalidFileException

        # 尝试使用 openpyxl 创建多工作表，如果失败则回退到单工作表 CSV
        try:
            wb = Workbook()
            ws_all = wb.active
            ws_all.title = "所有文件记录"
            ws_all.append(
                ['文件绝对路径', '文件整体唯一值(SHA-256)', '去除EXIF信息后的唯一值(SHA-256)', '文件大小(字节)'])

            # 记录重复文件
            duplicates_map = collections.defaultdict(list)

            for result in all_results:
                ws_all.append(result)
                file_size = result[3]
                no_exif_hash = result[2]
                if no_exif_hash != 'ERROR':
                    duplicates_map[(file_size, no_exif_hash)].append(result)

            # 寻找重复记录
            duplicate_files = [item for key, item in duplicates_map.items() if len(item) > 1]

            if duplicate_files:
                ws_duplicates = wb.create_sheet(title="重复文件记录")
                ws_duplicates.append(
                    ['文件绝对路径', '文件整体唯一值(SHA-256)', '去除EXIF信息后的唯一值(SHA-256)', '文件大小(字节)'])
                for group in duplicate_files:
                    for record in group:
                        ws_duplicates.append(record)

            # 将 .csv 扩展名改为 .xlsx
            output_xlsx_file = os.path.splitext(self.output_file)[0] + ".xlsx"
            wb.save(output_xlsx_file)
            self.log(f"结果已保存到 Excel 文件: {output_xlsx_file}")

        except ImportError:
            self.log("警告: openpyxl 库未安装，将只生成一个 CSV 文件。请运行 'pip install openpyxl' 以获得完整功能。")
            with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(
                    ['文件绝对路径', '文件整体唯一值(SHA-256)', '去除EXIF信息后的唯一值(SHA-256)', '文件大小(字节)'])
                writer.writerows(all_results)
            self.log(f"结果已保存到 CSV 文件: {self.output_file}")

        except InvalidFileException:
            self.log(f"错误: 无法保存 Excel 文件，请确保 {self.output_file} 路径有效且无写保护。")
            self.log("将回退到生成 CSV 文件。")
            with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(
                    ['文件绝对路径', '文件整体唯一值(SHA-256)', '去除EXIF信息后的唯一值(SHA-256)', '文件大小(字节)'])
                writer.writerows(all_results)
            self.log(f"结果已保存到 CSV 文件: {self.output_file}")

    def cleanup(self):
        """清理并重置状态"""
        self.is_running = False
        self.is_paused = False
        self.stop_event.clear()
        self.pause_event.set()

        self.start_button.config(state="normal")
        self.pause_button.config(state="disabled")
        self.stop_button.config(state="disabled")

        self.log(f"任务完成。已处理 {self.total_files_processed} / {self.total_files_found} 个文件。")
        self.status_label.config(text="状态: 完成")
        self.progress_bar.config(value=self.total_files_processed)
        self.progress_label.config(text=f"已处理 {self.total_files_processed} / {self.total_files_found} 个文件")

    def update_progress(self):
        """更新GUI的进度条和标签"""
        self.progress_bar['value'] = self.total_files_processed
        self.progress_label.config(text=f"已处理 {self.total_files_processed} / {self.total_files_found} 个文件")
        self.root.update_idletasks()  # 强制更新GUI

    def start_processing(self):
        """在新的线程中启动处理过程，防止GUI卡死"""
        if self.is_running:
            return

        self.total_files_processed = 0
        self.progress_bar['value'] = 0
        self.results = collections.defaultdict(list)
        threading.Thread(target=self.process_all_files, daemon=True).start()

    def clear_log(self):
        """清空日志框内容"""
        self.log_text.delete(1.0, tk.END)


if __name__ == "__main__":
    try:
        import piexif
        import openpyxl
    except ImportError as e:
        print(f"部分库未安装: {e}。为获得完整功能，请运行 'pip install piexif openpyxl'。")

    root = tk.Tk()
    app = FileProcessorApp(root)
    root.mainloop()