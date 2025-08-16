import os
import hashlib
import csv
import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext
from concurrent.futures import ThreadPoolExecutor
import piexif


class FileProcessorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("文件哈希值生成器")
        self.root.geometry("600x500")

        self.directory_to_process = ""
        self.output_file = "file_hashes.csv"
        self.total_files_processed = 0
        self.total_files_found = 0

        self.create_widgets()

    def create_widgets(self):
        # 路径选择框架
        path_frame = ttk.Frame(self.root, padding="10")
        path_frame.pack(fill="x")

        ttk.Label(path_frame, text="选择目录:").pack(side="left")
        self.path_entry = ttk.Entry(path_frame, width=50)
        self.path_entry.pack(side="left", padx=5, expand=True, fill="x")
        ttk.Button(path_frame, text="浏览...", command=self.select_directory).pack(side="left")

        # 进度条
        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", length=580, mode="determinate")
        self.progress_bar.pack(pady=10)

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
        ttk.Button(button_frame, text="开始处理", command=self.start_processing).pack(side="left", expand=True)
        ttk.Button(button_frame, text="清空日志", command=self.clear_log).pack(side="right", expand=True)

    def select_directory(self):
        """打开文件对话框，让用户选择目录"""
        self.directory_to_process = filedialog.askdirectory()
        if self.directory_to_process:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, self.directory_to_process)
            self.log("已选择目录: " + self.directory_to_process)

    def log(self, message):
        """向日志框和控制台输出信息"""
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def get_file_hashes(self, file_path):
        """计算文件的哈希值，并处理EXIF信息"""
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
                    # 读取SOI (Start of Image)
                    data_soi = f.read(2)
                    if data_soi != b'\xff\xd8':
                        self.log(f"警告: {file_path} 不是有效的JPEG文件，跳过EXIF处理。")
                        no_exif_hash = full_hash
                    else:
                        # 找到第一个APP1 (EXIF) Marker
                        exif_found = False
                        data_marker = f.read(2)
                        while data_marker:
                            if data_marker == b'\xff\xe1':  # APP1 Marker
                                # 读取EXIF段长度
                                exif_len_bytes = f.read(2)
                                if len(exif_len_bytes) < 2:
                                    break
                                exif_length = int.from_bytes(exif_len_bytes, byteorder='big')
                                # 跳过整个EXIF段（长度包括2个字节的长度本身）
                                f.seek(exif_length - 2, 1)
                                exif_found = True
                                break
                            elif data_marker[0] == 0xff:
                                # 读取段长度并跳过
                                marker_len_bytes = f.read(2)
                                if len(marker_len_bytes) < 2:
                                    break
                                marker_length = int.from_bytes(marker_len_bytes, byteorder='big')
                                f.seek(marker_length - 2, 1)
                                data_marker = f.read(2)
                            else:
                                break

                        # 重新定位到SOI后，更新哈希值
                        hash_no_exif.update(data_soi)

                        # 接着从当前位置开始读取文件内容并计算哈希
                        while True:
                            data = f.read(block_size)
                            if not data:
                                break
                            hash_no_exif.update(data)

                        no_exif_hash = hash_no_exif.hexdigest()
                        if not exif_found:
                            self.log(f"警告: {file_path} 没有找到EXIF信息。")

            else:
                # 对于非JPEG文件，两个哈希值相同
                no_exif_hash = full_hash

            return (file_path, full_hash, no_exif_hash, file_size)

        except Exception as e:
            self.log(f"错误: 处理 {file_path} 时发生异常 - {e}")
            return (file_path, "ERROR", "ERROR", file_size)

    def process_all_files(self):
        """多线程处理所有文件，并将结果写入CSV"""
        if not self.directory_to_process:
            self.log("请先选择一个目录。")
            return

        self.status_label.config(text="状态: 正在遍历目录...")
        self.root.update_idletasks()

        # 获取所有符合要求的文件列表
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
            self.status_label.config(text="状态: 完成")
            return

        self.log(f"共找到 {self.total_files_found} 个文件，开始处理...")
        self.status_label.config(text="状态: 正在处理文件...")
        self.progress_bar.config(maximum=self.total_files_found)

        self.total_files_processed = 0

        # 创建并打开CSV文件
        with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(
                ['文件绝对路径', '文件整体唯一值(SHA-256)', '去除EXIF信息后的唯一值(SHA-256)', '文件大小(字节)'])

            # 使用线程池处理文件
            # 这里的max_workers可以根据您的CPU核心数进行调整，以达到最佳性能
            with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
                # 提交所有文件处理任务
                futures = {executor.submit(self.get_file_hashes, file_path) for file_path in file_paths}

                # 等待并处理结果
                for future in futures:
                    result = future.result()
                    if result:
                        writer.writerow(result)
                        self.total_files_processed += 1
                        self.update_progress()

        self.log(f"所有文件已处理完毕，结果已保存到 {self.output_file}")
        self.status_label.config(text="状态: 完成")
        self.progress_bar.config(value=self.total_files_found)
        self.progress_label.config(text=f"已处理 {self.total_files_processed} / {self.total_files_found} 个文件")

    def update_progress(self):
        """更新GUI的进度条和标签"""
        self.progress_bar['value'] = self.total_files_processed
        self.progress_label.config(text=f"已处理 {self.total_files_processed} / {self.total_files_found} 个文件")
        self.root.update_idletasks()  # 强制更新GUI

    def start_processing(self):
        """在新的线程中启动处理过程，防止GUI卡死"""
        import threading
        self.total_files_processed = 0
        self.progress_bar['value'] = 0
        threading.Thread(target=self.process_all_files, daemon=True).start()

    def clear_log(self):
        """清空日志框内容"""
        self.log_text.delete(1.0, tk.END)


if __name__ == "__main__":
    # 检查piexif库是否安装
    try:
        import piexif
    except ImportError:
        print("piexif 库未安装。请运行 'pip install piexif' 进行安装。")
        # 即使没有piexif，程序依然可以运行，只是EXIF处理部分会有警告
        # 但为确保功能完整，还是建议用户安装

    root = tk.Tk()
    app = FileProcessorApp(root)
    root.mainloop()