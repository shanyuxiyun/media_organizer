import hashlib
import os
import argparse
from openpyxl import Workbook
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# 全局变量
block_size = 128
wb_lock = Lock()  # 用于保护Excel写入操作的锁


def read_last_bytes(file_path: str, file_size: int, num_bytes=block_size) -> str:
    """
    读取文件末尾指定字节数并计算SHA256哈希值
    
    :param file_path: 文件路径
    :param file_size: 文件大小
    :param num_bytes: 要读取的字节数
    :return: SHA256哈希值的十六进制表示
    """
    try:
        with open(file_path, 'rb') as f:
            # 计算开始读取的位置
            # 如果文件小于 num_bytes，则从文件开头读取
            if file_size < num_bytes:
                start_position = 0
            else:
                start_position = file_size - num_bytes

            # 将文件指针移动到指定位置
            f.seek(start_position)

            # 读取剩下的所有内容
            last_bytes = f.read()

            h = hashlib.sha256()
            h.update(last_bytes)
            return h.hexdigest()
    except Exception as e:
        return f"Exception: {str(e)}"


def process_file(file_info, ws):
    """
    处理单个文件并将其信息写入工作表
    
    :param file_info: 包含文件路径和目录索引的元组
    :param ws: Excel工作表对象
    """
    file_path, dir_index = file_info
    try:
        file_size = os.path.getsize(file_path)
        hash_value = read_last_bytes(file_path, file_size)
        unique_value = hash_value + str(file_size)
        
        # 使用锁保护Excel写入操作
        with wb_lock:
            ws.append([file_path, file_size, hash_value, unique_value])
    except Exception as e:
        with wb_lock:
            ws.append([file_path, "Error", f"Error: {str(e)}", "Error"])


def process_directory(directory, base_dir, max_workers=4):
    """
    处理单个目录并将结果保存到Excel文件
    
    :param directory: 要处理的目录路径
    :param base_dir: 基础目录路径，用于保存Excel文件
    :param max_workers: 最大线程数
    """
    dir_name = os.path.basename(directory)
    print(f'Processing {dir_name}')
    
    # 创建Excel工作簿
    wb = Workbook()
    ws = wb.active
    ws.title = "Files"
    ws.append(['Path', 'Size', 'Hash', 'HashSize'])
    
    # 收集所有文件信息
    files_to_process = []
    for dirpath, dirs, filenames in os.walk(directory):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            files_to_process.append((file_path, dir_name))
    
    # 使用线程池处理文件
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_file = {
            executor.submit(process_file, file_info, ws): file_info 
            for file_info in files_to_process
        }
        
        # 处理完成的任务
        for future in as_completed(future_to_file):
            file_info = future_to_file[future]
            try:
                future.result()
            except Exception as e:
                print(f"Error processing {file_info[0]}: {str(e)}")
    
    # 保存Excel文件
    output_path = os.path.join(base_dir, f'{dir_name}.xlsx')
    wb.save(output_path)
    print(f'Saved results to {output_path}')


def main():
    """
    主函数，处理命令行参数并执行主要逻辑
    """
    parser = argparse.ArgumentParser(description='Calculate file hashes and save to Excel')
    parser.add_argument('base_directory', help='Base directory containing subdirectories to process')
    parser.add_argument('--workers', type=int, default=4, help='Number of worker threads (default: 4)')
    parser.add_argument('--block-size', type=int, default=128, help='Block size in KB (default: 128)')
    
    args = parser.parse_args()
    
    # 更新全局块大小
    global block_size
    block_size = args.block_size * 1024
    
    # 检查基础目录是否存在
    if not os.path.exists(args.base_directory):
        print(f"Error: Directory '{args.base_directory}' does not exist")
        return
    
    if not os.path.isdir(args.base_directory):
        print(f"Error: '{args.base_directory}' is not a directory")
        return
    
    # 获取所有子目录
    directories = [
        os.path.join(args.base_directory, d) 
        for d in os.listdir(args.base_directory) 
        if os.path.isdir(os.path.join(args.base_directory, d))
    ]
    
    if not directories:
        print(f"No subdirectories found in '{args.base_directory}'")
        return
    
    # 处理每个目录
    for i, directory in enumerate(directories, start=1):
        print(f'{i}/{len(directories)} processing {directory}')
        process_directory(directory, args.base_directory, args.workers)


if __name__ == "__main__":
    main()
