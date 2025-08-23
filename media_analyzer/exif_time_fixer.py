#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
EXIF时间修复工具
用于将目录中图片和视频文件的EXIF创建时间随机更新为2020-2022年之间的某个时间点
"""

import os
import random
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 设置最大并发线程数
MAX_WORKERS = 10

def generate_datetime_with_fixed_time(start_year=2020, end_year=2022):
    """
    生成指定年份范围内的随机日期和固定时间
    
    Args:
        start_year (int): 起始年份
        end_year (int): 结束年份
    
    Returns:
        str: 格式化的日期时间字符串 'YYYY:MM:DD 01:23:45'
    """
    # 生成随机年份
    year = random.randint(start_year, end_year)
    
    # 生成随机月份
    month = random.randint(1, 12)
    
    # 生成随机日期（需要考虑月份天数）
    if month in [1, 3, 5, 7, 8, 10, 12]:
        day = random.randint(1, 31)
    elif month in [4, 6, 9, 11]:
        day = random.randint(1, 30)
    else:  # 2月
        # 简单处理闰年情况
        if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
            day = random.randint(1, 29)
        else:
            day = random.randint(1, 28)
    
    # 返回带固定时间的格式化字符串
    return f"{year:04d}:{month:02d}:{day:02d} 01:23:45"


def get_supported_files(directory):
    """
    获取目录中支持的媒体文件列表
    
    Args:
        directory (str): 目录路径
    
    Returns:
        list: 支持的文件路径列表
    """
    # 支持的文件扩展名
    supported_extensions = {
        '.jpg', '.jpeg', '.png', '.tiff', '.tif', '.webp',  # 图片格式
        '.mp4', '.mov', '.avi', '.mkv', '.wmv', '.flv', '.webm'  # 视频格式
    }
    
    files = []
    directory_path = Path(directory)
    
    # 遍历目录中的所有文件
    for file_path in directory_path.rglob('*'):
        if file_path.is_file() and file_path.suffix.lower() in supported_extensions:
            files.append(str(file_path))
    
    return files


def update_exif_datetime(file_path, datetime_str):
    """
    使用exiftool更新文件的EXIF时间信息
    
    Args:
        file_path (str): 文件路径
        datetime_str (str): 日期时间字符串 'YYYY:MM:DD HH:MM:SS'
    
    Returns:
        bool: 是否成功更新
    """
    try:
        # 构建exiftool命令
        # 更新创建时间、修改时间和拍摄时间
        cmd = [
            'exiftool',
            f'-DateTimeOriginal={datetime_str}',
            f'-CreateDate={datetime_str}',
            f'-ModifyDate={datetime_str}',
            '-overwrite_original',  # 覆盖原文件
            file_path
        ]
        
        # 执行命令
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8')
        return True
    except subprocess.CalledProcessError as e:
        print(f"更新文件EXIF信息失败: {file_path}")
        print(f"错误信息: {e.stderr}")
        return False
    except FileNotFoundError:
        print("错误: 未找到exiftool命令，请确保已安装exiftool")
        return False

def process_file(file_path):
    """
    处理单个文件的函数，用于多线程
    """
    random_datetime = generate_datetime_with_fixed_time()
    print(f"处理文件: {file_path}，设置时间为: {random_datetime}")
    if update_exif_datetime(file_path, random_datetime):
        return True
    return False

def main():
    """
    主函数
    """
    # 检查命令行参数
    if len(sys.argv) != 2:
        print("使用方法: python exif_time_fixer.py <目录路径>")
        sys.exit(1)
    
    directory = sys.argv[1]
    
    # 检查目录是否存在
    if not os.path.exists(directory):
        print(f"错误: 目录 '{directory}' 不存在")
        sys.exit(1)
    
    if not os.path.isdir(directory):
        print(f"错误: '{directory}' 不是一个目录")
        sys.exit(1)
    
    # 获取支持的文件列表
    files = get_supported_files(directory)
    
    if not files:
        print(f"在目录 '{directory}' 中未找到支持的媒体文件")
        sys.exit(0)
    
    print(f"找到 {len(files)} 个支持的媒体文件，将使用最多 {MAX_WORKERS} 个线程进行处理")
    
    success_count = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交所有任务
        future_to_file = {executor.submit(process_file, file_path): file_path for file_path in files}
        
        for future in as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                if future.result():
                    success_count += 1
                    print(f"成功更新: {file_path}")
                else:
                    print(f"更新失败: {file_path}")
            except Exception as exc:
                print(f"处理文件 {file_path} 时发生错误: {exc}")

    print(f"\n处理完成! 成功更新 {success_count}/{len(files)} 个文件的EXIF时间")


if __name__ == "__main__":
    main()