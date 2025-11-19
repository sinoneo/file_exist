import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import hashlib
import threading
import time

class FileExist:
    def __init__(self, root):
        self.root = root
        self.root.title("20251119-文件存在检查工具，检查原目录下的文件是否在新目录下存在")
        self.root.geometry("800x600")
        
        # 存储目录路径
        self.source_dir = tk.StringVar()
        self.target_dir = tk.StringVar()
        
        # 进度变量
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar()
        
        # 创建界面
        self.create_widgets()
        
    def create_widgets(self):
        # 原目录选择
        source_frame = tk.Frame(self.root)
        source_frame.pack(pady=10, padx=20, fill=tk.X)
        
        tk.Label(source_frame, text="原目录:").pack(anchor=tk.W)
        source_path_frame = tk.Frame(source_frame)
        source_path_frame.pack(fill=tk.X, pady=5)
        tk.Entry(source_path_frame, textvariable=self.source_dir, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(source_path_frame, text="选择", command=self.select_source_dir).pack(side=tk.RIGHT)
        
        # 新目录选择
        target_frame = tk.Frame(self.root)
        target_frame.pack(pady=10, padx=20, fill=tk.X)
        
        tk.Label(target_frame, text="新目录:").pack(anchor=tk.W)
        target_path_frame = tk.Frame(target_frame)
        target_path_frame.pack(fill=tk.X, pady=5)
        tk.Entry(target_path_frame, textvariable=self.target_dir, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(target_path_frame, text="选择", command=self.select_target_dir).pack(side=tk.RIGHT)
        
        # 检查按钮
        check_frame = tk.Frame(self.root)
        check_frame.pack(pady=20)
        tk.Button(check_frame, text="开始检查", command=self.start_check_sync, bg="lightblue", font=("Arial", 12)).pack()
        
        # 进度条
        progress_frame = tk.Frame(self.root)
        progress_frame.pack(pady=10, padx=20, fill=tk.X)
        
        tk.Label(progress_frame, text="进度:").pack(anchor=tk.W)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # 状态标签
        self.status_label = tk.Label(progress_frame, textvariable=self.status_var)
        self.status_label.pack(anchor=tk.W)
        
        # 结果显示区域
        result_frame = tk.Frame(self.root)
        result_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)
        
        tk.Label(result_frame, text="检查结果:").pack(anchor=tk.W)
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
    def select_source_dir(self):
        dir_path = filedialog.askdirectory(title="选择原目录")
        if dir_path:
            self.source_dir.set(dir_path)
            
    def select_target_dir(self):
        dir_path = filedialog.askdirectory(title="选择新目录")
        if dir_path:
            self.target_dir.set(dir_path)
    
    def calculate_file_hash(self, file_path):
        """计算文件的MD5哈希值"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                # 分块读取文件，避免大文件占用过多内存
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return None
    
    def get_file_info(self, file_path):
        """获取文件的大小、创建时间、修改时间"""
        try:
            stat = os.stat(file_path)
            size = stat.st_size
            ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_ctime))
            mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
            return size, ctime, mtime
        except Exception:
            return 0, "未知", "未知"
    
    def update_progress(self, current, total, phase=""):
        """更新进度条"""
        if total > 0:
            progress = (current / total) * 100
            self.progress_var.set(progress)
            self.status_var.set(f"{phase} - {current}/{total} ({progress:.1f}%)")
            self.root.update_idletasks()  # 刷新界面
    
    def check_sync(self):
        """执行检查的主函数"""
        source = self.source_dir.get()
        target = self.target_dir.get()
        
        if not source or not target:
            messagebox.showwarning("警告", "请选择原目录和新目录")
            self.progress_var.set(0)
            self.status_var.set("")
            return
        
        # 获取原目录中所有文件
        source_files = []  # 存储 (相对路径, 文件完整路径) 的列表
        for root, dirs, files in os.walk(source):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, source)
                source_files.append((rel_path, file_path))
        
        # 计算原目录文件哈希值和文件信息
        self.status_var.set("正在计算原目录文件哈希值和信息...")
        self.root.update_idletasks()
        source_files_with_info = {}
        for i, (rel_path, file_path) in enumerate(source_files):
            file_hash = self.calculate_file_hash(file_path)
            file_size, file_ctime, file_mtime = self.get_file_info(file_path)
            if file_hash:
                source_files_with_info[os.path.basename(file_path)] = (rel_path, file_path, file_hash, file_size, file_ctime, file_mtime)
            self.update_progress(i + 1, len(source_files), "计算原目录信息")
        
        # 获取新目录中所有文件
        self.status_var.set("正在获取新目录文件列表...")
        self.root.update_idletasks()
        target_files = []  # 存储 (文件名, 文件完整路径) 的列表
        for root, dirs, files in os.walk(target):
            for file in files:
                file_path = os.path.join(root, file)
                target_files.append((file, file_path))
        
        # 计算新目录文件哈希值和文件信息
        self.status_var.set("正在计算新目录文件哈希值和信息...")
        self.root.update_idletasks()
        target_files_with_info = {}  # {文件名: [(完整路径, 哈希值, 大小, 创建时间, 修改时间), ...]}
        for i, (filename, file_path) in enumerate(target_files):
            file_hash = self.calculate_file_hash(file_path)
            file_size, file_ctime, file_mtime = self.get_file_info(file_path)
            if file_hash:
                if filename not in target_files_with_info:
                    target_files_with_info[filename] = []
                target_files_with_info[filename].append((file_path, file_hash, file_size, file_ctime, file_mtime))
            self.update_progress(i + 1, len(target_files), "计算新目录信息")
        
        # 检查原目录中的文件是否都在新目录中存在且内容相同
        self.status_var.set("正在对比文件...")
        self.root.update_idletasks()
        
        missing_files = []
        different_content_files = []
        
        for i, (filename, (rel_path, file_path, source_hash, source_size, source_ctime, source_mtime)) in enumerate(source_files_with_info.items()):
            if filename not in target_files_with_info:
                # 文件名不存在
                missing_files.append(rel_path)
            else:
                # 文件名存在，检查内容是否相同
                found = False
                for target_path, target_hash, target_size, target_ctime, target_mtime in target_files_with_info[filename]:
                    if source_hash == target_hash:
                        found = True
                        break
                if not found:
                    # 文件名存在但内容不同
                    # 找到所有同名文件的信息
                    target_infos = [(path, hash_val, size, ctime, mtime) 
                                   for path, hash_val, size, ctime, mtime in target_files_with_info[filename]]
                    different_content_files.append((
                        rel_path, file_path, source_hash, source_size, source_ctime, source_mtime, target_infos
                    ))
            self.update_progress(i + 1, len(source_files_with_info), "对比文件")
        
        # 显示结果
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        
        if missing_files:
            self.result_text.insert(tk.END, f"发现 {len(missing_files)} 个文件在新目录中不存在:\n\n")
            for file_path in missing_files:
                self.result_text.insert(tk.END, f"缺失: {file_path}\n")
            self.result_text.insert(tk.END, "\n")
        
        if different_content_files:
            self.result_text.insert(tk.END, f"发现 {len(different_content_files)} 个文件内容不同:\n\n")
            for rel_path, file_path, source_hash, source_size, source_ctime, source_mtime, target_infos in different_content_files:
                self.result_text.insert(tk.END, f"内容不同:\n")
                self.result_text.insert(tk.END, f"  原目录: {rel_path}\n")
                self.result_text.insert(tk.END, f"    MD5: {source_hash}\n")
                self.result_text.insert(tk.END, f"    大小: {source_size} bytes\n")
                self.result_text.insert(tk.END, f"    创建时间: {source_ctime}\n")
                self.result_text.insert(tk.END, f"    修改时间: {source_mtime}\n")
                
                for target_path, target_hash, target_size, target_ctime, target_mtime in target_infos:
                    self.result_text.insert(tk.END, f"  新目录: {os.path.relpath(target_path, self.target_dir.get())}\n")
                    self.result_text.insert(tk.END, f"    MD5: {target_hash}\n")
                    self.result_text.insert(tk.END, f"    大小: {target_size} bytes\n")
                    self.result_text.insert(tk.END, f"    创建时间: {target_ctime}\n")
                    self.result_text.insert(tk.END, f"    修改时间: {target_mtime}\n")
                self.result_text.insert(tk.END, "\n")
        
        if not missing_files and not different_content_files:
            self.result_text.insert(tk.END, "所有文件都已存在于新目录中且内容相同！")
            
        self.result_text.config(state=tk.DISABLED)
        self.progress_var.set(100)
        self.status_var.set("完成")
    
    def start_check_sync(self):
        """启动检查线程"""
        self.progress_var.set(0)
        self.status_var.set("开始检查...")
        # 在新线程中执行检查，避免界面冻结
        thread = threading.Thread(target=self.check_sync)
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileExist(root)
    root.mainloop()



