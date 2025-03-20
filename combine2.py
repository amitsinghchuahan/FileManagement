import os
import shutil
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading

VERSION = "2.0"
AUTHOR = "Amit Singh Chauhan "

class FileManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"File Manager v{VERSION}")
        self.root.geometry("600x600")
        
        self.abort_flag = False
        self.progress_var = tk.DoubleVar()
        self.selected_folder = tk.StringVar()
        self.dest_folder = tk.StringVar()
        self.extension_vars = {}
        self.duplicate_action = tk.StringVar(value="Move")
        self.extract_action = tk.StringVar(value="Move")
        self.duplicate_option = tk.StringVar(value="Rename")
        
        self.setup_gui()

    def setup_gui(self):
        tk.Label(self.root, text="Source Folder:").pack(pady=5)
        tk.Entry(self.root, textvariable=self.selected_folder, width=50).pack()
        tk.Button(self.root, text="Browse", command=self.browse_folder).pack(pady=5)

        tk.Label(self.root, text="Destination Folder:").pack(pady=5)
        tk.Entry(self.root, textvariable=self.dest_folder, width=50).pack()
        tk.Button(self.root, text="Browse", command=self.browse_dest).pack(pady=5)

        notebook = ttk.Notebook(self.root)
        notebook.pack(pady=10, fill="both", expand=True)

        # Duplicate Tab
        dup_frame = ttk.Frame(notebook)
        notebook.add(dup_frame, text="Duplicate Finder")
        tk.Label(dup_frame, text="Action for Duplicates:").pack(pady=5)
        ttk.Combobox(dup_frame, textvariable=self.duplicate_action, values=["Move", "Delete"]).pack()
        tk.Button(dup_frame, text="Start Duplicate Scan", command=lambda: self.start_operation("duplicates")).pack(pady=10)

        # Extract Tab
        ext_frame = ttk.Frame(notebook)
        notebook.add(ext_frame, text="File Extractor")
        tk.Label(ext_frame, text="Action:").pack(pady=5)
        ttk.Combobox(ext_frame, textvariable=self.extract_action, values=["Move", "Copy"]).pack()
        tk.Label(ext_frame, text="If File Exists:").pack(pady=5)
        ttk.Combobox(ext_frame, textvariable=self.duplicate_option, values=["Rename", "Skip", "Overwrite"]).pack()
        tk.Button(ext_frame, text="Start Extraction", command=lambda: self.start_operation("extract")).pack(pady=10)

        # Sort Tab
        sort_frame = ttk.Frame(notebook)
        notebook.add(sort_frame, text="File Sorter")
        tk.Label(sort_frame, text="Select Extensions:").pack(pady=5)
        self.ext_frame = ttk.Frame(sort_frame)
        self.ext_frame.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(self.ext_frame, height=150)
        self.scrollbar = tk.Scrollbar(self.ext_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas)
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        tk.Button(sort_frame, text="Sort Files", command=lambda: self.start_operation("sort")).pack(pady=10)

        self.status_label = tk.Label(self.root, text="Status: Waiting", fg="blue")
        self.status_label.pack(pady=5)
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100, length=400)
        self.progress_bar.pack(pady=5)
        tk.Button(self.root, text="Abort", fg="red", command=self.abort_operation).pack(pady=5)
        tk.Button(self.root, text="About", command=self.show_about).pack(pady=5)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.selected_folder.set(folder)
            self.update_extensions(folder)

    def browse_dest(self):
        folder = filedialog.askdirectory()
        if folder and not folder.startswith(self.selected_folder.get()):
            self.dest_folder.set(folder)
        else:
            messagebox.showwarning("Warning", "Destination cannot be inside source folder!")

    def update_extensions(self, folder):
        extensions = set(os.path.splitext(f)[-1].lower().strip(".") or "NoExt" for r, _, f in os.walk(folder) for f in f)
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.extension_vars = {ext: tk.BooleanVar() for ext in sorted(extensions)}
        for ext, var in self.extension_vars.items():
            tk.Checkbutton(self.scrollable_frame, text=ext, variable=var).pack(anchor="w", padx=5)

    def calculate_hash(self, file_path):
        hasher = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(1048576):
                    if self.abort_flag:
                        return None
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None

    def start_operation(self, operation):
        if not self.selected_folder.get():
            messagebox.showerror("Error", "Select a source folder!")
            return
        if not self.dest_folder.get():
            messagebox.showerror("Error", "Select a destination folder!")
            return
        self.abort_flag = False
        self.progress_var.set(0)
        self.status_label.config(text=f"Starting {operation}...")
        threading.Thread(target=self.process_operation, args=(operation,), daemon=True).start()

    def process_operation(self, operation):
        if operation == "duplicates":
            self.handle_duplicates()
        elif operation == "extract":
            self.extract_files()
        elif operation == "sort":
            self.sort_by_extension()

    def handle_duplicates(self):
        folder = self.selected_folder.get()
        dest = self.dest_folder.get()
        size_dict = {}
        duplicates = []
        files_list = [os.path.join(r, f) for r, _, fs in os.walk(folder) for f in fs]
        total_files = len(files_list)

        if not total_files:
            messagebox.showinfo("Info", "No files found!")
            self.progress_var.set(100)
            return

        for i, file_path in enumerate(files_list):
            if self.abort_flag:
                self.status_label.config(text="Aborted!")
                self.progress_var.set(100)
                return
            self.status_label.config(text=f"Scanning: {os.path.basename(file_path)}")
            self.root.update_idletasks()
            try:
                size = os.path.getsize(file_path)
                size_dict.setdefault(size, []).append(file_path)
            except:
                continue
            self.progress_var.set((i + 1) / total_files * 40)

        file_hashes = {}
        processed = 0
        for file_list in size_dict.values():
            if len(file_list) > 1:
                for file_path in file_list:
                    if self.abort_flag:
                        self.status_label.config(text="Aborted!")
                        self.progress_var.set(100)
                        return
                    self.status_label.config(text=f"Hashing: {os.path.basename(file_path)}")
                    self.root.update_idletasks()
                    hash_val = self.calculate_hash(file_path)
                    if hash_val:
                        if hash_val in file_hashes:
                            duplicates.append((file_path, file_hashes[hash_val]))
                        else:
                            file_hashes[hash_val] = file_path
                    processed += 1
                    self.progress_var.set(40 + (processed / total_files * 50))

        dup_folder = os.path.join(dest, "Duplicates")
        os.makedirs(dup_folder, exist_ok=True)
        for i, (dup, orig) in enumerate(duplicates):
            if self.abort_flag:
                self.status_label.config(text="Aborted!")
                self.progress_var.set(100)
                return
            self.status_label.config(text=f"Handling: {os.path.basename(dup)}")
            self.root.update_idletasks()
            try:
                if self.duplicate_action.get() == "Delete":
                    os.remove(dup)
                else:
                    shutil.move(dup, os.path.join(dup_folder, os.path.basename(dup)))
            except:
                continue
            self.progress_var.set(90 + (i + 1) / len(duplicates) * 10)

        self.progress_var.set(100)
        self.status_label.config(text=f"Processed {len(duplicates)} duplicates!")

    def extract_files(self):
        src = self.selected_folder.get()
        dest = self.dest_folder.get()
        files = [os.path.join(r, f) for r, _, fs in os.walk(src) for f in fs]
        total_files = len(files)

        if not total_files:
            messagebox.showinfo("Info", "No files found!")
            self.progress_var.set(100)
            return

        for i, file_path in enumerate(files):
            if self.abort_flag:
                self.status_label.config(text="Aborted!")
                self.progress_var.set(100)
                return
            dest_path = os.path.join(dest, os.path.basename(file_path))
            self.status_label.config(text=f"Extracting: {os.path.basename(file_path)}")
            self.root.update_idletasks()

            if os.path.exists(dest_path):
                if self.duplicate_option.get() == "Skip":
                    continue
                elif self.duplicate_option.get() == "Rename":
                    base, ext = os.path.splitext(dest_path)
                    count = 1
                    while os.path.exists(dest_path):
                        dest_path = f"{base}_{count}{ext}"
                        count += 1

            try:
                if self.extract_action.get() == "Move":
                    shutil.move(file_path, dest_path)
                else:
                    shutil.copy(file_path, dest_path)
            except:
                continue
            self.progress_var.set((i + 1) / total_files * 100)

        self.progress_var.set(100)
        self.status_label.config(text="Extraction complete!")

    def sort_by_extension(self):
        src = self.selected_folder.get()
        dest = self.dest_folder.get()
        selected_exts = [ext for ext, var in self.extension_vars.items() if var.get()]
        if not selected_exts:
            messagebox.showwarning("Warning", "Select at least one extension!")
            self.progress_var.set(100)
            return

        files = [os.path.join(r, f) for r, _, fs in os.walk(src) for f in fs 
                 if os.path.splitext(f)[-1].lower().strip(".") in selected_exts or ("NoExt" in selected_exts and not os.path.splitext(f)[-1])]
        total_files = len(files)

        if not total_files:
            messagebox.showinfo("Info", "No files found with selected extensions!")
            self.progress_var.set(100)
            return

        for i, file_path in enumerate(files):
            if self.abort_flag:
                self.status_label.config(text="Aborted!")
                self.progress_var.set(100)
                return
            ext = os.path.splitext(file_path)[-1].lower().strip(".") or "NoExt"
            ext_folder = os.path.join(dest, ext)
            os.makedirs(ext_folder, exist_ok=True)
            dest_path = os.path.join(ext_folder, os.path.basename(file_path))

            if os.path.exists(dest_path):
                base, ext = os.path.splitext(dest_path)
                count = 1
                while os.path.exists(dest_path):
                    dest_path = f"{base}_{count}{ext}"
                    count += 1

            try:
                shutil.move(file_path, dest_path)
            except:
                continue
            self.status_label.config(text=f"Sorting: {os.path.basename(file_path)}")
            self.root.update_idletasks()
            self.progress_var.set((i + 1) / total_files * 100)

        self.progress_var.set(100)
        self.status_label.config(text="Sorting complete!")

    def abort_operation(self):
        self.abort_flag = True
        self.status_label.config(text="Aborting...")
        self.progress_var.set(100)

    def show_about(self):
        about_text = (
            f"File Manager v{VERSION}\n"
            f"Author: {AUTHOR}\n\n"
            "Features:\n"
            "- Find & Handle Duplicates (Move/Delete)\n"
            "- Extract Files from Subfolders (Copy/Move)\n"
            "- Sort Files by Extension\n"
            "- Real-time progress with abort option\n"
            "- Handles duplicates with Rename/Skip/Overwrite options\n"
            "- Destination folder compulsory for all operations"
        )
        messagebox.showinfo("About", about_text)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileManagerApp(root)
    root.mainloop()