import os
import shutil
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading

VERSION = "1.0"
AUTHOR = "Amit Singh Chauhan (with Grok's help)"

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
        self.select_all_var = tk.BooleanVar(value=False)
        
        self.setup_gui()

    def setup_gui(self):
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=5)

        tk.Label(top_frame, text="Source Folder:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        tk.Entry(top_frame, textvariable=self.selected_folder, width=40).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(top_frame, text="Browse", command=self.browse_folder).grid(row=0, column=2, padx=5, pady=5)

        tk.Button(top_frame, text="About", command=self.show_about).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        tk.Label(top_frame, text="Destination Folder:").grid(row=1, column=1, padx=5, pady=5, sticky="w")
        tk.Entry(top_frame, textvariable=self.dest_folder, width=40).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(top_frame, text="Browse", command=self.browse_dest).grid(row=1, column=2, padx=5, pady=5)

        notebook = ttk.Notebook(self.root)
        notebook.pack(pady=10, fill="both", expand=True)

        dup_frame = ttk.Frame(notebook)
        notebook.add(dup_frame, text="Duplicate Finder")
        tk.Label(dup_frame, text="Action for Duplicates:").pack(pady=5)
        ttk.Combobox(dup_frame, textvariable=self.duplicate_action, values=["Move", "Delete"]).pack()
        tk.Button(dup_frame, text="Start Duplicate Scan", command=lambda: self.start_operation("duplicates")).pack(pady=10)

        ext_frame = ttk.Frame(notebook)
        notebook.add(ext_frame, text="File Extractor")
        tk.Label(ext_frame, text="Action:").pack(pady=5)
        ttk.Combobox(ext_frame, textvariable=self.extract_action, values=["Move", "Copy"]).pack()
        tk.Label(ext_frame, text="If File Exists:").pack(pady=5)
        ttk.Combobox(ext_frame, textvariable=self.duplicate_option, values=["Rename", "Skip", "Overwrite"]).pack()
        tk.Button(ext_frame, text="Start Extraction", command=lambda: self.start_operation("extract")).pack(pady=10)

        sort_frame = ttk.Frame(notebook)
        notebook.add(sort_frame, text="File Sorter")
        tk.Label(sort_frame, text="Select Extensions:").pack(pady=5)
        tk.Checkbutton(sort_frame, text="Select All", variable=self.select_all_var, 
                       command=self.toggle_select_all).pack(pady=5)
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

        status_progress_frame = tk.Frame(self.root)
        status_progress_frame.pack(pady=5)

        self.status_label = tk.Label(status_progress_frame, text="Status: Waiting", fg="blue")
        self.status_label.pack(side="top", pady=5)

        progress_frame = tk.Frame(status_progress_frame)
        progress_frame.pack(side="top", pady=5)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100, length=400)
        self.progress_bar.pack(side="left", padx=5)
        tk.Button(progress_frame, text="Abort", fg="red", command=self.abort_operation).pack(side="left", padx=5)

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
        self.extension_vars = {ext: tk.BooleanVar(value=self.select_all_var.get()) for ext in sorted(extensions)}
        for ext, var in self.extension_vars.items():
            tk.Checkbutton(self.scrollable_frame, text=ext, variable=var).pack(anchor="w", padx=5)

    def toggle_select_all(self):
        select_all_state = self.select_all_var.get()
        for var in self.extension_vars.values():
            var.set(select_all_state)

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
        about_window = tk.Toplevel(self.root)
        about_window.title("About File Manager")
        about_window.geometry("500x400")
        about_window.resizable(True, True)

        text_frame = tk.Frame(about_window)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")

        # Increased font size to 12
        about_text_widget = tk.Text(text_frame, wrap="word", yscrollcommand=scrollbar.set, height=20, width=60, font=("TkTextFont", 12))
        about_text_widget.pack(side="left", fill="both", expand=True)

        scrollbar.config(command=about_text_widget.yview)

        about_text = (
            f"File Manager v{VERSION}\n"
            f"Author: {AUTHOR}\n\n"
            "Welcome to File Manager! This app helps you organize, clean, and manage your files easily. Here’s what it can do for you:\n\n"
            "1. Duplicate Finder:\n"
            "   - What it does: Finds duplicate files in your selected source folder by comparing their size and content (using MD5 hash).\n"
            "   - How it works: \n"
            "     - Scans all files in the source folder and its subfolders.\n"
            "     - Groups files by size, then checks their hashes to confirm duplicates.\n"
            "     - You can choose to either 'Move' duplicates to a 'Duplicates' folder in the destination folder or 'Delete' them permanently.\n"
            "   - Progress: Shows a progress bar and updates you with the file being scanned or handled.\n\n"
            "2. File Extractor:\n"
            "   - What it does: Pulls all files from subfolders in the source folder and places them directly into the destination folder.\n"
            "   - How it works:\n"
            "     - Collects every file from the source folder and its subfolders.\n"
            "     - You can 'Move' files (originals are relocated) or 'Copy' them (keeps originals in source).\n"
            "     - If a file already exists in the destination, you can:\n"
            "       - 'Rename': Adds a number (e.g., file_1.txt) to avoid overwriting.\n"
            "       - 'Skip': Ignores the duplicate file.\n"
            "       - 'Overwrite': Replaces the existing file with the new one.\n"
            "   - Progress: Updates you with the file being extracted and shows a progress bar.\n\n"
            "3. File Sorter:\n"
            "   - What it does: Organizes files from the source folder into subfolders in the destination folder based on their file extensions (e.g., .jpg, .pdf).\n"
            "   - How it works:\n"
            "     - Scans the source folder and lists all unique file extensions.\n"
            "     - You select which extensions to sort using checkboxes. Use 'Select All' to check or uncheck all extensions at once.\n"
            "     - Creates subfolders in the destination folder named after each extension (e.g., 'jpg', 'pdf').\n"
            "     - Moves files into their respective extension folders. If a file already exists, it renames it (e.g., image_1.jpg).\n"
            "   - Progress: Shows the file being sorted and a progress bar.\n\n"
            "Key Features:\n"
            "- Source and Destination Folders: You must select both a source folder (where files come from) and a destination folder (where files go) for all operations.\n"
            "- Real-Time Progress: A progress bar and status label show what’s happening at every step.\n"
            "- Abort Option: Click 'Abort' anytime to stop the current operation.\n"
            "- Error Handling: Alerts you if no files are found, no extensions are selected, or folders aren’t chosen.\n\n"
            "How to Use:\n"
            "1. Select a source folder (where your files are).\n"
            "2. Select a destination folder (where you want results).\n"
            "3. Choose an operation from the tabs: Duplicate Finder, File Extractor, or File Sorter.\n"
            "4. Set your options (e.g., Move/Delete, Rename/Skip) and click the start button.\n"
            "5. Watch the progress and stop if needed with 'Abort'.\n\n"
            "This app is designed to make file management simple and efficient. Enjoy organizing your files!"
        )
        about_text_widget.insert("1.0", about_text)
        about_text_widget.config(state="disabled")

        tk.Button(about_window, text="Close", command=about_window.destroy).pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileManagerApp(root)
    root.mainloop()