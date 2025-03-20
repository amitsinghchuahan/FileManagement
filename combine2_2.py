import os  # For file and directory operations
import shutil  # For moving and copying files
import hashlib  # For calculating file hashes (to detect duplicates)
import tkinter as tk  # GUI framework
from tkinter import filedialog, messagebox, ttk  # GUI components
import threading  # For running operations in the background

# Application version and author details
VERSION = "1.0"
AUTHOR = "Amit Singh Chauhan (with Grok's help)"

class FileManagerApp:
    """Main class for the File Manager application"""

    def __init__(self, root):
        """Initialize the application window and variables"""
        self.root = root
        self.root.title(f"File Manager v{VERSION}")
        self.root.geometry("600x600")

        # Flags and variables for operations
        self.abort_flag = False  # Flag to stop operations
        self.progress_var = tk.DoubleVar()  # Variable for progress bar
        self.selected_folder = tk.StringVar()  # Stores selected source folder
        self.dest_folder = tk.StringVar()  # Stores destination folder
        self.extension_vars = {}  # Dictionary for file extensions
        self.duplicate_action = tk.StringVar(value="Move")  # Action for duplicates
        self.extract_action = tk.StringVar(value="Move")  # Action for extraction
        self.duplicate_option = tk.StringVar(value="Rename")  # Option for duplicate handling
        self.select_all_var = tk.BooleanVar(value=False)  # Toggle select all extensions

        self.setup_gui()  # Call function to set up GUI

    def setup_gui(self):
        """Create GUI components"""
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=5)

        # Source folder selection
        tk.Label(top_frame, text="Source Folder:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        tk.Entry(top_frame, textvariable=self.selected_folder, width=40).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(top_frame, text="Browse", command=self.browse_folder).grid(row=0, column=2, padx=5, pady=5)

        # Destination folder selection
        tk.Label(top_frame, text="Destination Folder:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        tk.Entry(top_frame, textvariable=self.dest_folder, width=40).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(top_frame, text="Browse", command=self.browse_dest).grid(row=1, column=2, padx=5, pady=5)

        # Notebook (Tab layout)
        notebook = ttk.Notebook(self.root)
        notebook.pack(pady=10, fill="both", expand=True)

        # Duplicate Finder Tab
        dup_frame = ttk.Frame(notebook)
        notebook.add(dup_frame, text="Duplicate Finder")
        tk.Label(dup_frame, text="Action for Duplicates:").pack(pady=5)
        ttk.Combobox(dup_frame, textvariable=self.duplicate_action, values=["Move", "Delete"]).pack()
        tk.Button(dup_frame, text="Start Duplicate Scan", command=lambda: self.start_operation("duplicates")).pack(pady=10)

        # File Extractor Tab
        ext_frame = ttk.Frame(notebook)
        notebook.add(ext_frame, text="File Extractor")
        tk.Label(ext_frame, text="Action:").pack(pady=5)
        ttk.Combobox(ext_frame, textvariable=self.extract_action, values=["Move", "Copy"]).pack()
        tk.Label(ext_frame, text="If File Exists:").pack(pady=5)
        ttk.Combobox(ext_frame, textvariable=self.duplicate_option, values=["Rename", "Skip", "Overwrite"]).pack()
        tk.Button(ext_frame, text="Start Extraction", command=lambda: self.start_operation("extract")).pack(pady=10)

        # File Sorter Tab
        sort_frame = ttk.Frame(notebook)
        notebook.add(sort_frame, text="File Sorter")
        tk.Label(sort_frame, text="Select Extensions:").pack(pady=5)
        tk.Checkbutton(sort_frame, text="Select All", variable=self.select_all_var, 
                       command=self.toggle_select_all).pack(pady=5)
        
        # Scrollable frame for extensions
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

        # Status and Progress Bar
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
        """Open a dialog to select source folder"""
        folder = filedialog.askdirectory()
        if folder:
            self.selected_folder.set(folder)
            self.update_extensions(folder)  # Update file extensions found in the folder

    def browse_dest(self):
        """Open a dialog to select destination folder"""
        folder = filedialog.askdirectory()
        if folder and not folder.startswith(self.selected_folder.get()):
            self.dest_folder.set(folder)
        else:
            messagebox.showwarning("Warning", "Destination cannot be inside source folder!")

    def update_extensions(self, folder):
        """Scan the folder and update file extensions list"""
        extensions = set(os.path.splitext(f)[-1].lower().strip(".") or "NoExt" for r, _, f in os.walk(folder) for f in f)
        
        # Clear previous checkboxes
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        # Create checkboxes for each file extension found
        self.extension_vars = {ext: tk.BooleanVar(value=self.select_all_var.get()) for ext in sorted(extensions)}
        for ext, var in self.extension_vars.items():
            tk.Checkbutton(self.scrollable_frame, text=ext, variable=var).pack(anchor="w", padx=5)

    def toggle_select_all(self):
        """Toggle selection of all file extensions"""
        select_all_state = self.select_all_var.get()
        for var in self.extension_vars.values():
            var.set(select_all_state)

    def abort_operation(self):
        """Set the abort flag to stop ongoing operations"""
        self.abort_flag = True
        self.status_label.config(text="Operation Aborted!", fg="red")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileManagerApp(root)
    root.mainloop()
