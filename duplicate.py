import os
import hashlib
import shutil
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

VERSION = "1.9"
AUTHOR = "Your Name"

abort_flag = False  
last_file_processed = "None"  

def calculate_hash(file_path, chunk_size=1048576):  
    """Efficient hash calculation with abort check."""
    global abort_flag, last_file_processed
    hasher = hashlib.md5()  

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                if abort_flag:  
                    return None  
                hasher.update(chunk)
    except Exception:
        return None  

    return hasher.hexdigest()

def find_duplicate_files(folder_path, progress_var, status_label, root):
    """Fast duplicate search ensuring progress bar updates correctly."""
    global abort_flag, last_file_processed
    abort_flag = False  
    last_file_processed = "None"  

    size_dict = {}
    duplicates = []
    files_list = []

    for root_dir, _, files in os.walk(folder_path):
        for file in files:
            files_list.append(os.path.join(root_dir, file))

    total_files = len(files_list)
    if total_files == 0:
        messagebox.showinfo("No Files", "No files found in the folder.")
        return []

    progress_var.set(0)

    # First pass: group by file size
    for index, file_path in enumerate(files_list):
        if abort_flag:
            status_label.config(text=f"Aborted! Last File: {last_file_processed}")
            return []

        last_file_processed = os.path.basename(file_path)
        status_label.config(text=f"Scanning: {last_file_processed}")
        root.update_idletasks()

        try:
            file_size = os.path.getsize(file_path)
            size_dict.setdefault(file_size, []).append(file_path)
        except Exception:
            continue  
        
        progress_var.set((index + 1) / total_files * 40)  

    file_hashes = {}
    processed_files = 0
    for file_list in size_dict.values():
        if len(file_list) > 1:
            for file_path in file_list:
                if abort_flag:
                    status_label.config(text=f"Aborted! Last File: {last_file_processed}")
                    return []

                last_file_processed = os.path.basename(file_path)
                status_label.config(text=f"Processing: {last_file_processed}")
                root.update_idletasks()

                file_hash = calculate_hash(file_path)
                if file_hash:
                    if file_hash in file_hashes:
                        duplicates.append((file_path, file_hashes[file_hash]))
                    else:
                        file_hashes[file_hash] = file_path

                processed_files += 1
                progress_var.set(40 + (processed_files / total_files * 50))  

    progress_var.set(90)  # Ensure it's updated before returning
    return duplicates

def handle_duplicates(duplicates, action, progress_var, status_label, root):
    """Handle duplicate files (Delete/Move) and update UI correctly."""
    global abort_flag, last_file_processed
    if not duplicates:
        messagebox.showinfo("No Duplicates", "No duplicate files found.")
        progress_var.set(100)  # Ensure progress reaches 100%
        return

    duplicate_folder = os.path.join(selected_folder.get(), "Duplicates")
    os.makedirs(duplicate_folder, exist_ok=True)

    total_duplicates = len(duplicates)
    
    for index, (dup_file, orig_file) in enumerate(duplicates):
        if abort_flag:
            status_label.config(text=f"Aborted! Last File: {last_file_processed}")
            return

        last_file_processed = os.path.basename(dup_file)
        status_label.config(text=f"Handling: {last_file_processed}")
        root.update_idletasks()

        try:
            if action == "Delete":
                os.remove(dup_file)
            elif action == "Move":
                shutil.move(dup_file, os.path.join(duplicate_folder, os.path.basename(dup_file)))
        except Exception:
            continue  
        
        progress_var.set(90 + ((index + 1) / total_duplicates * 10))  

    progress_var.set(100)  # Ensure progress bar is full at the end
    messagebox.showinfo("Completed", f"Total Duplicates Processed: {total_duplicates}\nAction: {action}")
    status_label.config(text=f"Completed - {total_duplicates} duplicates handled")

def start_duplicate_scan(action):
    """Run file scanning in a separate thread to prevent freezing."""
    global abort_flag
    abort_flag = False  

    folder = selected_folder.get()
    if not folder:
        messagebox.showerror("Error", "Please select a folder.")
        return

    progress_var.set(0)
    status_label.config(text="Finding duplicates...")
    root.update_idletasks()

    def run_scan():
        """Thread function for scanning duplicates."""
        duplicates = find_duplicate_files(folder, progress_var, status_label, root)

        if abort_flag:
            status_label.config(text=f"Operation Aborted! Last File: {last_file_processed}")
            return

        total_duplicates = len(duplicates)
        if total_duplicates == 0:
            status_label.config(text="No duplicates found.")
            progress_var.set(100)  # Ensure progress reaches full
            return

        status_label.config(text=f"Found {total_duplicates} duplicates.")
        root.update_idletasks()

        handle_duplicates(duplicates, action, progress_var, status_label, root)

    threading.Thread(target=run_scan, daemon=True).start()

def abort_operation():
    """Abort the scanning or processing."""
    global abort_flag
    abort_flag = True
    status_label.config(text=f"Aborting... Last File: {last_file_processed}")
    progress_var.set(100)  # Mark progress as full to indicate operation ended

def browse_folder():
    """Open file dialog to select a folder."""
    folder_selected = filedialog.askdirectory()
    selected_folder.set(folder_selected)

def show_about():
    """Display an About message box."""
    about_text = (
        f"Duplicate File Finder v{VERSION}\n"
        f"Author: {AUTHOR}\n\n"
        "How it Works:\n"
        "1. Scans the folder for duplicate files.\n"
        "2. Compares files by size first, then by content (MD5 hash).\n"
        "3. Allows you to delete or move duplicates.\n"
        "4. Progress bar shows real-time status.\n"
        "5. Displays total duplicates found.\n"
        "6. 'Abort' feature now shows last file processed.\n"
        "7. Faster processing by hashing only the first 1 MB of files."
    )
    messagebox.showinfo("About", about_text)

# GUI Setup
root = tk.Tk()
root.title("Duplicate File Finder")
root.geometry("420x360")

selected_folder = tk.StringVar()
progress_var = tk.DoubleVar()

tk.Label(root, text="Select Folder:").pack(pady=5)
tk.Entry(root, textvariable=selected_folder, width=40).pack(pady=5)
tk.Button(root, text="Browse", command=browse_folder).pack(pady=5)

status_label = tk.Label(root, text="Status: Waiting", fg="blue")
status_label.pack(pady=5)

progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100, length=300)
progress_bar.pack(pady=5)

tk.Button(root, text="Delete Duplicates", command=lambda: start_duplicate_scan("Delete")).pack(pady=5)
tk.Button(root, text="Move Duplicates", command=lambda: start_duplicate_scan("Move")).pack(pady=5)
tk.Button(root, text="Abort", command=abort_operation, fg="red").pack(pady=5)
tk.Button(root, text="About", command=show_about).pack(pady=5)

root.mainloop()
