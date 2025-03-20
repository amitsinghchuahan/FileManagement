import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.ttk import Progressbar, Combobox

# Global flag to stop extraction
stop_extraction = False

def copy_or_move_files(source_dir, destination_dir, progress_var, progress_bar, action, duplicate_option):
    global stop_extraction
    stop_extraction = False  # Reset flag when starting
    
    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir)
    
    files = []
    
    # Collect all files from source directory and its subdirectories
    for root, _, filenames in os.walk(source_dir):
        for file_name in filenames:
            file_path = os.path.join(root, file_name)
            files.append(file_path)
    
    total_files = len(files)
    if total_files == 0:
        messagebox.showinfo("Info", "No files found to extract.")
        return
    
    for i, file_path in enumerate(files):
        if stop_extraction:
            messagebox.showinfo("Aborted", "File extraction was aborted!")
            return
        
        dest_path = os.path.join(destination_dir, os.path.basename(file_path))  # Save files directly in destination
        
        # Handle duplicate files based on user selection
        if os.path.exists(dest_path):
            if duplicate_option == "Skip":
                continue
            elif duplicate_option == "Rename":
                base, ext = os.path.splitext(dest_path)
                count = 1
                while os.path.exists(dest_path):
                    dest_path = f"{base}_{count}{ext}"
                    count += 1
            # If Overwrite, just proceed
        
        if action == "Copy":
            shutil.copy(file_path, dest_path)
        else:  # Move
            shutil.move(file_path, dest_path)
        
        progress_var.set((i + 1) / total_files * 100)
        progress_bar.update_idletasks()
    
    messagebox.showinfo("Success", f"Files {action.lower()}ed successfully!")

def browse_source():
    source_dir.set(filedialog.askdirectory())

def browse_destination():
    dest = filedialog.askdirectory()
    if dest.startswith(source_dir.get()):
        messagebox.showwarning("Warning", "Destination cannot be the same as the source or a subfolder of the source.")
    else:
        destination_dir.set(dest)

def start_extraction():
    if not source_dir.get() or not destination_dir.get():
        messagebox.showwarning("Warning", "Please select both source and destination directories.")
        return
    
    if destination_dir.get().startswith(source_dir.get()):
        messagebox.showwarning("Warning", "Destination cannot be the same as the source or a subfolder of the source.")
        return
    
    copy_or_move_files(source_dir.get(), destination_dir.get(), progress_var, progress_bar, action_var.get(), duplicate_var.get())

def abort_extraction():
    global stop_extraction
    stop_extraction = True  # Set flag to stop extraction

def show_about():
    about_text = (
        "File Extractor v2.0\n"
        "Author: Amit Singh Chauhan\n\n"
        "This software allows users to extract files from nested subfolders "
        "and place them directly into a destination folder. "
        "Users can choose to either Copy or Move files and select how to handle duplicate files:\n"
        "- Overwrite existing files\n"
        "- Rename duplicate files\n"
        "- Skip duplicate files\n\n"
        "A progress bar updates in real-time to show extraction progress.\n"
        "A notification is displayed upon task completion.\n"
        "An Abort button is available to stop the process at any time."
    )
    messagebox.showinfo("About", about_text)

# GUI Setup
root = tk.Tk()
root.title("File Extractor")
root.geometry("400x420")
root.resizable(False, False)  # Disable minimize and maximize

source_dir = tk.StringVar()
destination_dir = tk.StringVar()
progress_var = tk.DoubleVar()
action_var = tk.StringVar(value="Copy")
duplicate_var = tk.StringVar(value="Overwrite")

tk.Label(root, text="Source Directory:").pack(pady=5)
tk.Entry(root, textvariable=source_dir, width=40).pack()
tk.Button(root, text="Browse", command=browse_source).pack()

tk.Label(root, text="Destination Directory:").pack(pady=5)
tk.Entry(root, textvariable=destination_dir, width=40).pack()
tk.Button(root, text="Browse", command=browse_destination).pack()

tk.Label(root, text="Action:").pack(pady=5)
Combobox(root, textvariable=action_var, values=["Copy", "Move"]).pack()

tk.Label(root, text="If File Exists:").pack(pady=5)
Combobox(root, textvariable=duplicate_var, values=["Overwrite", "Rename", "Skip"]).pack()

tk.Button(root, text="Start Extraction", command=start_extraction).pack(pady=5)
tk.Button(root, text="Abort", command=abort_extraction).pack(pady=5)  # Added Abort button
tk.Button(root, text="About", command=show_about).pack(pady=5)

progress_bar = Progressbar(root, orient="horizontal", length=300, mode="determinate", variable=progress_var)
progress_bar.pack(pady=10)

root.mainloop()
