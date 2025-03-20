import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading

# Global Variables
VERSION = "1.3"
AUTHOR = "Your Name"
extension_vars = {}
abort_event = threading.Event()

def scan_extensions(folder_path):
    """Scans the folder and returns a set of unique file extensions."""
    extensions = set()
    for root_dir, _, files in os.walk(folder_path):
        for file in files:
            ext = os.path.splitext(file)[-1].lower().strip(".") or "Unknown"
            extensions.add(ext)
    return sorted(extensions)

def update_extension_checkboxes(extensions):
    """Updates the GUI checkboxes with found extensions."""
    for widget in scrollable_frame.winfo_children():
        widget.destroy()
    global extension_vars
    extension_vars = {}

    select_all_checkbox = tk.Checkbutton(scrollable_frame, text="Select All", variable=select_all_var, command=toggle_all_extensions)
    select_all_checkbox.pack(anchor="w", padx=5)

    for ext in extensions:
        var = tk.BooleanVar()
        chk = tk.Checkbutton(scrollable_frame, text=ext, variable=var)
        chk.pack(anchor="w", padx=5)
        extension_vars[ext] = var

def toggle_all_extensions():
    """Toggles all extension checkboxes based on 'Select All' state."""
    state = select_all_var.get()
    for var in extension_vars.values():
        var.set(state)

def browse_folder():
    """Opens file dialog to select a folder and updates available extensions."""
    folder_selected = filedialog.askdirectory()
    if folder_selected:
        selected_folder.set(folder_selected)
        extensions = scan_extensions(folder_selected)
        update_extension_checkboxes(extensions)

def get_selected_extensions():
    """Returns a list of selected file extensions."""
    return [ext for ext, var in extension_vars.items() if var.get()]

def get_unique_filename(dest_folder, filename):
    """Ensures no file overwrites by appending a number if a duplicate exists."""
    base, ext = os.path.splitext(filename)
    counter = 1
    new_filename = filename
    while os.path.exists(os.path.join(dest_folder, new_filename)):
        new_filename = f"{base}_{counter}{ext}"
        counter += 1
    return new_filename

def start_processing(action):
    """Runs file processing in a separate thread to prevent UI freezing."""
    threading.Thread(target=process_files, args=(action,), daemon=True).start()

def process_files(action):
    """Handles Move, Copy, and Delete operations."""
    abort_event.clear()

    folder_path = selected_folder.get()
    if not folder_path:
        messagebox.showwarning("Warning", "Please select a folder first!")
        return

    selected_exts = get_selected_extensions()
    if not selected_exts:
        messagebox.showwarning("Warning", "Please select file types to process!")
        return

    dest_folder = ""
    if action in ["Move", "Copy"]:
        dest_folder = filedialog.askdirectory(title=f"Select destination folder for {action}")
        if not dest_folder:
            return

    total_files = sum(1 for root_dir, _, files in os.walk(folder_path)
                      for file in files if os.path.splitext(file)[-1].lower().strip(".") in selected_exts)

    if total_files == 0:
        messagebox.showinfo("Info", "No files found with selected extensions!")
        return

    processed_files = 0
    for root_dir, _, files in os.walk(folder_path):
        for file in files:
            if abort_event.is_set():
                root.after(100, lambda: status_label.config(text=f"Aborted at: {file}", fg="red"))
                progress_var.set(0)
                return

            file_ext = os.path.splitext(file)[-1].lower().strip(".") or "Unknown"
            if file_ext in selected_exts:
                file_path = os.path.join(root_dir, file)
                
                if action in ["Move", "Copy"]:
                    ext_folder = os.path.join(dest_folder, file_ext)  # Folder for this extension
                    os.makedirs(ext_folder, exist_ok=True)  # Create if not exists

                    unique_filename = get_unique_filename(ext_folder, file)
                    dest_path = os.path.join(ext_folder, unique_filename)
                    
                    if action == "Move":
                        shutil.move(file_path, dest_path)
                    else:
                        shutil.copy2(file_path, dest_path)

                elif action == "Delete":
                    os.remove(file_path)

            processed_files += 1
            progress_var.set((processed_files / total_files) * 100)
            root.after(100, lambda f=file: status_label.config(text=f"Processing: {f}"))

    root.after(100, lambda: status_label.config(text=f"{action} completed!", fg="green"))

def abort_operation():
    """Sets the abort flag to stop processing."""
    abort_event.set()
    root.after(100, lambda: status_label.config(text="Operation Aborted", fg="red"))
    progress_var.set(0)

def show_about():
    """Displays an About message box."""
    about_text = (
        f"File Organizer v{VERSION}\n"
        f"Author: {AUTHOR}\n\n"
        "How it Works:\n"
        "1. Scans the selected folder and subfolders.\n"
        "2. Sorts files into subfolders based on extensions.\n"
        "3. You can choose to Move, Copy, or Delete files.\n"
        "4. 'Delete' allows selecting specific file types before deleting.\n"
        "5. Shows a real-time progress bar.\n"
        "6. 'Abort' button stops the operation and shows the last processed file."
    )
    messagebox.showinfo("About", about_text)

# GUI Setup
root = tk.Tk()
root.title("File Organizer by Extension")
root.geometry("500x500")

select_all_var = tk.BooleanVar()
selected_folder = tk.StringVar()
progress_var = tk.DoubleVar()

# Folder Selection
tk.Label(root, text="Select Folder:").pack(pady=5)
tk.Entry(root, textvariable=selected_folder, width=50).pack(pady=5)
tk.Button(root, text="Browse", command=browse_folder).pack(pady=5)

# Status & Progress Bar
status_label = tk.Label(root, text="Status: Waiting", fg="blue")
status_label.pack(pady=5)
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100, length=350)
progress_bar.pack(pady=5)

# Extension Selection
tk.Label(root, text="Select Extensions to Process:").pack(pady=5)
ext_frame = tk.Frame(root)
ext_frame.pack(pady=5, fill="both", expand=False)
canvas = tk.Canvas(ext_frame, height=150)
scrollbar = tk.Scrollbar(ext_frame, orient="vertical", command=canvas.yview)
scrollable_frame = tk.Frame(canvas)
scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)
canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

# Action Buttons
button_frame1 = tk.Frame(root)
button_frame1.pack(pady=5)
tk.Button(button_frame1, text="Move Files", command=lambda: start_processing("Move")).pack(side="left", padx=5)
tk.Button(button_frame1, text="Copy Files", command=lambda: start_processing("Copy")).pack(side="left", padx=5)
tk.Button(button_frame1, text="Delete Files", command=lambda: start_processing("Delete"), fg="red").pack(side="left", padx=5)

# Abort & About Buttons
button_frame2 = tk.Frame(root)
button_frame2.pack(pady=10)
tk.Button(button_frame2, text="Abort", fg="red", width=15, command=abort_operation).pack(pady=5)
tk.Button(button_frame2, text="About", command=show_about, width=15).pack(pady=5)

root.mainloop()
