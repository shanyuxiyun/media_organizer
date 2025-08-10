import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
from organizer import PhotoOrganizer

class PhotoOrganizerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Photo Organizer")
        self.geometry("800x600")
        self.organizer = None

        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Input/Output Configuration ---
        config_frame = ttk.LabelFrame(main_frame, text="Configuration")
        config_frame.pack(fill=tk.X, padx=5, pady=5)

        # Input Directory
        ttk.Label(config_frame, text="Input Directory:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.input_dir_var = tk.StringVar()
        input_dir_entry = ttk.Entry(config_frame, textvariable=self.input_dir_var, width=60)
        input_dir_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(config_frame, text="Browse...", command=self.browse_input_dir).grid(row=0, column=2, padx=5, pady=5)

        # Output Directory
        ttk.Label(config_frame, text="Output Directory:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.output_dir_var = tk.StringVar()
        output_dir_entry = ttk.Entry(config_frame, textvariable=self.output_dir_var, width=60)
        output_dir_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(config_frame, text="Browse...", command=self.browse_output_dir).grid(row=1, column=2, padx=5, pady=5)

        # Exiftool Path
        ttk.Label(config_frame, text="Exiftool Path:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.exiftool_path_var = tk.StringVar()
        exiftool_path_entry = ttk.Entry(config_frame, textvariable=self.exiftool_path_var, width=60)
        exiftool_path_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(config_frame, text="Browse...", command=self.browse_exiftool).grid(row=2, column=2, padx=5, pady=5)
        
        config_frame.columnconfigure(1, weight=1)

        # --- Controls ---
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        self.dry_run_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(control_frame, text="Dry Run", variable=self.dry_run_var).pack(side=tk.LEFT, padx=5)
        
        self.start_button = ttk.Button(control_frame, text="Start", command=self.start_organization)
        self.start_button.pack(side=tk.RIGHT, padx=5)
        self.pause_button = ttk.Button(control_frame, text="Pause", state=tk.DISABLED, command=self.toggle_pause)
        self.pause_button.pack(side=tk.RIGHT, padx=5)
        self.cancel_button = ttk.Button(control_frame, text="Cancel", state=tk.DISABLED, command=self.cancel_organization)
        self.cancel_button.pack(side=tk.RIGHT, padx=5)


        # --- Progress and Logging ---
        progress_frame = ttk.LabelFrame(main_frame, text="Progress")
        progress_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.log_text = tk.Text(progress_frame, height=15, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.tag_configure("summary", font=("TkDefaultFont", 10, "bold"))

        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=100, mode="determinate")
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)
        
        # --- Status Bar ---
        status_bar = ttk.Frame(self)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = ttk.Label(status_bar, text="Ready", anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, padx=5)


    def browse_input_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.input_dir_var.set(os.path.abspath(directory))

    def browse_output_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.output_dir_var.set(os.path.abspath(directory))

    def browse_exiftool(self):
        filepath = filedialog.askopenfilename(
            title="Select Exiftool Executable",
            filetypes=(("Executable files", "*.exe"), ("All files", "*.*"))
        )
        if filepath:
            self.exiftool_path_var.set(os.path.abspath(filepath))

    def start_organization(self):
        input_dir = self.input_dir_var.get()
        output_dir = self.output_dir_var.get()
        exiftool_path = self.exiftool_path_var.get()

        if not os.path.isdir(input_dir):
            messagebox.showerror("Error", "Invalid Input Directory.")
            return
        if not os.path.isdir(output_dir):
            messagebox.showerror("Error", "Invalid Output Directory.")
            return
        if exiftool_path and not os.path.isfile(exiftool_path):
            messagebox.showerror("Error", "Invalid Exiftool Path. If left empty, exiftool must be in the system PATH.")
            return
            
        self.log("Starting organization...")
        self.status_label.config(text="Processing...")
        self.start_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.NORMAL)
        self.cancel_button.config(state=tk.NORMAL)

        self.organizer = PhotoOrganizer(
            input_dir=input_dir,
            output_dir=output_dir,
            exiftool_path=exiftool_path,
            logger=self.log,
            progress_callback=self.update_progress,
            dry_run=self.dry_run_var.get()
        )
        
        self.analysis_thread = threading.Thread(target=self.organizer.analyze_files, daemon=True)
        self.analysis_thread.start()
        self.monitor_thread = threading.Thread(target=self.monitor_organization, daemon=True)
        self.monitor_thread.start()

    def toggle_pause(self):
        if self.organizer:
            if self.organizer.pause_event.is_set():
                self.organizer.pause_event.clear()
                self.log("Resumed.")
                self.pause_button.config(text="Pause")
            else:
                self.organizer.pause_event.set()
                self.log("Paused.")
                self.pause_button.config(text="Resume")

    def cancel_organization(self):
        if self.organizer:
            self.organizer.cancel_event.set()
            self.log("Cancelling...")

    def monitor_organization(self):
        self.analysis_thread.join()
        if not self.organizer.cancel_event.is_set():
            stats = self.organizer.get_statistics()
            self.log_summary("\n--- Organization Complete! ---")
            self.log_summary(f"Total Files Analyzed: {stats['total_files']}")
            self.log_summary(f"Files Moved/Renamed: {stats['moved_files']}")
            self.log_summary(f"Duplicate Files Found: {stats['duplicate_files']}")
            self.log_summary(f"Files without EXIF Data: {stats['no_exif_files']}")
            self.log_summary("\n--- Source File Types ---")
            for ext, count in stats['source_file_types'].items():
                self.log_summary(f"  {ext}: {count}")
            self.log_summary("\n--- Destination File Types ---")
            for ext, count in stats['dest_file_types'].items():
                self.log_summary(f"  {ext}: {count}")
            self.log_summary("---------------------------------")
        else:
            self.log("Organization cancelled.")
        
        self.start_button.config(state=tk.NORMAL)
        self.pause_button.config(state=tk.DISABLED)
        self.cancel_button.config(state=tk.DISABLED)

    def log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def log_summary(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n", "summary")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def update_progress(self, current, total):
        self.progress_bar["value"] = current
        self.progress_bar["maximum"] = total
        self.status_label.config(text=f"Processing... {current}/{total}")
        if current == total:
            self.status_label.config(text="Done!")


if __name__ == "__main__":
    app = PhotoOrganizerApp()
    app.mainloop()
