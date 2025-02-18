import base64
import json
import re
import time
import threading
import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# Import ttkbootstrap for modern, rounded widgets
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# External libraries for analysis
import google.generativeai as genai
from iptcinfo3 import IPTCInfo
from PIL import Image

# External libraries for metadata removal
import rawpy
import numpy as np

# Global model variable for Gemini analysis
model = None

# Global variables for Analysis (Tagging) page
analysis_input_directory = None
analysis_output_directory = None

# Global variables for Removal (Stripping) page
removal_input_directory = None
removal_output_directory = None

SYSTEM_PROMPT = """
You're the big dog of image metadata analysis, hitting it straight off the tee. 
When I feed you an image encoded in Base64, you need to look deep and yank out the IPTC metadata.

Output it as clean JSON, with these keys:

- "caption": A quick summary, like a birdie putt
- "keywords": A list of tags, like hazards to avoid
- "byline": Who took the picture, the caddie's info
- "credit": Where the props go, like the club house
- "source": Where it's from, like the tee box

Keep it all solid valid JSON, no chitchat, and avoid going into the rough (don't add any commentary or markdown).
Be sure to use golf colloquialisms whenever appropriate. And ALWAYS add a keyword describing the emotion of the humans in any image if they are present.
"""

# ---------------------------
# Functions for Image Analysis (Tagging)
# ---------------------------
def encode_image(image_path):
    """Encodes an image to Base64."""
    try:
        image_path = Path(image_path)
        if not image_path.is_file():
            raise FileNotFoundError(f"No such file: {image_path}")
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode("utf-8")
    except FileNotFoundError as e:
        log_message(f"Error: {e}")
        return None

def analyze_image(image_path, max_retries=5):
    """Analyzes the image with Gemini, using exponential backoff on failures."""
    global model
    base64_image = encode_image(image_path)
    if base64_image is None:
        return None

    prompt_parts = [
        SYSTEM_PROMPT,
        {"mime_type": "image/jpeg", "data": base64_image}
    ]

    retries = 0
    while retries <= max_retries:
        try:
            response = model.generate_content(prompt_parts)
            if not response.text:
                log_message("Error: Gemini returned an empty response.")
                return None

            json_string = response.text.strip()

            # Remove markdown code fences if present
            if json_string.startswith("```"):
                lines = json_string.splitlines()
                if lines and re.match(r'^```(?:\w+)?$', lines[0].strip()):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                json_string = "\n".join(lines).strip()

            # Remove Unicode control characters
            json_string = re.sub(r'[\x00-\x1F\x7F-\x9F\u2000-\u200D\uFEFF]', '', json_string)

            if not json_string:
                log_message("Error: String is empty after cleaning")
                return None

            try:
                json_data = json.loads(json_string)
                return json_data
            except json.JSONDecodeError as json_err:
                log_message(f"Error: JSON decode failed. Response: {response.text}")
                log_message(f"JSONDecodeError details: {json_err}")
                return None

        except Exception as e:
            error_str = str(e)
            if "429" in error_str:
                wait_time = 2 ** retries
                log_message(f"Rate limit hit for {image_path}. Retrying in {wait_time} seconds... (Attempt {retries + 1} of {max_retries})")
                time.sleep(wait_time)
                retries += 1
            else:
                log_message(f"Error generating response for {image_path}: {e}")
                return None

    log_message(f"Max retries exceeded for {image_path}.")
    return None

def write_image_metadata(image_path, output_path, metadata):
    """
    Writes metadata to the image.
    For JPEG files, it uses IPTCInfo to write IPTC metadata.
    For PNG files, it embeds the metadata as textual chunks using Pillow.
    """
    image_path_obj = Path(image_path)
    ext = image_path_obj.suffix.lower()
    
    if ext in [".jpg", ".jpeg"]:
        try:
            info = IPTCInfo(image_path, force=True)
            if metadata.get("caption"):
                info['caption/abstract'] = metadata["caption"]
            if metadata.get("keywords"):
                info['keywords'] = metadata["keywords"]
            if metadata.get("byline"):
                info['by-line'] = metadata["byline"]
            if metadata.get("credit"):
                info['credit'] = metadata["credit"]
            if metadata.get("source"):
                info['source'] = metadata["source"]
            info.save_as(output_path)
            log_message(f"Metadata written to IPTC in: {output_path}")
        except Exception as e:
            log_message(f"Error writing IPTC metadata for {image_path}: {e}")
    
    elif ext == ".png":
        try:
            from PIL import PngImagePlugin
            im = Image.open(image_path)
            pnginfo = PngImagePlugin.PngInfo()
            if metadata.get("caption"):
                pnginfo.add_text("caption", metadata["caption"])
            if metadata.get("keywords"):
                pnginfo.add_text("keywords", ", ".join(metadata["keywords"]))
            if metadata.get("byline"):
                pnginfo.add_text("byline", metadata["byline"])
            if metadata.get("credit"):
                pnginfo.add_text("credit", metadata["credit"])
            if metadata.get("source"):
                pnginfo.add_text("source", metadata["source"])
            im.save(output_path, pnginfo=pnginfo)
            log_message(f"Metadata written to PNG in: {output_path}")
        except Exception as e:
            log_message(f"Error writing PNG metadata for {image_path}: {e}")
    else:
        log_message(f"Unsupported file extension: {ext}")

def process_images():
    """Processes images for metadata analysis using the Gemini API."""
    global model, analysis_input_directory, analysis_output_directory
    api_key = analysis_api_key.get().strip()
    if not api_key:
        messagebox.showerror("Error", "Please enter a valid API key.")
        return

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
    except Exception as e:
        messagebox.showerror("Error", f"Failed to configure API: {e}")
        return

    if analysis_input_directory is None or not analysis_input_directory.is_dir():
        messagebox.showerror("Error", "Please select a valid input directory for analysis.")
        return
    if analysis_output_directory is None:
        messagebox.showerror("Error", "Please select a valid output directory for analysis.")
        return

    supported_extensions = {".jpg", ".jpeg", ".png"}
    image_files = [p for p in analysis_input_directory.iterdir() if p.suffix.lower() in supported_extensions]

    if not image_files:
        messagebox.showinfo("No Images", "No supported JPEG or PNG images found in the input directory.")
        return

    log_message(f"Found {len(image_files)} image(s) to analyze.\n")
    
    for image_path in image_files:
        log_message(f"Analyzing image: {image_path.name}")
        metadata = analyze_image(str(image_path))
        if metadata:
            log_message("Image Metadata:")
            log_message(json.dumps(metadata, indent=2))
            output_file = analysis_output_directory / image_path.name
            write_image_metadata(str(image_path), str(output_file), metadata)
        else:
            log_message(f"Skipping {image_path.name} due to missing metadata.")
        log_message("-" * 40)
    
    log_message("Image analysis complete!")
    messagebox.showinfo("Done", "Finished analyzing images.")

def start_processing():
    threading.Thread(target=process_images, daemon=True).start()

# ---------------------------
# Functions for Metadata Removal (Stripping)
# ---------------------------
def remove_metadata_image(input_path, output_path):
    """Removes metadata from an image by recreating it from pixel data."""
    try:
        with Image.open(input_path) as img:
            new_img = Image.new(img.mode, img.size)
            new_img.paste(img)
            new_img.save(output_path)
        log_message(f"Processed: {input_path} -> {output_path}")
    except Exception as e:
        log_message(f"Error processing {input_path}: {e}")

def process_raw_cr2(input_path, output_folder):
    """Converts a .cr2 RAW image to JPEG format without metadata."""
    try:
        with rawpy.imread(input_path) as raw:
            rgb_image = raw.postprocess()
        img = Image.fromarray(rgb_image)
        output_filename = os.path.splitext(os.path.basename(input_path))[0] + ".jpg"
        output_path = os.path.join(output_folder, output_filename)
        img.save(output_path, "JPEG", quality=95)
        log_message(f"Converted and saved: {input_path} -> {output_path}")
    except Exception as e:
        log_message(f"Error processing {input_path}: {e}")

def remove_metadata_images():
    """Processes images by stripping metadata (supports .cr2 conversion)."""
    global removal_input_directory, removal_output_directory
    if removal_input_directory is None or not removal_input_directory.is_dir():
        messagebox.showerror("Error", "Please select a valid input directory for removal.")
        return
    if removal_output_directory is None:
        messagebox.showerror("Error", "Please select a valid output directory for removal.")
        return

    if not os.path.exists(removal_output_directory):
        os.makedirs(removal_output_directory)
        log_message(f"Created output folder: {removal_output_directory}")

    valid_extensions = ('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.cr2')
    for filename in os.listdir(removal_input_directory):
        input_path = os.path.join(str(removal_input_directory), filename)
        if filename.lower().endswith(valid_extensions):
            if filename.lower().endswith('.cr2'):
                process_raw_cr2(input_path, str(removal_output_directory))
            else:
                output_path = os.path.join(str(removal_output_directory), filename)
                remove_metadata_image(input_path, output_path)
        else:
            log_message(f"Skipping non-image file: {filename}")

    log_message("Metadata removal complete!")
    messagebox.showinfo("Done", "Finished removing metadata.")

def start_removing_metadata():
    threading.Thread(target=remove_metadata_images, daemon=True).start()

# ---------------------------
# Modern Dashboard UI Setup using ttkbootstrap (with rounded edges)
# ---------------------------
# Define our accent color
accent = "#ff6633"

# Create the main window with a modern theme (e.g., "flatly")
root = ttk.Window(themename="flatly")
root.title("Image Metadata Utility")
root.geometry("900x600")
root.configure(bg="#ffffff")

# Define our custom accent style for buttons
style = ttk.Style()
style.theme_use("flatly")
style.configure("Accent.TButton", background=accent, foreground="white", borderwidth=0, padding=6)
# Map active state to a slightly different shade
style.map("Accent.TButton", background=[("active", "#e6734d")])

# --- Top Header with Tagline ---
top_frame = ttk.Frame(root, padding=(10, 5))
top_frame.grid(row=0, column=0, columnspan=2, sticky="ew")

title_label = ttk.Label(top_frame, text="Image Metadata Utility", font=("Helvetica", 16, "bold"), foreground="#333333")
title_label.pack(side=tk.TOP, anchor="w", padx=5)
tagline_label = ttk.Label(top_frame, text="© Solstice Solutions | all rights reserved", font=("Helvetica", 8), foreground="#666666")
tagline_label.pack(side=tk.TOP, anchor="w", padx=5)

# --- Sidebar Container with Visible Border ---
# Use a tk.Frame to allow a visible highlight border.
sidebar_container = tk.Frame(root, bg="#ffffff", highlightthickness=2, highlightbackground=accent)
sidebar_container.grid(row=1, column=0, sticky="ns", padx=(10,0), pady=10)

# Navigation panel inside the sidebar container (using ttk for buttons)
nav_frame = ttk.Frame(sidebar_container, padding=(10, 10))
nav_frame.pack(side=tk.LEFT, fill="y")

# --- Main Content Area and Response Monitor in a Vertical PanedWindow ---
paned_window = ttk.PanedWindow(root, orient="vertical")
paned_window.grid(row=1, column=1, sticky="nsew", padx=10, pady=10)
root.rowconfigure(1, weight=1)
root.columnconfigure(1, weight=1)

# Create the content frame (for Analysis/Removal pages)
content_frame = ttk.Frame(paned_window)
paned_window.add(content_frame, weight=3)

# Create the log (response monitor) frame
log_frame = ttk.Frame(paned_window)
paned_window.add(log_frame, weight=1)

# Navigation Buttons in the Sidebar
def show_analysis_frame():
    analysis_frame.tkraise()

def show_removal_frame():
    removal_frame.tkraise()

analysis_nav_btn = ttk.Button(nav_frame, text="Tagging (Analysis)", command=show_analysis_frame, style="Accent.TButton", bootstyle=("round",))
analysis_nav_btn.pack(fill="x", pady=5)
removal_nav_btn = ttk.Button(nav_frame, text="Stripping (Metadata Removal)", command=show_removal_frame, style="Accent.TButton", bootstyle=("round",))
removal_nav_btn.pack(fill="x", pady=5)

# Create two pages in content_frame for Analysis and Removal.
analysis_frame = ttk.Frame(content_frame)
removal_frame = ttk.Frame(content_frame)
for frame in (analysis_frame, removal_frame):
    frame.grid(row=0, column=0, sticky="nsew")

# ----- Analysis (Tagging) Page -----
analysis_header = ttk.Label(analysis_frame, text="Tagging (Analysis)", font=("Helvetica", 14, "bold"), foreground="#333333")
analysis_header.grid(row=0, column=0, columnspan=2, pady=(0, 10), sticky="w")

ttk.Label(analysis_frame, text="API Key:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
analysis_api_key = tk.Entry(analysis_frame, width=40, show="*")
analysis_api_key.grid(row=1, column=1, sticky="w", padx=5, pady=5)

def analysis_select_directory(which):
    global analysis_input_directory, analysis_output_directory
    selected = filedialog.askdirectory(title="Select Directory")
    if not selected:
        return
    selected_path = Path(selected)
    if which == "input":
        analysis_input_directory = selected_path
        analysis_input_label.config(text=f"Input: {analysis_input_directory}")
    else:
        analysis_output_directory = selected_path
        analysis_output_label.config(text=f"Output: {analysis_output_directory}")

analysis_input_btn = ttk.Button(analysis_frame, text="Select Input Directory", command=lambda: analysis_select_directory("input"), style="Accent.TButton", bootstyle=("round",))
analysis_input_btn.grid(row=2, column=0, sticky="w", padx=5, pady=5)
analysis_input_label = ttk.Label(analysis_frame, text="Input: Not Selected")
analysis_input_label.grid(row=2, column=1, sticky="w", padx=5, pady=5)

analysis_output_btn = ttk.Button(analysis_frame, text="Select Output Directory", command=lambda: analysis_select_directory("output"), style="Accent.TButton", bootstyle=("round",))
analysis_output_btn.grid(row=3, column=0, sticky="w", padx=5, pady=5)
analysis_output_label = ttk.Label(analysis_frame, text="Output: Not Selected")
analysis_output_label.grid(row=3, column=1, sticky="w", padx=5, pady=5)

analysis_process_btn = ttk.Button(analysis_frame, text="Analyze Images", command=start_processing, style="Accent.TButton", bootstyle=("round",))
analysis_process_btn.grid(row=4, column=0, columnspan=2, pady=15)

# ----- Removal (Stripping) Page -----
removal_header = ttk.Label(removal_frame, text="Stripping (Metadata Removal)", font=("Helvetica", 14, "bold"), foreground="#333333")
removal_header.grid(row=0, column=0, columnspan=2, pady=(0, 10), sticky="w")

def removal_select_directory(which):
    global removal_input_directory, removal_output_directory
    selected = filedialog.askdirectory(title="Select Directory")
    if not selected:
        return
    selected_path = Path(selected)
    if which == "input":
        removal_input_directory = selected_path
        removal_input_label.config(text=f"Input: {removal_input_directory}")
    else:
        removal_output_directory = selected_path
        removal_output_label.config(text=f"Output: {removal_output_directory}")

removal_input_btn = ttk.Button(removal_frame, text="Select Input Directory", command=lambda: removal_select_directory("input"), style="Accent.TButton", bootstyle=("round",))
removal_input_btn.grid(row=1, column=0, sticky="w", padx=5, pady=5)
removal_input_label = ttk.Label(removal_frame, text="Input: Not Selected")
removal_input_label.grid(row=1, column=1, sticky="w", padx=5, pady=5)

removal_output_btn = ttk.Button(removal_frame, text="Select Output Directory", command=lambda: removal_select_directory("output"), style="Accent.TButton", bootstyle=("round",))
removal_output_btn.grid(row=2, column=0, sticky="w", padx=5, pady=5)
removal_output_label = ttk.Label(removal_frame, text="Output: Not Selected")
removal_output_label.grid(row=2, column=1, sticky="w", padx=5, pady=5)

removal_process_btn = ttk.Button(removal_frame, text="Remove Metadata", command=start_removing_metadata, style="Accent.TButton", bootstyle=("round",))
removal_process_btn.grid(row=3, column=0, columnspan=2, pady=15)

# --- Response Monitor (Log) Area ---
# This log area is now a pane in the vertical PanedWindow so it can be resized by dragging.
log_text = scrolledtext.ScrolledText(log_frame, height=8, state=tk.DISABLED, background="#f7f7f7", font=("Helvetica", 10))
log_text.pack(fill="both", expand=True)

def log_message(message):
    log_text.config(state=tk.NORMAL)
    log_text.insert(tk.END, message + "\n")
    log_text.see(tk.END)
    log_text.config(state=tk.DISABLED)

analysis_frame.tkraise()
root.mainloop()

