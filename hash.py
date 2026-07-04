# Full updated script with Hashcat (GPU) integration
import hashlib
import pickle
import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter.ttk import Combobox, Button
import os
import threading
import winsound
import time
import random
import re
import subprocess
import tempfile
import shutil

# Constants
DICTIONARY_FILE = "C:/Users/91878/wordlist.txt"
RAINBOW_TABLE_FILE = "C:/Users/91878/rainbow_table.pkl"

# Hashcat mapping for algorithms we support (only safe/known mappings)
HASHCAT_MODES = {
    "md5": "0",
    "sha1": "100",
    "sha256": "1400",
    "sha512": "1700",
    # Add more map entries if you confirm Hashcat mode numbers
}

# --- Helper: Hashing ---
def hash_password(password, hash_type):
    try:
        hash_func = getattr(hashlib, hash_type)()
        hash_func.update(password.encode())
        return hash_func.hexdigest()
    except AttributeError:
        return None

# --- Auto detect candidates (unchanged) ---
def detect_hash_candidates(hash_str):
    h = hash_str.strip()
    candidates_by_length = {
        32: ["md5"],
        40: ["sha1"],
        56: ["sha224"],
        64: ["sha256"],
        96: ["sha384"],
        128: ["sha512"]
    }
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    base64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
    candidates = []
    if hex_pattern.fullmatch(h):
        length = len(h)
        if length in candidates_by_length:
            candidates = candidates_by_length[length].copy()
        else:
            for ln, algs in candidates_by_length.items():
                if abs(length - ln) <= 2:
                    candidates.extend(algs)
    if not candidates and base64_pattern.fullmatch(h):
        candidates = ["sha256", "sha1", "md5"]
    if not candidates:
        candidates = ["md5", "sha1", "sha256", "sha512", "sha384", "sha224"]
    seen = set()
    ordered = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered

# --- Cracking functions (dictionary & rainbow) ---
def crack_with_dictionary(hash_to_crack, hash_types):
    try:
        with open(DICTIONARY_FILE, 'r', encoding='utf-8', errors='ignore') as file:
            wordlist = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        return "DICTIONARY_NOT_FOUND"

    for alg in hash_types:
        for word in wordlist:
            h = hash_password(word, alg)
            if h is None:
                continue
            if h == hash_to_crack:
                return (word, alg)
    return (None, None)

def create_rainbow_table(hash_type):
    rainbow_table = {}
    try:
        with open(DICTIONARY_FILE, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                word = line.strip()
                if not word:
                    continue
                hashed = hash_password(word, hash_type)
                if hashed:
                    rainbow_table[hashed] = word
        data = {}
        if os.path.exists(RAINBOW_TABLE_FILE):
            try:
                with open(RAINBOW_TABLE_FILE, 'rb') as f:
                    data = pickle.load(f) or {}
            except Exception:
                data = {}
        data[hash_type] = rainbow_table
        with open(RAINBOW_TABLE_FILE, 'wb') as file:
            pickle.dump(data, file)
        return True
    except Exception as e:
        return str(e)

def crack_with_rainbow_table(hash_to_crack, hash_types):
    if not os.path.exists(RAINBOW_TABLE_FILE):
        return "RAINBOW_NOT_FOUND"
    try:
        with open(RAINBOW_TABLE_FILE, 'rb') as file:
            data = pickle.load(file) or {}
    except Exception:
        return "RAINBOW_NOT_FOUND"
    for alg in hash_types:
        table = data.get(alg)
        if not table:
            continue
        if hash_to_crack in table:
            return (table[hash_to_crack], alg)
    return (None, None)

# --- Hashcat (GPU) Integration ---
def hashcat_available():
    """Return path to hashcat executable or None."""
    hc = shutil.which("hashcat")
    if hc:
        return hc
    # Windows common name
    hc_exe = shutil.which("hashcat.exe")
    return hc_exe

def run_hashcat_process(hashcat_path, mode, hashfile_path, wordlist_path, device_type="gpu", show_output_fn=None):
    """
    Run hashcat as subprocess and stream output.
    device_type: "gpu" or "cpu" (maps to --opencl-device-types)
      - "gpu" -> 2
      - "cpu" -> 1
    show_output_fn: callable to write lines to GUI console.
    Returns (exit_code, last_lines)
    """
    device_map = {"gpu": "2", "cpu": "1", "all": "3"}
    opencl_type = device_map.get(device_type, "2")
    args = [
        hashcat_path,
        "-m", mode,
        "-a", "0",            # straight (wordlist) attack
        hashfile_path,
        wordlist_path,
        "--status",
        "--status-timer", "5",
        "--opencl-device-types", opencl_type,
        "--potfile-disable"   # disable saving to potfile by default (optional)
    ]
    # You may want to remove --potfile-disable to save recovered passwords on disk
    # but for demo reasons we disable it so output is only streaming.
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        if show_output_fn:
            show_output_fn(f"[-] Failed to start Hashcat: {e}")
        return -1, str(e)

    last_lines = []
    if show_output_fn:
        show_output_fn("[*] Hashcat started, streaming output...")
    # stream lines
    try:
        for line in proc.stdout:
            if not line:
                continue
            if show_output_fn:
                show_output_fn(line.rstrip(), delay_typing=False)
            last_lines.append(line.rstrip())
            if len(last_lines) > 200:
                last_lines.pop(0)
    except Exception as e:
        if show_output_fn:
            show_output_fn(f"[-] Error reading Hashcat output: {e}")
    proc.wait()
    return proc.returncode, "\n".join(last_lines)

def gpu_crack_with_hashcat(hash_value, hash_alg_candidate, device_type="gpu", show_output_fn=None):
    """
    High-level wrapper: writes hash to temp file, runs hashcat with mapped mode,
    then parses output for a recovered password. Returns (found_plain, alg) or (None, None) or error string.
    """
    hc = hashcat_available()
    if not hc:
        return "HASHCAT_NOT_FOUND"
    mode = HASHCAT_MODES.get(hash_alg_candidate)
    if not mode:
        return f"HASHCAT_MODE_NOT_SUPPORTED_FOR_{hash_alg_candidate}"

    if not os.path.exists(DICTIONARY_FILE):
        return "DICTIONARY_NOT_FOUND"

    # write hash to temp file
    tmp_dir = tempfile.mkdtemp(prefix="hc_tmp_")
    try:
        hashfile = os.path.join(tmp_dir, "target.hash")
        with open(hashfile, "w") as f:
            f.write(hash_value + "\n")
        # run hashcat
        exit_code, last_output = run_hashcat_process(hc, mode, hashfile, DICTIONARY_FILE, device_type=device_type, show_output_fn=show_output_fn)
        # Attempt to parse recovered plain from last_output lines
        # Hashcat prints recovered lines like: "<hash>:<plaintext>" in potfile
        # We tried to disable potfile, so we must parse stdout for "Recovered" or "Recovered.*:" messages
        # As fallback, run hashcat with --show (if a potfile exists) — but we disabled potfile by default above.
        # We'll do a secondary run with --show (without --potfile-disable) if exit code is 0 or >0
        if exit_code == 0 or exit_code == 1:  # 0=found? Hashcat exit codes vary; we still parse output
            # quick parse: look for patterns like 'Recovered' and ':\t' or ' : '
            combined = last_output
            # pattern for "hash:plain"
            m = re.search(r'([0-9a-fA-F]+)\s*[:=]\s*(.+)', combined)
            if m:
                plaintext = m.group(2).strip()
                return (plaintext, hash_alg_candidate)
        # If not found in stream, try a safe --show run to check potfile (only if user allows potfile)
        # We'll attempt to run a separate --show (without --potfile-disable) to be thorough
        args_show = [hc, "-m", mode, "--show", hashfile, "--potfile-path", os.path.join(tmp_dir, "hashcat.pot")]
        try:
            proc2 = subprocess.Popen(args_show, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            out2, _ = proc2.communicate(timeout=10)
            if out2:
                # out2 lines in format: hash:plain
                m2 = re.search(r'^[0-9a-fA-F]+[:](.+)$', out2.strip(), re.MULTILINE)
                if m2:
                    plaintext = m2.group(1).strip()
                    return (plaintext, hash_alg_candidate)
        except Exception:
            pass

        return (None, None)
    finally:
        try:
            # cleanup
            if os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir)
        except Exception:
            pass

# --- GUI Setup ---
root = tk.Tk()
root.title("🕵️‍♂️ Hacker's Password Cracker (Hashcat GPU integrated)")
root.geometry("980x650")
root.resizable(False, False)
is_dark = True
root.configure(bg="#0f0f0f")

# Terminal flicker
def flicker():
    while True:
        try:
            title_frame.configure(bg=random.choice(["#000000", "#101010", "#0f0f0f"]))
        except tk.TclError:
            return
        time.sleep(0.1)
threading.Thread(target=flicker, daemon=True).start()

title_frame = tk.Frame(root, bg="#000000", height=50)
title_frame.pack(fill=tk.X)
tk.Label(title_frame, text="💻 Hacker Terminal - Password Cracker (GPU)", font=("Consolas", 16, "bold"), fg="#00FF00", bg="#000000").pack(pady=8)

form_frame = tk.Frame(root, bg="#0f0f0f")
form_frame.place(x=20, y=60)

tk.Label(form_frame, text="🔑 Hash:", fg="#00FF00", bg="#0f0f0f", font=("Consolas", 11)).grid(row=0, column=0, sticky="w", pady=5)
hash_entry = tk.Entry(form_frame, width=70, font=("Consolas", 10))
hash_entry.grid(row=0, column=1, padx=10, pady=5)

tk.Label(form_frame, text="🔧 Hash Type:", fg="#00FF00", bg="#0f0f0f", font=("Consolas", 11)).grid(row=1, column=0, sticky="w", pady=5)
hash_type_combo = Combobox(form_frame, values=["auto", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"], width=30, font=("Consolas", 10))
hash_type_combo.grid(row=1, column=1, padx=10, pady=5)
hash_type_combo.set("auto")

# Authorization checkbox (ethics)
auth_var = tk.BooleanVar(value=False)
auth_check = tk.Checkbutton(form_frame, text="I confirm I have authorization to test these hashes (required for GPU/Hashcat)", variable=auth_var, fg="#00FF00", bg="#0f0f0f", font=("Consolas", 9))
auth_check.grid(row=2, column=1, sticky="w", pady=4)

# Device type selection for Hashcat
tk.Label(form_frame, text="🔌 Hashcat Device:", fg="#00FF00", bg="#0f0f0f", font=("Consolas", 11)).grid(row=3, column=0, sticky="w", pady=5)
device_combo = Combobox(form_frame, values=["gpu", "cpu", "all"], width=30, font=("Consolas", 10))
device_combo.grid(row=3, column=1, padx=10, pady=5)
device_combo.set("gpu")

# Output console
output = scrolledtext.ScrolledText(root, width=120, height=26, font=("Consolas", 10), bg="#000000", fg="#00FF00")
output.place(x=20, y=200)

attempt_var = tk.StringVar(value="Attempts: 0")
attempt_label = tk.Label(root, textvariable=attempt_var, fg="#00FF00", bg="#0f0f0f", font=("Consolas", 11))
attempt_label.place(x=850, y=170)

countdown_var = tk.StringVar(value="Countdown: 30")
countdown_label = tk.Label(root, textvariable=countdown_var, fg="#00FF00", bg="#0f0f0f", font=("Consolas", 11))
countdown_label.place(x=700, y=170)

# Fake logs
def fake_logs():
    logs = [
        "[net] Packet sniffed on port 443",
        "[scan] Port 22 open on 192.168.1.10",
        "[auth] Login attempt from 10.0.0.5",
        "[net] DNS response intercepted",
        "[sys] CPU usage spiked during decryption",
        "[warn] Suspicious hash detected"
    ]
    while True:
        try:
            show_output(random.choice(logs))
            time.sleep(random.uniform(1, 3))
        except tk.TclError:
            return
threading.Thread(target=fake_logs, daemon=True).start()

def countdown():
    for i in range(30, -1, -1):
        try:
            countdown_var.set(f"Countdown: {i}")
            time.sleep(1)
        except tk.TclError:
            return
threading.Thread(target=countdown, daemon=True).start()

attempt_count = 0

def show_output(text, delay_typing=True):
    try:
        if delay_typing:
            for char in text + "\n":
                output.insert(tk.END, char)
                output.see(tk.END)
                output.update_idletasks()
                time.sleep(random.uniform(0.003, 0.015))
        else:
            output.insert(tk.END, text + "\n")
            output.see(tk.END)
    except tk.TclError:
        return

def play_success_sound():
    try:
        winsound.Beep(1200, 300)
    except:
        pass

def play_error_sound():
    try:
        winsound.Beep(400, 300)
    except:
        pass

# UI Helper
def _determine_candidates_from_ui(hash_val):
    selected = hash_type_combo.get().strip().lower()
    if selected == "auto" or selected == "":
        candidates = detect_hash_candidates(hash_val)
        show_output(f"[*] Auto-detected candidates (by heuristics): {', '.join(candidates)}")
        return candidates
    else:
        return [selected]

# Existing buttons' logic (dictionary and rainbow) kept largely same
def crack_dict():
    global attempt_count
    hash_val = hash_entry.get().strip()
    if not hash_val:
        messagebox.showwarning("Input needed", "Please enter a hash to crack.")
        return
    show_output("[*] Starting dictionary attack...")
    time.sleep(0.2)
    candidates = _determine_candidates_from_ui(hash_val)
    attempt_count += 1
    attempt_var.set(f"Attempts: {attempt_count}")
    result = crack_with_dictionary(hash_val, candidates)
    if result == "DICTIONARY_NOT_FOUND":
        show_output("[-] Dictionary file not found.")
        play_error_sound()
    elif result and result[0]:
        found, alg = result
        show_output(f"[+] Password found: {found}  (algorithm: {alg})")
        hash_type_combo.set(alg)
        play_success_sound()
    else:
        show_output("[-] Password not found in dictionary for candidate algorithms.")
        play_error_sound()

def rainbow_make():
    selected = hash_type_combo.get().strip().lower()
    algs_to_make = []
    if selected == "auto" or selected == "":
        algs_to_make = ["md5", "sha1", "sha256"]
        show_output("[*] Auto mode: creating rainbow tables for md5, sha1, sha256 ...", delay_typing=True)
    else:
        algs_to_make = [selected]
        show_output(f"[*] Generating rainbow table for {selected} ...", delay_typing=True)
    for alg in algs_to_make:
        res = create_rainbow_table(alg)
        if res is True:
            show_output(f"[+] Rainbow table for {alg} created successfully.")
        else:
            show_output(f"[-] Failed to create rainbow table for {alg}: {res}")
            play_error_sound()

def crack_rainbow():
    global attempt_count
    hash_val = hash_entry.get().strip()
    if not hash_val:
        messagebox.showwarning("Input needed", "Please enter a hash to crack.")
        return
    show_output("[*] Searching in rainbow table...", delay_typing=True)
    candidates = _determine_candidates_from_ui(hash_val)
    attempt_count += 1
    attempt_var.set(f"Attempts: {attempt_count}")
    result = crack_with_rainbow_table(hash_val, candidates)
    if result == "RAINBOW_NOT_FOUND":
        show_output("[-] Rainbow table database not found. Please create first.")
        play_error_sound()
    elif result and result[0]:
        found, alg = result
        show_output(f"[+] Found in rainbow table: {found}  (algorithm: {alg})")
        hash_type_combo.set(alg)
        play_success_sound()
    else:
        show_output("[-] Not found in rainbow table for candidate algorithms.")
        play_error_sound()

# New: GPU/Hashcat button handler
def crack_with_hashcat_button():
    global attempt_count
    if not auth_var.get():
        messagebox.showwarning("Authorization required", "You must confirm you have authorization to test these hashes.")
        return
    hash_val = hash_entry.get().strip()
    if not hash_val:
        messagebox.showwarning("Input needed", "Please enter a hash to crack.")
        return
    # Determine candidates
    candidates = _determine_candidates_from_ui(hash_val)
    device_type = device_combo.get().strip().lower()
    show_output(f"[*] Attempting GPU/Hashcat attack using device: {device_type}")
    attempt_count += 1
    attempt_var.set(f"Attempts: {attempt_count}")

    def worker():
        for cand in candidates:
            show_output(f"[*] Trying algorithm candidate: {cand}")
            # Only try candidates that have Hashcat mode mapping
            if cand not in HASHCAT_MODES:
                show_output(f"[-] No Hashcat mode mapping for {cand}, skipping.")
                continue
            res = gpu_crack_with_hashcat(hash_val, cand, device_type=device_type, show_output_fn=show_output)
            if isinstance(res, str):
                if res == "HASHCAT_NOT_FOUND":
                    show_output("[-] Hashcat executable not found on PATH. Please install Hashcat and ensure it's in PATH.")
                    play_error_sound()
                    return
                elif res == "DICTIONARY_NOT_FOUND":
                    show_output("[-] Dictionary file not found for Hashcat attack.")
                    play_error_sound()
                    return
                else:
                    show_output(f"[-] Hashcat error / unsupported: {res}")
                    continue
            elif res and res[0]:
                found, alg = res
                show_output(f"[+] Hashcat recovered password: {found}  (algorithm: {alg})")
                hash_type_combo.set(alg)
                play_success_sound()
                return
            else:
                show_output(f"[-] Hashcat did not recover with candidate {cand}.")
        show_output("[-] Hashcat GPU attack finished — no password recovered for candidate algorithms.")
        play_error_sound()

    threading.Thread(target=worker, daemon=True).start()

# Toggle dark/light mode
def toggle_mode():
    global is_dark
    is_dark = not is_dark
    color = "#0f0f0f" if is_dark else "#e0e0e0"
    fg = "#00FF00" if is_dark else "black"
    form_frame.configure(bg=color)
    for widget in form_frame.winfo_children():
        if isinstance(widget, tk.Label) or isinstance(widget, tk.Checkbutton):
            widget.configure(bg=color, fg=fg)
    root.configure(bg=color)
    output.configure(bg="#000000" if is_dark else "#ffffff", fg="#00FF00" if is_dark else "#000000")
    attempt_label.configure(bg=color, fg=fg)
    countdown_label.configure(bg=color, fg=fg)

# Buttons (including new GPU Hashcat button)
btn_frame = tk.Frame(root, bg="#0f0f0f")
btn_frame.place(x=20, y=140)
Button(btn_frame, text="🚀 Crack w/ Dictionary", command=lambda: threading.Thread(target=crack_dict, daemon=True).start()).grid(row=0, column=0, padx=6)
Button(btn_frame, text="⚙️ Create Rainbow Table", command=lambda: threading.Thread(target=rainbow_make, daemon=True).start()).grid(row=0, column=1, padx=6)
Button(btn_frame, text="🧠 Crack w/ Rainbow Table", command=lambda: threading.Thread(target=crack_rainbow, daemon=True).start()).grid(row=0, column=2, padx=6)
Button(btn_frame, text="🔺 GPU Crack (Hashcat)", command=lambda: threading.Thread(target=crack_with_hashcat_button, daemon=True).start()).grid(row=0, column=3, padx=6)
Button(btn_frame, text="🌗 Toggle Mode", command=toggle_mode).grid(row=0, column=4, padx=6)
Button(btn_frame, text="❌ Exit", command=root.quit).grid(row=0, column=5, padx=6)

# Startup hint about Hashcat availability
hc_path = hashcat_available()
if hc_path:
    show_output(f"[i] Hashcat found at: {hc_path}", delay_typing=False)
else:
    show_output("[i] Hashcat not found in PATH. GPU mode will not work until Hashcat is installed and added to PATH.", delay_typing=False)
    show_output("[i] To install Hashcat, visit https://hashcat.net/hashcat/ and follow their install instructions for your OS.", delay_typing=False)

root.mainloop()
