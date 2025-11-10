"""
Caesar Security Tool
Author: Noor Hafsa
Purpose: Internship Task (Caesar cipher) + educational security features to demonstrate
weaknesses, defensive controls, and a secure alternative.

Features:
- Encrypt / Decrypt (Caesar)
- Brute-force demo (shows all 25 shifts)
- File support (read/write)
- Simple suspicious-content detector (phishing-like URL patterns & dangerous keywords)
- Basic rate-limiter for brute-force attempts (educational)
- Logging of operations (local logfile)
- Secure alternative demo using cryptography.Fernet (optional)
"""

import re
import time
import logging
from collections import deque

# Optional: install cryptography for the secure example
try:
    from cryptography.fernet import Fernet
    HAS_FERNET = True
except Exception:
    HAS_FERNET = False

LOGFILE = "caesar_security_tool.log"
logging.basicConfig(filename=LOGFILE, level=logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s")

# ----- Caesar functions -----
def encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    logging.info("Encrypt operation: shift=%s text_len=%d", shift, len(text))
    return result

def decrypt(text, shift):
    return encrypt(text, -shift)

# ----- Brute force (educational) -----
def brute_force(text):
    results = []
    for i in range(1, 26):
        results.append((i, decrypt(text, i)))
    logging.info("Brute force run on text_len=%d", len(text))
    return results

# ----- File helpers -----
def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        data = f.read()
    logging.info("Read file: %s size=%d", path, len(data))
    return data

def write_file(path, data):
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    logging.info("Wrote file: %s size=%d", path, len(data))

# ----- Simple suspicious-content detector -----
URL_REGEX = re.compile(
    r"(?:(?:https?|ftp):\/\/)?(?:[\w-]+\.)+[a-zA-Z]{2,}(?:\/\S*)?"
)
PHISHING_KEYWORDS = [
    "verify", "account", "password", "login", "confirm", "bank", "urgent",
    "click here", "update", "reset", "suspend", "secure"
]

def detect_suspicious(text):
    findings = {"urls": [], "keywords": []}
    # find URLs
    for m in URL_REGEX.finditer(text):
        findings["urls"].append(m.group(0))
    # find keywords (case-insensitive)
    low = text.lower()
    for kw in PHISHING_KEYWORDS:
        if kw in low:
            findings["keywords"].append(kw)
    logging.info("Suspicion scan: urls=%d keywords=%d",
                 len(findings["urls"]), len(findings["keywords"]))
    return findings

# ----- Rate limiter (naive) -----
class RateLimiter:
    def __init__(self, max_attempts=5, window_seconds=60):
        self.attempts = deque()
        self.max_attempts = max_attempts
        self.window = window_seconds

    def allow(self):
        now = time.time()
        while self.attempts and now - self.attempts[0] > self.window:
            self.attempts.popleft()
        if len(self.attempts) >= self.max_attempts:
            return False
        self.attempts.append(now)
        return True

# ----- Secure example (Fernet) -----
def fernet_demo(plain_text):
    if not HAS_FERNET:
        return None, "cryptography not installed"
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(plain_text.encode())
    recovered = f.decrypt(token).decode()
    logging.info("Fernet demo: data_len=%d", len(plain_text))
    return {"key": key.decode(), "token": token.decode(), "recovered": recovered}, None

# ----- Simple CLI -----
def run_cli():
    limiter = RateLimiter(max_attempts=8, window_seconds=60)  # educational values
    print("🔐 Caesar Security Tool — Demo + Defensive Features")
    menu = """
1) Encrypt text (console)
2) Decrypt text (console)
3) Brute-force a ciphertext (console)  <-- educational
4) Scan text for suspicious content (phishing detector)
5) File: encrypt -> write file
6) File: decrypt -> write file
7) Secure demo (Fernet) [optional]
8) Exit
"""
    print(menu)
    while True:
        choice = input("Choice: ").strip()
        if choice == "1":
            txt = input("Enter message: ")
            shift = int(input("Shift (integer): "))
            print("Encrypted:", encrypt(txt, shift))
        elif choice == "2":
            txt = input("Enter ciphertext: ")
            shift = int(input("Shift (integer): "))
            print("Decrypted:", decrypt(txt, shift))
        elif choice == "3":
            if not limiter.allow():
                print("Rate limit reached. Wait a bit. (Educational control)")
                continue
            txt = input("Enter ciphertext to brute-force: ")
            results = brute_force(txt)
            for i, out in results:
                print(f"Shift {i:02}: {out}")
            print("\n(You just saw how trivial brute-forcing Caesar is.)")
        elif choice == "4":
            txt = input("Enter text to scan: ")
            findings = detect_suspicious(txt)
            if findings["urls"] or findings["keywords"]:
                print("Suspicious content found:")
                if findings["urls"]:
                    print("  URLs:", ", ".join(findings["urls"]))
                if findings["keywords"]:
                    print("  Keywords:", ", ".join(findings["keywords"]))
                print("Suggestion: treat links as suspicious, don't click, verify sender.")
            else:
                print("No obvious suspicious indicators found.")
        elif choice == "5":
            inpath = input("Input file path (plain text): ")
            outpath = input("Output file path (cipher text): ")
            shift = int(input("Shift (integer): "))
            data = read_file(inpath)
            write_file(outpath, encrypt(data, shift))
            print("File encrypted and written to", outpath)
        elif choice == "6":
            inpath = input("Input file path (cipher text): ")
            outpath = input("Output file path (plain text): ")
            shift = int(input("Shift (integer): "))
            data = read_file(inpath)
            write_file(outpath, decrypt(data, shift))
            print("File decrypted and written to", outpath)
        elif choice == "7":
            sample = input("Enter short text to run Fernet demo (requires cryptography): ")
            result, err = fernet_demo(sample)
            if err:
                print("Fernet demo unavailable:", err)
            else:
                print("Fernet key (store securely):", result["key"])
                print("Ciphertext (token):", result["token"])
                print("Recovered plaintext:", result["recovered"])
        elif choice == "8":
            print("Exit. Keep learning. Logfile:", LOGFILE)
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    run_cli()
