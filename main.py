import threading
import time
import subprocess
from src.generator import generar_super_password

def set_clipboard(text):
    """
    Copies text to the Windows clipboard using the native 'clip' command.
    """
    try:
        subprocess.run(['clip.exe'], input=text.encode('utf-16le'), check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception as e:
        print(f"\n[!] Error accessing clipboard: {e}")

def auto_clean_clipboard(delay=30):
    """
    Waits 'delay' seconds and then clears the clipboard.
    """
    time.sleep(delay)
    set_clipboard("")
    print("\n[Security] The clipboard has been cleared automatically (Auto-Clean).")

def run():
    try:
        # Recommended configuration: 16 characters including spaces
        password, bits = generar_super_password(longitud=16, permitir_espacios=True)
        
        print("\n" + "="*60)
        print("    CORPORATE & NIST PASSWORD GENERATOR     ")
        print("="*60)
        print(f" Suggested password : [ {password} ]")
        print(f" String length      : {len(password)} characters")
        print(f" Calculated entropy : {bits} bits (Optimal Strength: >80)")
        print("="*60)
        
        # Copy to clipboard
        set_clipboard(password)
        print("\n[*] The password has been successfully copied to the clipboard.")
        print("[!] You have exactly 30 seconds to paste it before it is destroyed.")
        print("\nPress Ctrl+C at any time to exit immediately...")

        # Start auto-destruct thread
        cleaner_thread = threading.Thread(target=auto_clean_clipboard, args=(30,), daemon=False)
        cleaner_thread.start()
        
    except Exception as e:
        print(f"\n[!] An error occurred while generating the password: {e}\n")

if __name__ == "__main__":
    run()