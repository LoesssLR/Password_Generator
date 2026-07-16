# NIST & Corporate Password Generator

A cryptographically secure local password generator that strictly complies with the NIST SP 800-63B standard and high-complexity corporate policies.

## Features Implemented
- **CSPRNG Entropy:** Utilizes Python's native `secrets` library instead of `random` to guarantee operating system level cryptographic randomness.
- **Shannon Entropy Validation:** Calculates theoretical entropy and strictly enforces a minimum threshold of 80 bits.
- **Homoglyph Exclusion:** Removes visually ambiguous characters (l, 1, I, o, 0, O) to improve human readability and prevent transcription errors.
- **Sequential and Repetitive Filtering:** Actively rejects passwords containing ascending or descending ASCII sequences and prevents 3 or more identical consecutive characters.
- **Full ASCII Support:** Incorporates all printable ASCII characters, including intermediate whitespace, while ensuring the presence of mandatory institutional symbols.
- **Context Filtering:** Compares the output against a dictionary of weak passwords and specific environment data (like old passwords) to prevent predictable patterns.
- **Secure Clipboard Integration:** Automatically copies the generated password to the Windows clipboard using native tools without requiring external libraries.
- **Clipboard Auto-Clean:** Implements a background thread that clears the clipboard exactly 30 seconds after execution to prevent unauthorized access to the password in memory.

## Usage
1. Activate the virtual environment: `.\venv\Scripts\activate`
2. Run the script: `python main.py`
3. The password will be generated, displayed on the console, and copied to your clipboard.
4. You have 30 seconds to paste it before the auto-clean mechanism wipes the clipboard.