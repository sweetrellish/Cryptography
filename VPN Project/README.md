# VPN Project

A Python-based VPN simulation project with a Tkinter GUI and cryptography primitives for demonstrating secure communication concepts.

## Quick Start

From the project root folder, run:

```bash
/opt/homebrew/bin/python3.13 -m venv myenv
source myenv/bin/activate
python -m pip install --upgrade pip && python -m pip install -r requirements.txt
python VPNSimulator.py
```

For the AES-focused MATH 447 starter, run:

```bash
python AESSimulator.py
```

## Project Files

- `VPNSimulator.py`: Main GUI application.
- `AESSimulator.py`: AES-focused simulator starter for MATH 447 (CBC and GCM demos).
- `aes_core.py`: Reusable AES helper functions used by the GUI.
- `vpn_simulation.py`: Supporting simulation logic.
- `tooltip.py`: Tooltip helper used by the GUI.
- `tink.py`: Tkinter-related helper/demo script.
- `SSL.py`: SSL socket-related demo script.
- `tests/test_aes_core.py`: Unit tests for AES core behavior.
- `PROJECT_REFERENCE.md`: Command log + technical timeline of all work completed.

## Prerequisites

- macOS (or another OS with Python + Tk support)
- Python 3.13 recommended
- `pip`

Important: On this machine, `python3` may point to Python 3.14, which can fail with:

`ModuleNotFoundError: No module named '_tkinter'`

If that happens, use Python 3.13 explicitly.

## Setup (Recommended)

Run these commands from the project folder:

```bash
# 1) Create a fresh virtual environment with Python 3.13
/opt/homebrew/bin/python3.13 -m venv myenv

# 2) Activate it
source myenv/bin/activate

# 3) Upgrade pip and install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run the GUI App

```bash
# from project root (with venv activated)
python VPNSimulator.py
```

If you are not using the virtual environment:

```bash
/opt/homebrew/bin/python3.13 VPNSimulator.py
```

## Run the AES Starter (MATH 447)

```bash
# from project root (with venv activated)
python AESSimulator.py
```

Inside the AES starter, use the Mode Comparison Lab button to run an ECB vs CBC vs GCM pattern-leakage demo.

## Tinker Workflow (Recommended)

For robust team experimentation, use this order:

1. Edit crypto logic in `aes_core.py`.
2. Run tests to confirm behavior.
3. Use `AESSimulator.py` to interactively demo your changes.

Run tests:

```bash
python -m unittest tests/test_aes_core.py -v
```

## Full Reference Log

For a readable history of commands, debugging logic, and implementation decisions, see:

- `PROJECT_REFERENCE.md`

## Open and Edit in VS Code

1. Open the project folder in VS Code.
2. Open Command Palette: `Cmd+Shift+P`.
3. Run: `Python: Select Interpreter`.
4. Choose either:
   - `./myenv/bin/python` (recommended), or
   - `/opt/homebrew/bin/python3.13`
5. Run `VPNSimulator.py` from the VS Code Run button or terminal.

## Common Troubleshooting

### Error: `ModuleNotFoundError: No module named '_tkinter'`

Cause: Wrong interpreter selected (usually Python 3.14 without Tk bindings).

Fix:

```bash
# Verify interpreter
python --version
which python

# Test tkinter
python -c "import tkinter as tk; print(tk.TkVersion)"
```

If this fails, switch to Python 3.13 interpreter and retry.

### Renaming the Project Folder Safely (for example, to "Cryptography")

Renaming is safe for source code, but virtual environment and IDE metadata can keep old absolute paths.

Use this checklist immediately after renaming:

1. Open terminal in the renamed folder.
2. Delete old virtual environment folder (`myenv`).
3. Create a new virtual environment with Python 3.13.
4. Activate the new virtual environment.
5. Install dependencies from `requirements.txt`.
6. In VS Code, run "Python: Select Interpreter" and select `./myenv/bin/python`.
7. Run tests (`python -m unittest tests/test_aes_core.py -v`).
8. Launch apps (`python AESSimulator.py` and/or `python VPNSimulator.py`).

Suggested command sequence:

```bash
rm -rf myenv
/opt/homebrew/bin/python3.13 -m venv myenv
source myenv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest tests/test_aes_core.py -v
```

### Virtual Environment Seems Broken

If `myenv/bin/python` is not executable or behaves oddly, recreate the environment:

```bash
rm -rf myenv
/opt/homebrew/bin/python3.13 -m venv myenv
source myenv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Notes

This project is for simulation/learning. Do not treat it as production VPN software.
