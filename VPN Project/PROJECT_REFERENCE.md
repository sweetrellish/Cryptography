# Project Reference Log

This document summarizes all major setup/debug/refactor steps completed so far for the VPN Project and MATH 447 AES starter.

## 1) What Was Built

- Existing VPN simulator retained: `VPNSimulator.py`
- New AES-focused starter GUI added: `AESSimulator.py`
- AES logic extracted into reusable module: `aes_core.py`
- Unit tests added for AES core: `tests/test_aes_core.py`
- Setup documentation and troubleshooting improved: `README.md`
- Team dependency pinning file added: `requirements.txt`

## 2) Root Cause Investigation (Tkinter Issue)

Observed error:

- `ModuleNotFoundError: No module named '_tkinter'`

Conclusion:

- `python3` on PATH resolved to Homebrew Python 3.14 without Tk bindings.
- Python 3.13 (`/opt/homebrew/bin/python3.13`) had Tk support and successfully launched GUI apps.
- Existing `myenv` showed signs of being moved/copied from a different absolute path and had unreliable launcher behavior.

## 3) Command Log (Key Commands Executed)

The list below captures the important command sequence used during diagnosis and setup.

### Interpreter/Environment Diagnostics

- `which -a python3 python3.13`
- `python3 --version`
- `/opt/homebrew/bin/python3.13 --version`
- `python3 -c "import sys; print(sys.executable)"`
- `/opt/homebrew/bin/python3.13 -c "import sys; print(sys.executable)"`
- `python3 -c "import tkinter"`
- `/opt/homebrew/bin/python3.13 -c "import tkinter as tk; print('py313 tkinter ok', tk.TkVersion)"`

### venv Inspection/Repair Checks

- `ls -l myenv/bin`
- `sed -n '1,20p' myenv/bin/python`
- `sed -n '1,20p' myenv/bin/python3.13`
- `sed -n '1,20p' myenv/pyvenv.cfg`
- `chmod +x myenv/bin/python myenv/bin/python3 myenv/bin/python3.13 myenv/bin/pip myenv/bin/pip3 myenv/bin/pip3.13`

### Run Verification

- `/opt/homebrew/bin/python3.13 VPNSimulator.py`
- `/opt/homebrew/bin/python3.13 AESSimulator.py`

### Build/Test Validation

- `/opt/homebrew/bin/python3.13 -m py_compile AESSimulator.py`
- `/opt/homebrew/bin/python3.13 -m py_compile AESSimulator.py aes_core.py tests/test_aes_core.py`
- `/opt/homebrew/bin/python3.13 -m unittest tests/test_aes_core.py -v`

### Dependency Snapshot/Pinning

- `/opt/homebrew/bin/python3.13 -m pip freeze > requirements.txt`

## 4) Logic and Design Decisions

### Why Python 3.13 was selected

- It was confirmed to support `tkinter` in this environment.
- It runs both VPN and AES GUI scripts successfully.

### Why AES code was split into `aes_core.py`

- Keeps cryptographic logic independent from GUI wiring.
- Makes the code easier to test and safer to modify collaboratively.
- Supports classroom experimentation with reduced risk of GUI regressions.

### Why tests were added

- Verify CBC and GCM round trips.
- Verify GCM integrity failures when ciphertext is tampered.
- Verify mode comparison behavior showing ECB pattern leakage.

### Why the new mode comparison lab was added

- Supports MATH 447 instruction goals.
- Makes security-mode differences visible through repeated-block analysis.
- Enables interactive in-app experiments while preserving reproducibility through tests.

## 5) Current Files and Purpose

- `README.md`: Primary setup/use guide
- `PROJECT_REFERENCE.md`: Full historical reference (this file)
- `requirements.txt`: Team install dependencies
- `VPNSimulator.py`: Original networking-focused simulator
- `AESSimulator.py`: AES-focused educational GUI
- `aes_core.py`: Reusable cryptography functions and mode comparison helper
- `tests/test_aes_core.py`: Unit tests

## 6) Recommended Team Workflow

1. Create/activate venv with Python 3.13.
2. Install dependencies from `requirements.txt`.
3. Make crypto changes in `aes_core.py` first.
4. Run tests before GUI demos.
5. Demo behavior in `AESSimulator.py`.
6. Keep `VPNSimulator.py` unchanged unless network behavior is the goal.

## 7) Next Good Enhancements (Optional)

- Add deterministic test vectors from NIST for AES modes.
- Add export/import sample packets for assignment submissions.
- Add a small benchmark tab to compare mode performance.

## 8) MATH 447 Assignment Template

Use this structure for each experiment writeup.

### A) Experiment Metadata

- Team members:
- Date:
- Course/Section:
- Experiment title:

### B) Research Question

- What cryptographic behavior are we testing?
- What do we expect to observe?

### C) Environment

- OS:
- Python version:
- Command used to run app/tests:
- Relevant files touched:

### D) Inputs

- AES mode(s):
- Key size(s):
- IV/nonce strategy:
- AAD used (if GCM):
- Plaintext pattern used:

### E) Procedure

1. Steps followed in order.
2. Commands executed.
3. GUI actions performed.

### F) Observations

- Ciphertext differences:
- Repeated block counts (ECB/CBC/GCM):
- Decryption outcomes:
- Integrity check outcomes (GCM tag):

### G) Evidence

- JSON packet examples:
- Test output snippets:
- Screenshots (optional):

### H) Analysis

- Did results match expectations?
- Security implications of observed behavior.
- Limitations of the experiment.

### I) Conclusion

- Main takeaways.
- Recommended secure defaults.

### J) Follow-up Experiments

- What to test next and why.

### K) Quick Fill-In Example

```
Experiment title: ECB vs CBC vs GCM Pattern Leakage
Question: Does ECB reveal repeated plaintext structure more than CBC/GCM?
Input pattern: "A" * 64
Modes tested: ECB, CBC, GCM
Result summary: ECB showed repeated ciphertext blocks; CBC/GCM did not.
Conclusion: ECB is not appropriate for protecting structured plaintext patterns.
```
