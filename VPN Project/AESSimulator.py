"""
AES Encryption Simulator (MATH 447 Cryptography Presentation Mode)

This standalone GUI focuses on AES encryption/decryption concepts.
It supports AES-CBC (with PKCS7 padding) and AES-GCM (authenticated encryption).

Intended use: classroom/demo project starter, not production cryptography software.
"""

from datetime import datetime
import json
import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext
from pathlib import Path
from typing import TypedDict

from cryptography.exceptions import InvalidTag
from aes_core import aes_decrypt
from aes_core import aes_encrypt
from aes_core import key_length_valid
from aes_core import mode_pattern_report
from aes_core import parse_hex_or_raise
from aes_core import random_iv
from aes_core import random_key
from aes_core import validate_iv_for_mode
from aes_core_process import aes_cbc_decrypt_process
from aes_core_process import aes_cbc_encrypt_process


DEFAULT_PATTERN_SAMPLE = "BLOCK-16-REPEAT!" * 8


class PresentationPreset(TypedDict):
    engine: str
    mode: str
    key_size_bits: str
    key_hex: str
    iv_hex: str
    aad_text: str
    plaintext: str
    process_trace_enabled: bool
    run_pattern_demo: bool


class PresentationState(TypedDict):
    exported_at: str
    engine: str
    mode: str
    key_size_bits: str
    process_trace_enabled: bool
    key_hex: str
    iv_hex: str
    aad_text: str
    plaintext: str
    packet_text: str
    packet: dict[str, object]
    decrypted_text: str
    comparison_text: str
    status: str


PRESENTATION_PRESETS: dict[str, PresentationPreset] = {
    "Standard Cipher Block Chaining (CBC)": {
        "engine": "Standard",
        "mode": "Cipher Block Chaining (CBC)",
        "key_size_bits": "128",
        "key_hex": "00112233445566778899aabbccddeeff",
        "iv_hex": "0f0e0d0c0b0a09080706050403020100",
        "aad_text": "",
        "plaintext": "Meet at 5 PM by the library steps.",
        "process_trace_enabled": False,
        "run_pattern_demo": False,
    },
    "Standard Galois/Counter Mode (GCM) Integrity Demo": {
        "engine": "Standard",
        "mode": "Galois/Counter Mode (GCM)",
        "key_size_bits": "256",
        "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "iv_hex": "1a1b1c1d1e1f202122232425",
        "aad_text": "attendance-sheet",
        "plaintext": "GCM adds authentication so tampering is detectable.",
        "process_trace_enabled": False,
        "run_pattern_demo": False,
    },
    "Rijndael Trace Walkthrough": {
        "engine": "Rijndael Process",
        "mode": "Cipher Block Chaining (CBC)",
        "key_size_bits": "128",
        "key_hex": "000102030405060708090a0b0c0d0e0f",
        "iv_hex": "0f0e0d0c0b0a09080706050403020100",
        "aad_text": "",
        "plaintext": "Rijndael rounds transform the state step by step.",
        "process_trace_enabled": True,
        "run_pattern_demo": False,
    },
    "Pattern Leakage Demo": {
        "engine": "Standard",
        "mode": "Cipher Block Chaining (CBC)",
        "key_size_bits": "256",
        "key_hex": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "iv_hex": "11223344556677889900aabbccddeeff",
        "aad_text": "",
        "plaintext": DEFAULT_PATTERN_SAMPLE,
        "process_trace_enabled": False,
        "run_pattern_demo": True,
    },
}


def _presentation_summary(state: PresentationState) -> str:
    packet = state["packet"]
    packet_text = state["packet_text"]
    trace_entries = 0

    trace = packet.get("trace")
    if isinstance(trace, list):
        trace_entries = len(trace)
    elif isinstance(trace, dict):
        trace_entries = 1

    lines = [
        "# AES Demo Slide Bundle",
        "",
        f"Generated: {state['exported_at']}",
        f"Engine: {state['engine']}",
        f"Mode: {state['mode']}",
        f"Key Size (selected): {state['key_size_bits']} bits",
        f"Process Trace Enabled: {state['process_trace_enabled']}",
        "",
        "## Suggested Slide Flow",
        "1. Show the plaintext and selected AES engine/mode.",
        "2. Explain the generated key and IV/nonce values.",
        "3. Walk through the encrypted packet JSON and identify ciphertext, IV, and metadata.",
        "4. Show the decrypted output to confirm round-trip correctness.",
        "5. If present, use the comparison output or trace data to explain security/process behavior.",
        "",
        "## Current Demo Snapshot",
        f"- Plaintext length: {len(state['plaintext'])} characters",
        f"- Packet JSON present: {'yes' if packet_text else 'no'}",
        f"- Decrypted output present: {'yes' if state['decrypted_text'] else 'no'}",
        f"- Pattern demo present: {'yes' if state['comparison_text'] else 'no'}",
        f"- Trace entries exported: {trace_entries}",
        "",
        "## Presentation Tips",
        "- Use plaintext.txt and decrypted_output.txt on before/after slides.",
        "- Use packet.json for a zoomed-in ciphertext/IV metadata slide.",
        "- Use comparison.txt for ECB vs CBC vs GCM interpretation.",
        "- Use trace.json when explaining Rijndael process steps.",
    ]

    return "\n".join(lines) + "\n"


def _presenter_script(state: PresentationState) -> str:
    packet = state["packet"]
    trace = packet.get("trace")
    trace_entries = len(trace) if isinstance(trace, list) else 0
    aad_text = state["aad_text"] or "None"

    slides = [
        ("Slide 1 - Goal", [
            f"Today I am demonstrating the {state['engine']} path of the AES simulator.",
            f"The selected mode is {state['mode']} with a {state['key_size_bits']}-bit key.",
            "The goal is to show plaintext input, encryption output, and what changes depending on the mode or engine.",
        ]),
        ("Slide 2 - Inputs", [
            f"This plaintext is: {state['plaintext']}",
            f"The IV or nonce shown in the simulator is: {state['iv_hex'] or 'generated in app'}.",
            f"Additional authenticated data is: {aad_text}.",
        ]),
        ("Slide 3 - Packet", [
            "Here I focus on the encrypted packet JSON.",
            "I point out the mode, IV or nonce, ciphertext, and any tag or trace metadata.",
            f"The packet currently includes keys: {', '.join(packet.keys()) if packet else 'none yet'}.",
        ]),
        ("Slide 4 - Decryption", [
            f"After decryption, the simulator returns: {state['decrypted_text'] or 'no decrypted output exported yet'}.",
            "This confirms the round-trip when the correct key and supporting values are used.",
        ]),
    ]

    if state["comparison_text"]:
        slides.append(("Slide 5 - Pattern Leakage", [
            "The comparison output helps explain why ECB leaks patterns while CBC and GCM hide repetition better.",
            "I use this slide to connect the simulator output to secure mode selection.",
        ]))

    if trace_entries:
        slides.append(("Slide 6 - Rijndael Trace", [
            f"The exported trace contains {trace_entries} trace entries for the current packet.",
            "I use this to discuss AddRoundKey, SubBytes, ShiftRows, MixColumns, and why the final round differs.",
        ]))

    lines = ["# Presenter Script", ""]
    for title, notes in slides:
        lines.append(f"## {title}")
        lines.append("")
        for note in notes:
            lines.append(f"- {note}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _collect_export_state(app: "AESSimulatorApp") -> PresentationState:
    packet_text = app.packet_box.get("1.0", tk.END).strip()
    packet: dict[str, object] = {}
    if packet_text:
        try:
            loaded_packet = json.loads(packet_text)
            if isinstance(loaded_packet, dict):
                packet = loaded_packet
        except json.JSONDecodeError:
            packet = {}

    return {
        "exported_at": datetime.now().isoformat(timespec="seconds"),
        "engine": app.engine_var.get(),
        "mode": app.mode_var.get(),
        "key_size_bits": app.key_size_var.get(),
        "process_trace_enabled": app.process_trace_var.get(),
        "key_hex": app.key_entry.get().strip(),
        "iv_hex": app.iv_entry.get().strip(),
        "aad_text": app.aad_entry.get().strip(),
        "plaintext": app.plaintext_box.get("1.0", tk.END).rstrip("\n"),
        "packet_text": packet_text,
        "packet": packet,
        "decrypted_text": app.decrypted_box.get("1.0", tk.END).rstrip("\n"),
        "comparison_text": app.comparison_box.get("1.0", tk.END).rstrip("\n"),
        "status": app.status_var.get(),
    }


def export_presentation_bundle(state: PresentationState, export_root: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    bundle_dir = export_root / f"aes_demo_bundle_{timestamp}"
    bundle_dir.mkdir(parents=True, exist_ok=False)

    summary_text = _presentation_summary(state)
    presenter_script = _presenter_script(state)
    metadata = {
        "exported_at": state["exported_at"],
        "engine": state["engine"],
        "mode": state["mode"],
        "key_size_bits": state["key_size_bits"],
        "process_trace_enabled": state["process_trace_enabled"],
        "status": state["status"],
    }

    (bundle_dir / "slide_notes.md").write_text(summary_text, encoding="utf-8")
    (bundle_dir / "presenter_script.md").write_text(presenter_script, encoding="utf-8")
    (bundle_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (bundle_dir / "plaintext.txt").write_text(str(state["plaintext"]), encoding="utf-8")
    (bundle_dir / "decrypted_output.txt").write_text(str(state["decrypted_text"]), encoding="utf-8")
    (bundle_dir / "comparison.txt").write_text(str(state["comparison_text"]), encoding="utf-8")

    inputs = {
        "key_hex": state["key_hex"],
        "iv_hex": state["iv_hex"],
        "aad_text": state["aad_text"],
    }
    (bundle_dir / "input_materials.json").write_text(json.dumps(inputs, indent=2), encoding="utf-8")

    packet_text = str(state["packet_text"])
    (bundle_dir / "packet.json").write_text(packet_text if packet_text else "{}\n", encoding="utf-8")

    packet = state["packet"]
    if isinstance(packet, dict) and packet.get("trace") is not None:
        (bundle_dir / "trace.json").write_text(json.dumps(packet["trace"], indent=2), encoding="utf-8")

    return bundle_dir

class AESSimulatorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("MATH 447 - AES Encryption Simulator")

        self.engine_var = tk.StringVar(value="Standard")
        self.mode_var = tk.StringVar(value="CBC")
        self.key_size_var = tk.StringVar(value="256")
        self.preset_var = tk.StringVar(value="Standard CBC Walkthrough")
        self.process_trace_var = tk.BooleanVar(value=False)

        self._build_ui()
        self._on_mode_change()
        self._on_engine_change()

    def _build_ui(self) -> None:
        top = tk.Frame(self.root)
        top.pack(fill=tk.X, padx=10, pady=8)

        tk.Label(top, text="Engine:").grid(row=0, column=0, sticky="w")
        self.engine_menu = tk.OptionMenu(
            top,
            self.engine_var,
            "Standard",
            "Rijndael Process",
            command=lambda _: self._on_engine_change(),
        )
        self.engine_menu.grid(row=0, column=1, sticky="w")

        tk.Label(top, text="AES Mode:").grid(row=0, column=2, padx=(12, 0), sticky="w")
        self.mode_menu = tk.OptionMenu(top, self.mode_var, "CBC", "GCM", command=lambda _: self._on_mode_change())
        self.mode_menu.grid(row=0, column=3, sticky="w")

        tk.Label(top, text="Key Size (bits):").grid(row=0, column=4, padx=(12, 0), sticky="w")
        self.key_size_menu = tk.OptionMenu(top, self.key_size_var, "128", "192", "256")
        self.key_size_menu.grid(row=0, column=5, sticky="w")

        tk.Button(top, text="Generate Key + IV", command=self.generate_material).grid(
            row=0, column=6, padx=(12, 0)
        )

        self.preset_menu = tk.OptionMenu(top, self.preset_var, *PRESENTATION_PRESETS.keys())
        self.preset_menu.grid(row=1, column=1, sticky="w", pady=(6, 0))
        tk.Label(top, text="Presentation Preset:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        tk.Button(top, text="Load Preset", command=self.load_presentation_preset).grid(
            row=1, column=2, sticky="w", padx=(12, 0), pady=(6, 0)
        )

        self.trace_checkbox = tk.Checkbutton(
            top,
            text="Include process trace",
            variable=self.process_trace_var,
        )
        self.trace_checkbox.grid(row=0, column=7, padx=(12, 0), sticky="w")

        key_frame = tk.Frame(self.root)
        key_frame.pack(fill=tk.X, padx=10, pady=4)

        tk.Label(key_frame, text="Key (hex):").grid(row=0, column=0, sticky="w")
        self.key_entry = tk.Entry(key_frame, width=90)
        self.key_entry.grid(row=0, column=1, sticky="we", padx=6)

        tk.Label(key_frame, text="IV/Nonce (hex):").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.iv_entry = tk.Entry(key_frame, width=90)
        self.iv_entry.grid(row=1, column=1, sticky="we", padx=6, pady=(6, 0))

        tk.Label(key_frame, text="AAD (text, GCM only):").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.aad_entry = tk.Entry(key_frame, width=90)
        self.aad_entry.grid(row=2, column=1, sticky="we", padx=6, pady=(6, 0))

        key_frame.grid_columnconfigure(1, weight=1)

        text_frame = tk.Frame(self.root)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        tk.Label(text_frame, text="Plaintext Input:").grid(row=0, column=0, sticky="w")
        self.plaintext_box = scrolledtext.ScrolledText(text_frame, height=7, wrap=tk.WORD)
        self.plaintext_box.grid(row=1, column=0, sticky="nsew", pady=(2, 8))

        tk.Label(text_frame, text="Encrypted Packet (JSON):").grid(row=2, column=0, sticky="w")
        self.packet_box = scrolledtext.ScrolledText(text_frame, height=10, wrap=tk.WORD)
        self.packet_box.grid(row=3, column=0, sticky="nsew", pady=(2, 8))

        tk.Label(text_frame, text="Decrypted Output:").grid(row=4, column=0, sticky="w")
        self.decrypted_box = scrolledtext.ScrolledText(text_frame, height=7, wrap=tk.WORD)
        self.decrypted_box.grid(row=5, column=0, sticky="nsew", pady=(2, 2))

        text_frame.grid_rowconfigure(1, weight=1)
        text_frame.grid_rowconfigure(3, weight=1)
        text_frame.grid_rowconfigure(5, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)

        action_frame = tk.Frame(self.root)
        action_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Button(action_frame, text="Encrypt", command=self.encrypt).pack(side=tk.LEFT)
        tk.Button(action_frame, text="Decrypt Packet", command=self.decrypt).pack(side=tk.LEFT, padx=8)
        tk.Button(action_frame, text="Export Slide Bundle", command=self.export_slide_bundle).pack(side=tk.LEFT)
        tk.Button(action_frame, text="Clear", command=self.clear_all).pack(side=tk.LEFT)

        lab_frame = tk.LabelFrame(self.root, text="Mode Comparison Lab (ECB vs CBC vs GCM)")
        lab_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        tk.Button(lab_frame, text="Run Pattern Leakage Demo", command=self.run_pattern_demo).pack(
            anchor="w", padx=8, pady=(8, 4)
        )
        tk.Label(
            lab_frame,
            text="Uses current plaintext (or a default repeating sample) to compare repeated ciphertext blocks.",
            anchor="w",
        ).pack(fill=tk.X, padx=8)

        self.comparison_box = scrolledtext.ScrolledText(lab_frame, height=8, wrap=tk.WORD)
        self.comparison_box.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(self.root, textvariable=self.status_var, anchor="w", fg="darkgreen").pack(
            fill=tk.X, padx=10, pady=(0, 10)
        )

    def _on_mode_change(self) -> None:
        if self.engine_var.get() == "Rijndael Process":
            self.aad_entry.config(state="disabled")
            self.aad_entry.delete(0, tk.END)
            self.status_var.set("Engine: Rijndael Process (AES-128 CBC with optional round tracing)")
            return

        mode_name = self.mode_var.get()
        if mode_name == "CBC":
            self.aad_entry.config(state="disabled")
            self.aad_entry.delete(0, tk.END)
            self.status_var.set("Mode: CBC (confidentiality only; no built-in authentication)")
        else:
            self.aad_entry.config(state="normal")
            self.status_var.set("Mode: GCM (confidentiality + integrity/authentication)")

    def _on_engine_change(self) -> None:
        using_process = self.engine_var.get() == "Rijndael Process"

        if using_process:
            self.mode_var.set("CBC")
            self.key_size_var.set("128")
            self.mode_menu.config(state="disabled")
            self.key_size_menu.config(state="disabled")
            self.trace_checkbox.config(state="normal")
        else:
            self.mode_menu.config(state="normal")
            self.key_size_menu.config(state="normal")
            self.trace_checkbox.config(state="disabled")
            self.process_trace_var.set(False)

        self._on_mode_change()

    def generate_material(self) -> None:
        try:
            key_size_bits = 128 if self.engine_var.get() == "Rijndael Process" else int(self.key_size_var.get())
            mode_name = "CBC" if self.engine_var.get() == "Rijndael Process" else self.mode_var.get()
            key = random_key(key_size_bits)
            iv = random_iv(mode_name)

            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key.hex())

            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, iv.hex())

            self.status_var.set("Generated fresh key and IV/nonce")
        except Exception as exc:
            messagebox.showerror("Generation Error", str(exc))

    def load_presentation_preset(self) -> None:
        try:
            preset = PRESENTATION_PRESETS[self.preset_var.get()]

            self.engine_var.set(str(preset["engine"]))
            self._on_engine_change()

            self.mode_var.set(str(preset["mode"]))
            self.key_size_var.set(str(preset["key_size_bits"]))
            self.process_trace_var.set(bool(preset["process_trace_enabled"]))
            self._on_mode_change()

            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, str(preset["key_hex"]))

            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, str(preset["iv_hex"]))

            self.aad_entry.config(state="normal")
            self.aad_entry.delete(0, tk.END)
            self.aad_entry.insert(0, str(preset["aad_text"]))
            self._on_mode_change()

            self.plaintext_box.delete("1.0", tk.END)
            self.plaintext_box.insert(tk.END, str(preset["plaintext"]))

            self.encrypt()
            self.decrypt()

            if bool(preset["run_pattern_demo"]):
                self.run_pattern_demo()

            self.status_var.set(f"Loaded presentation preset: {self.preset_var.get()}")
        except Exception as exc:
            messagebox.showerror("Preset Error", str(exc))

    def encrypt(self) -> None:
        try:
            plaintext = self.plaintext_box.get("1.0", tk.END).rstrip("\n")
            if not plaintext:
                raise ValueError("Plaintext input cannot be empty")

            key = parse_hex_or_raise("Key", self.key_entry.get())
            mode_name = "CBC" if self.engine_var.get() == "Rijndael Process" else self.mode_var.get()

            if self.engine_var.get() == "Rijndael Process":
                if len(key) != 16:
                    raise ValueError("Rijndael Process engine requires AES-128 key (16 bytes / 32 hex chars)")
            elif not key_length_valid(key):
                raise ValueError("AES key must be 16, 24, or 32 bytes (32/48/64 hex chars)")

            iv_text = self.iv_entry.get().strip()
            iv = bytes.fromhex(iv_text) if iv_text else random_iv(mode_name)
            validate_iv_for_mode(iv, mode_name)

            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, iv.hex())

            if self.engine_var.get() == "Rijndael Process":
                packet = aes_cbc_encrypt_process(
                    plaintext=plaintext,
                    key=key,
                    iv=iv,
                    include_trace=self.process_trace_var.get(),
                )
                packet["engine"] = "Rijndael Process"
            else:
                aad = b""
                if mode_name == "GCM":
                    aad = self.aad_entry.get().encode("utf-8") if self.aad_entry.get() else b""
                packet = aes_encrypt(plaintext=plaintext, key=key, iv=iv, mode_name=mode_name, aad=aad)
                packet["engine"] = "Standard"

            packet["key_size_bits"] = len(key) * 8

            self.packet_box.delete("1.0", tk.END)
            self.packet_box.insert(tk.END, json.dumps(packet, indent=2))

            self.status_var.set("Encryption complete")
        except Exception as exc:
            messagebox.showerror("Encryption Error", str(exc))

    def decrypt(self) -> None:
        try:
            packet_text = self.packet_box.get("1.0", tk.END).strip()
            if not packet_text:
                raise ValueError("Encrypted packet JSON is empty")

            packet = json.loads(packet_text)
            key = parse_hex_or_raise("Key", self.key_entry.get())
            use_process = packet.get("engine") == "Rijndael Process" or packet.get("algorithm") == "AES-128 (Rijndael)"

            if use_process:
                if len(key) != 16:
                    raise ValueError("Rijndael Process engine requires AES-128 key (16 bytes / 32 hex chars)")
                result = aes_cbc_decrypt_process(
                    packet=packet,
                    key=key,
                    include_trace=self.process_trace_var.get(),
                )
                plaintext = result["plaintext"]

                if "trace" in result:
                    self.comparison_box.delete("1.0", tk.END)
                    self.comparison_box.insert(
                        tk.END,
                        f"Process trace blocks generated during decryption: {len(result['trace'])}\n"
                        "Tip: inspect packet JSON for full encryption trace and use include-trace for decrypt trace.",
                    )
            else:
                if not key_length_valid(key):
                    raise ValueError("AES key must be 16, 24, or 32 bytes (32/48/64 hex chars)")
                plaintext = aes_decrypt(packet, key)

            self.decrypted_box.delete("1.0", tk.END)
            self.decrypted_box.insert(tk.END, plaintext)

            self.status_var.set("Decryption complete")
        except InvalidTag:
            messagebox.showerror(
                "Decryption Error",
                "Authentication failed (GCM tag mismatch). Check key, nonce, tag, and AAD.",
            )
        except Exception as exc:
            messagebox.showerror("Decryption Error", str(exc))

    def clear_all(self) -> None:
        self.plaintext_box.delete("1.0", tk.END)
        self.packet_box.delete("1.0", tk.END)
        self.decrypted_box.delete("1.0", tk.END)
        self.comparison_box.delete("1.0", tk.END)
        self.status_var.set("Cleared")

    def export_slide_bundle(self) -> None:
        try:
            state = _collect_export_state(self)
            export_root = Path(__file__).resolve().parent / "presentation_exports"
            bundle_dir = export_presentation_bundle(state, export_root)
            self.status_var.set(f"Exported slide bundle to {bundle_dir.name}")
            messagebox.showinfo(
                "Export Complete",
                f"Presentation bundle exported to:\n{bundle_dir}\n\nUse slide_notes.md, packet.json, and the text files in PowerPoint.",
            )
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    def run_pattern_demo(self) -> None:
        try:
            key = parse_hex_or_raise("Key", self.key_entry.get())
            if not key_length_valid(key):
                raise ValueError("AES key must be 16, 24, or 32 bytes (32/48/64 hex chars)")

            sample = self.plaintext_box.get("1.0", tk.END).rstrip("\n")
            if not sample:
                sample = DEFAULT_PATTERN_SAMPLE

            report = mode_pattern_report(
                sample_text=sample,
                key=key,
                cbc_iv=random_iv("CBC"),
                gcm_iv=random_iv("GCM"),
            )

            lines = []
            lines.append("Pattern Leakage Demo")
            lines.append(f"Sample length: {report['sample_length']} bytes")
            lines.append("")
            lines.append("Repeated ciphertext blocks (16-byte blocks):")
            lines.append(f"ECB: {report['ecb']['repeated_blocks']} repeated")
            lines.append(f"CBC: {report['cbc']['repeated_blocks']} repeated")
            lines.append(f"GCM: {report['gcm']['repeated_blocks']} repeated")
            lines.append("")
            lines.append("Interpretation:")
            lines.append("- ECB often leaks plaintext patterns through repeated ciphertext blocks.")
            lines.append("- CBC and GCM reduce this visible repetition for the same input pattern.")
            lines.append("- GCM additionally provides integrity/authentication via a tag.")

            self.comparison_box.delete("1.0", tk.END)
            self.comparison_box.insert(tk.END, "\n".join(lines))
            self.status_var.set("Mode comparison demo complete")
        except Exception as exc:
            messagebox.showerror("Mode Comparison Error", str(exc))


if __name__ == "__main__":
    root = tk.Tk()
    app = AESSimulatorApp(root)
    root.geometry("980x900")
    root.mainloop()
