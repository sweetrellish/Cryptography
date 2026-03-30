"""
AES Encryption Simulator (MATH 447 starter)

This standalone GUI focuses on AES encryption/decryption concepts.
It supports AES-CBC (with PKCS7 padding) and AES-GCM (authenticated encryption).

Intended use: classroom/demo project starter, not production cryptography software.
"""

import json
import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext

from cryptography.exceptions import InvalidTag
from aes_core import aes_decrypt
from aes_core import aes_encrypt
from aes_core import key_length_valid
from aes_core import mode_pattern_report
from aes_core import parse_hex_or_raise
from aes_core import random_iv
from aes_core import random_key
from aes_core import validate_iv_for_mode


DEFAULT_PATTERN_SAMPLE = "BLOCK-16-REPEAT!" * 8

class AESSimulatorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("MATH 447 - AES Encryption Simulator")

        self.mode_var = tk.StringVar(value="CBC")
        self.key_size_var = tk.StringVar(value="256")

        self._build_ui()
        self._on_mode_change()

    def _build_ui(self) -> None:
        top = tk.Frame(self.root)
        top.pack(fill=tk.X, padx=10, pady=8)

        tk.Label(top, text="AES Mode:").grid(row=0, column=0, sticky="w")
        tk.OptionMenu(top, self.mode_var, "CBC", "GCM", command=lambda _: self._on_mode_change()).grid(
            row=0, column=1, sticky="w"
        )

        tk.Label(top, text="Key Size (bits):").grid(row=0, column=2, padx=(12, 0), sticky="w")
        tk.OptionMenu(top, self.key_size_var, "128", "192", "256").grid(row=0, column=3, sticky="w")

        tk.Button(top, text="Generate Key + IV", command=self.generate_material).grid(
            row=0, column=4, padx=(12, 0)
        )

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
        mode_name = self.mode_var.get()
        if mode_name == "CBC":
            self.aad_entry.config(state="disabled")
            self.aad_entry.delete(0, tk.END)
            self.status_var.set("Mode: CBC (confidentiality only; no built-in authentication)")
        else:
            self.aad_entry.config(state="normal")
            self.status_var.set("Mode: GCM (confidentiality + integrity/authentication)")

    def generate_material(self) -> None:
        try:
            key_size_bits = int(self.key_size_var.get())
            mode_name = self.mode_var.get()
            key = random_key(key_size_bits)
            iv = random_iv(mode_name)

            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key.hex())

            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, iv.hex())

            self.status_var.set("Generated fresh key and IV/nonce")
        except Exception as exc:
            messagebox.showerror("Generation Error", str(exc))

    def encrypt(self) -> None:
        try:
            plaintext = self.plaintext_box.get("1.0", tk.END).rstrip("\n")
            if not plaintext:
                raise ValueError("Plaintext input cannot be empty")

            key = parse_hex_or_raise("Key", self.key_entry.get())
            if not key_length_valid(key):
                raise ValueError("AES key must be 16, 24, or 32 bytes (32/48/64 hex chars)")

            mode_name = self.mode_var.get()
            iv_text = self.iv_entry.get().strip()
            iv = bytes.fromhex(iv_text) if iv_text else random_iv(mode_name)
            validate_iv_for_mode(iv, mode_name)

            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, iv.hex())

            aad = b""
            if mode_name == "GCM":
                aad = self.aad_entry.get().encode("utf-8") if self.aad_entry.get() else b""

            packet = aes_encrypt(plaintext=plaintext, key=key, iv=iv, mode_name=mode_name, aad=aad)
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
