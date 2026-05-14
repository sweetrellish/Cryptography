# Browser Presentation Demo

This is a lightweight browser fallback for presentation day.

## What It Supports

- Live AES-CBC demo in the browser using Web Crypto
- Live AES-GCM demo in the browser using Web Crypto
- Rijndael trace viewing by loading `trace.json` exported from `AESSimulator.py`
- Presentation presets for fast rehearsal

## How To Use

Open `index.html` directly in a browser, or serve the folder locally:

```bash
cd "VPN Project/presentation_web"
python3 -m http.server 8000
```

Then open:

```text
http://localhost:8000
```

## Presentation Workflow

1. Use the Tkinter AES simulator for your main demo and export a slide bundle.
2. If PowerPoint or screen sharing gets awkward, open this browser demo instead.
3. For Rijndael explanation, load `trace.json` from the exported slide bundle.
4. For quick live mode comparisons, use the CBC and GCM presets.

## Note

The browser demo does not reimplement the full Rijndael teaching engine. For round-by-round visualization, it expects exported trace data from the Python simulator.
