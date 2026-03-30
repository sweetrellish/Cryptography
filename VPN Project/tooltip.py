import tkinter as tk

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None

    def show_tooltip(self, event):
        # Create a new top-level window for the tooltip
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)  # Remove window decorations
        self.tooltip_window.geometry(f"+{event.x_root + 10}+{event.y_root + 10}")  # Position near the mouse
        label = tk.Label(
            self.tooltip_window, 
            text=self.text, 
            background="white", 
            foreground="black",
            relief="solid", 
            borderwidth=1, 
            font=("Helvetica", 10))
        label.pack()

    def hide_tooltip(self, event):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None
    def update_text(self, new_text):
        """Update the tooltip text dynamically."""
        self.text = new_text