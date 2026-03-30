import tkinter as tk
from tkinter import scrolledtext

root = tk.Tk()
root.title("Test Layout")

tk.Label(root, text="Label 1").grid(row=0, column=0)
tk.Label(root, text="Label 2").grid(row=0, column=1)
tk.Label(root, text="Label 3").grid(row=0, column=2)

box1 = scrolledtext.ScrolledText(root, width=30, height=10)
box2 = scrolledtext.ScrolledText(root, width=30, height=10)
box3 = scrolledtext.ScrolledText(root, width=30, height=10)

box1.grid(row=1, column=0)
box2.grid(row=1, column=1)
box3.grid(row=1, column=2)

root.mainloop()