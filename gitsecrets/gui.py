"""Tkinter GUI for git-secret-hunter (standard library only)."""

from __future__ import annotations

import queue
import threading

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

try:
    from gitsecrets import scanner
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from gitsecrets import scanner


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("git-secret-hunter")
        self.geometry("820x600")
        self.minsize(680, 480)
        self.ui: "queue.Queue" = queue.Queue()
        self.after(60, self._drain)

        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        top.columnconfigure(0, weight=1)
        ttk.Label(top, text="Git repository").grid(row=0, column=0, sticky="w")
        self.path = tk.StringVar()
        ttk.Entry(top, textvariable=self.path).grid(row=1, column=0, sticky="ew")
        ttk.Button(top, text="Browse…", command=self._browse).grid(row=1, column=1, padx=6)
        self.btn = ttk.Button(top, text="Scan history", command=self._scan)
        self.btn.grid(row=1, column=2)

        self.out = scrolledtext.ScrolledText(self, wrap="word", font=("Consolas", 10),
                                             state="disabled")
        self.out.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.status = ttk.Label(self, relief="sunken", anchor="w", text="Ready")
        self.status.pack(fill="x", side="bottom")

    def _drain(self):
        try:
            while True:
                self.ui.get_nowait()()
        except queue.Empty:
            pass
        self.after(60, self._drain)

    def _browse(self):
        d = filedialog.askdirectory(title="Choose a git repository")
        if d:
            self.path.set(d)

    def _show(self, text):
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("1.0", text)
        self.out.configure(state="disabled")

    def _scan(self):
        repo = self.path.get().strip()
        if not repo:
            messagebox.showinfo("No repo", "Choose a git repository.")
            return
        self.btn.configure(state="disabled")
        self.status.configure(text="Scanning history…")

        def work():
            try:
                res = scanner.scan_repo(repo)
                text = res.as_text()
            except Exception as exc:  # noqa: BLE001
                text = f"Error: {exc}"

            def done():
                self._show(text)
                self.btn.configure(state="normal")
                self.status.configure(text="Done.")
            self.ui.put(done)

        threading.Thread(target=work, daemon=True).start()


def main() -> int:
    App().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
