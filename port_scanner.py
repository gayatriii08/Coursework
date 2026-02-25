#!/usr/bin/env python3
"""
Port Scanner GUI - A GUI-based TCP port scanner
Usage: python port_scanner_gui.py
"""

import socket
import sys
import threading
import queue
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

# Common ports and their services
COMMON_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 69: "TFTP", 80: "HTTP", 110: "POP3", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 2181: "Zookeeper", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC", 6379: "Redis",
    6443: "Kubernetes", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport", 27017: "MongoDB"
}

# ── Colour theme ──────────────────────────────────────────────────────────────
DARK_BG      = "#1e1e2e"
PANEL_BG     = "#252536"
ACCENT       = "#7c6af7"
ACCENT_HOVER = "#9d8fff"
PINK         = "#fa50ca"
RED          = "#ff5555"
YELLOW       = "#f1fa8c"
TEXT_FG      = "#cdd6f4"
SUBTEXT      = "#6c7086"
BORDER       = "#313244"
ENTRY_BG     = "#181825"


class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")
        self.root.geometry("900x700")
        self.root.minsize(750, 580)
        self.root.configure(bg=DARK_BG)

        self.scanning = False
        self.open_ports = []
        self.lock = threading.Lock()
        self.port_queue = queue.Queue()
        self.scan_thread = None
        self.total_ports = 0
        self.scanned_ports = 0
        self.start_time = None

        self._build_ui()

    # ------------------------------------------------------------------ UI --

    def _build_ui(self):
        # ── Top bar ──────────────────────────────────────────────────────────
        top = tk.Frame(self.root, bg=DARK_BG, pady=12, padx=16)
        top.pack(fill="x")

        tk.Label(top, text="⬡  PORT SCANNER", bg=DARK_BG, fg=ACCENT,
                 font=("Consolas", 16, "bold")).pack(side="left")

        self.status_dot = tk.Label(top, text="●", bg=DARK_BG, fg=SUBTEXT,
                                   font=("Consolas", 12))
        self.status_dot.pack(side="right", padx=(0, 4))
        self.status_lbl = tk.Label(top, text="Idle", bg=DARK_BG, fg=SUBTEXT,
                                   font=("Consolas", 10))
        self.status_lbl.pack(side="right")

        ttk.Separator(self.root, orient="horizontal").pack(fill="x")

        # ── Config panel ─────────────────────────────────────────────────────
        cfg = tk.Frame(self.root, bg=PANEL_BG, padx=18, pady=14)
        cfg.pack(fill="x", padx=10, pady=(10, 0))

        tk.Label(cfg, text="Target Host", bg=PANEL_BG, fg=SUBTEXT,
                 font=("Consolas", 8)).grid(row=0, column=0, sticky="w")
        tk.Label(cfg, text="Threads", bg=PANEL_BG, fg=SUBTEXT,
                 font=("Consolas", 8)).grid(row=0, column=2, sticky="w", padx=(18, 0))
        tk.Label(cfg, text="Timeout (s)", bg=PANEL_BG, fg=SUBTEXT,
                 font=("Consolas", 8)).grid(row=0, column=4, sticky="w", padx=(18, 0))
        tk.Label(cfg, text="Ports", bg=PANEL_BG, fg=SUBTEXT,
                 font=("Consolas", 8)).grid(row=2, column=0, sticky="w", pady=(10, 0))

        self.target_var = tk.StringVar(value="scanme.nmap.org")
        self.threads_var = tk.StringVar(value="100")
        self.timeout_var = tk.StringVar(value="1.0")
        self.ports_var = tk.StringVar(value="1-1024")

        self._entry(cfg, self.target_var, width=30).grid(row=1, column=0, columnspan=2, sticky="ew")
        self._entry(cfg, self.threads_var, width=8).grid(row=1, column=2, padx=(18, 0))
        self._entry(cfg, self.timeout_var, width=8).grid(row=1, column=4, padx=(18, 0))
        self._entry(cfg, self.ports_var, width=30).grid(row=3, column=0, columnspan=2, sticky="ew")

         # ── Port preset buttons ───────────────────────────────────────────────
        btn_frame = tk.Frame(cfg, bg=PANEL_BG)
        btn_frame.grid(row=3, column=2, columnspan=4, padx=(18, 0), sticky="w")
        presets = [
            ("Common", ",".join(map(str, sorted(COMMON_SERVICES.keys())))),
            ("Top 100", "1-100"),
            ("1-1024",  "1-1024"),
            ("All",     "1-65535"),
        ]
        for label, val in presets:
            tk.Button(btn_frame, text=label, bg=BORDER, fg=TEXT_FG,
                      font=("Consolas", 8), relief="flat", cursor="hand2",
                      activebackground=ACCENT, activeforeground="white",
                      command=lambda v=val: self.ports_var.set(v),
                      padx=8, pady=2).pack(side="left", padx=3)

        # ── Checkboxes ────────────────────────────────────────────────────────
        chk_frame = tk.Frame(cfg, bg=PANEL_BG)
        chk_frame.grid(row=4, column=0, columnspan=6, pady=(10, 0), sticky="w")

        self.banner_var = tk.BooleanVar()
        self.resolve_var = tk.BooleanVar(value=True)

        self._checkbox(chk_frame, "Grab Banners", self.banner_var).pack(side="left", padx=(0, 20))
        self._checkbox(chk_frame, "Show Resolved IP", self.resolve_var).pack(side="left")

        # Buttons
        btn_right = tk.Frame(cfg, bg=PANEL_BG)
        btn_right.grid(row=1, column=6, rowspan=4, sticky="ne", padx=(18, 0))

        self.scan_btn = tk.Button(btn_right, text="▶  Start Scan",
                                  bg=ACCENT, fg="white",
                                  font=("Consolas", 10, "bold"),
                                  relief="flat", cursor="hand2",
                                  activebackground=ACCENT_HOVER,
                                  command=self._start_scan,
                                  padx=14, pady=6)
        self.scan_btn.pack(fill="x", pady=(0, 6))

        self.stop_btn = tk.Button(btn_right, text="◼  Stop",
                                  bg=BORDER, fg=RED,
                                  font=("Consolas", 10),
                                  relief="flat", cursor="hand2",
                                  state="disabled",
                                  command=self._stop_scan,
                                  padx=14, pady=6)
        self.stop_btn.pack(fill="x", pady=(0, 6))

        tk.Button(btn_right, text="⬇  Export",
                  bg=BORDER, fg=TEXT_FG,
                  font=("Consolas", 10),
                  relief="flat", cursor="hand2",
                  command=self._export_results,
                  padx=14, pady=6).pack(fill="x", pady=(0, 6))

        tk.Button(btn_right, text="✕  Clear",
                  bg=BORDER, fg=SUBTEXT,
                  font=("Consolas", 10),
                  relief="flat", cursor="hand2",
                  command=self._clear,
                  padx=14, pady=6).pack(fill="x")

        cfg.columnconfigure(1, weight=1)

        # ── Progress bar ──────────────────────────────────────────────────────
        prog_frame = tk.Frame(self.root, bg=DARK_BG, padx=10, pady=6)
        prog_frame.pack(fill="x")

        self.progress_var = tk.DoubleVar()
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Custom.Horizontal.TProgressbar",
                        troughcolor=BORDER, background=ACCENT,
                        thickness=6, borderwidth=0)
        self.progress_bar = ttk.Progressbar(prog_frame, variable=self.progress_var,
                                             maximum=100,
                                             style="Custom.Horizontal.TProgressbar")
        self.progress_bar.pack(fill="x")

        self.progress_lbl = tk.Label(prog_frame, text="", bg=DARK_BG,
                                     fg=SUBTEXT, font=("Consolas", 8))
        self.progress_lbl.pack(anchor="e")

        # ── Results table ─────────────────────────────────────────────────────
        table_frame = tk.Frame(self.root, bg=DARK_BG, padx=10)
        table_frame.pack(fill="both", expand=True)

        cols = ("port", "service", "status", "banner")
        style.configure("Treeview",
                        background=PANEL_BG, foreground=TEXT_FG,
                        fieldbackground=PANEL_BG, borderwidth=0,
                        rowheight=22, font=("Consolas", 9))
        style.configure("Treeview.Heading",
                        background=BORDER, foreground=TEXT_FG,
                        font=("Consolas", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", ACCENT)])

        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                  selectmode="browse")
        self.tree.heading("port",    text="Port",    anchor="w")
        self.tree.heading("service", text="Service", anchor="w")
        self.tree.heading("status",  text="Status",  anchor="w")
        self.tree.heading("banner",  text="Banner",  anchor="w")

        self.tree.column("port",    width=70,  stretch=False)
        self.tree.column("service", width=140, stretch=False)
        self.tree.column("status",  width=80,  stretch=False)
        self.tree.column("banner",  width=400, stretch=True)

        self.tree.tag_configure("open",   foreground=PINK)
        self.tree.tag_configure("closed", foreground=SUBTEXT)

        vsb = ttk.Scrollbar(table_frame, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # ── Log console ───────────────────────────────────────────────────────
        log_frame = tk.Frame(self.root, bg=DARK_BG, padx=10)
        log_frame.pack(fill="x", pady=(0, 10))

        tk.Label(log_frame, text="Log", bg=DARK_BG, fg=SUBTEXT,
                 font=("Consolas", 8)).pack(anchor="w")

        self.log = scrolledtext.ScrolledText(log_frame, height=5,
                                              bg=ENTRY_BG, fg=TEXT_FG,
                                              font=("Consolas", 8),
                                              relief="flat", state="disabled",
                                              insertbackground=TEXT_FG)
        self.log.pack(fill="x")
        self.log.tag_configure("open",  foreground=PINK)
        self.log.tag_configure("info",  foreground=ACCENT)
        self.log.tag_configure("error", foreground=RED)
        self.log.tag_configure("warn",  foreground=YELLOW)

     # ── Widget helpers ────────────────────────────────────────────────────────

    def _entry(self, parent, var, **kw):
        return tk.Entry(parent, textvariable=var, bg=ENTRY_BG, fg=TEXT_FG,
                        insertbackground=TEXT_FG, relief="flat",
                        font=("Consolas", 10), **kw)

    def _checkbox(self, parent, text, var):
        return tk.Checkbutton(parent, text=text, variable=var,
                               bg=PANEL_BG, fg=TEXT_FG,
                               selectcolor=ENTRY_BG, activebackground=PANEL_BG,
                               activeforeground=TEXT_FG,
                               font=("Consolas", 9))
    # ── Progress / status helpers ─────────────────────────────────────────────
    def _log(self, msg, tag=""):
        def _do():
            self.log.configure(state="normal")
            self.log.insert("end", msg + "\n", tag)
            self.log.see("end")
            self.log.configure(state="disabled")
        self.root.after(0, _do)

    def _set_status(self, text, color=SUBTEXT):
        def _do():
            self.status_lbl.configure(text=text, fg=color)
            self.status_dot.configure(fg=color)
        self.root.after(0, _do)

    def _update_progress(self):
        pct = (self.scanned_ports / self.total_ports * 100) if self.total_ports else 0
        elapsed = time.time() - self.start_time if self.start_time else 0
        rate = self.scanned_ports / elapsed if elapsed > 0 else 0

        def _do():
            self.progress_var.set(pct)
            self.progress_lbl.configure(
                text=f"{self.scanned_ports}/{self.total_ports} ports  |  "
                     f"{pct:.1f}%  |  {rate:.0f} ports/s  |  "
                     f"{elapsed:.1f}s elapsed")
        self.root.after(0, _do)

        # ── Port parser ───────────────────────────────────────────────────────────

    def _parse_ports(self, port_str):
        ports = []
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                ports.extend(range(int(a), int(b) + 1))
            else:
                ports.append(int(part))
        return sorted(set(p for p in ports if 1 <= p <= 65535))
    
 # ── Banner grabbing ───────────────────────────────────────────────────────

    def _grab_banner(self, ip, port, timeout):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in (80, 8080, 8000):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            s.close()
            return banner[:120] if banner else ""
        except Exception:
            return ""
        
 # ── Core port scan ────────────────────────────────────────────────────────

    def _scan_port(self, ip, port, timeout, grab_banners):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            service = COMMON_SERVICES.get(port, "Unknown")
            if result == 0:
                banner = self._grab_banner(ip, port, timeout) if grab_banners else ""
                with self.lock:
                    self.open_ports.append(port)
                self._add_result(port, service, "OPEN", banner)
                self._log(f"[OPEN] {port:>5}  {service:<20} {banner}", "open")
        except Exception:
            pass
        finally:
            with self.lock:
                self.scanned_ports += 1
            self._update_progress()

    def _add_result(self, port, service, status, banner=""):
        def _do():
            self.tree.insert("", "end",
                              values=(port, service, status, banner),
                              tags=("open" if status == "OPEN" else "closed",))
            self.tree.yview_moveto(1)
        self.root.after(0, _do)

 # ── Threading ─────────────────────────────────────────────────────────────

    def _worker(self, ip, timeout, grab_banners):
        while self.scanning:
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                break
            self._scan_port(ip, port, timeout, grab_banners)
            self.port_queue.task_done()

    def _run_scan(self, target, ip, ports, num_threads, timeout, grab_banners):
        self._log(f"Scan started: {target} ({ip})  –  {len(ports)} ports", "info")
        self.start_time = time.time()

        workers = []
        for _ in range(min(num_threads, len(ports))):
            t = threading.Thread(target=self._worker,
                                 args=(ip, timeout, grab_banners),
                                 daemon=True)
            t.start()
            workers.append(t)

        for t in workers:
            t.join()

        elapsed = time.time() - self.start_time

        def _done():
            self.scanning = False
            self.scan_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            found = sorted(self.open_ports)
            if found:
                self._log(f"Done in {elapsed:.2f}s  –  Open ports: {', '.join(map(str, found))}", "info")
                self._set_status(f"Done – {len(found)} open port(s)", PINK)
            else:
                self._log(f"Done in {elapsed:.2f}s  –  No open ports found.", "warn")
                self._set_status("Done – no open ports", YELLOW)

        self.root.after(0, _done)

    # ──────────────────────────────────────────── button actions ─────────────

    def _start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Missing Target", "Please enter a target host.")
            return

        try:
            timeout    = float(self.timeout_var.get())
            num_threads = int(self.threads_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Threads must be an integer and timeout a number.")
            return

        try:
            ports = self._parse_ports(self.ports_var.get())
        except ValueError:
            messagebox.showerror("Invalid Ports", "Use formats like: 80,443 or 1-1024")
            return

        if not ports:
            messagebox.showerror("No Ports", "No valid ports in range 1-65535.")
            return

        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            messagebox.showerror("Resolution Failed", f"Cannot resolve host: {target}")
            return

        self._clear(keep_config=True)
        self.open_ports = []
        self.scanned_ports = 0
        self.total_ports = len(ports)
        self.scanning = True
        self.progress_var.set(0)

        for p in ports:
            self.port_queue.put(p)

        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._set_status("Scanning…", ACCENT)

        if self.resolve_var.get() and target != ip:
            self._log(f"Resolved {target} → {ip}", "info")

        grab = self.banner_var.get()
        threading.Thread(target=self._run_scan,
                         args=(target, ip, ports, num_threads, timeout, grab),
                         daemon=True).start()

    def _stop_scan(self):
        self.scanning = False
        self._set_status("Stopped", RED)
        self._log("Scan stopped by user.", "warn")
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def _clear(self, keep_config=False):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self.progress_var.set(0)
        self.progress_lbl.configure(text="")
        self._set_status("Idle")
        if not keep_config:
            self.open_ports = []

    def _export_results(self):
        if not self.tree.get_children():
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("CSV", "*.csv"), ("All", "*.*")],
            title="Save scan results")
        if not path:
            return
        sep = "," if path.endswith(".csv") else "\t"
        with open(path, "w") as f:
            f.write(sep.join(["Port", "Service", "Status", "Banner"]) + "\n")
            for iid in self.tree.get_children():
                vals = self.tree.item(iid, "values")
                f.write(sep.join(str(v) for v in vals) + "\n")
        self._log(f"Results saved to: {path}", "info")
        messagebox.showinfo("Exported", f"Results saved to:\n{path}")

# ─────────────────────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()