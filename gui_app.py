#!/usr/bin/env python3
"""
CABS IT AUDITING TOOL -- GUI front-end for the existing audit engine.

This module owns NO audit logic. It is a controller: it collects User
Name / Lab / report-format selections from the user, then calls the
existing, unmodified main.run_audit() in a background thread and the
existing reporting/*.generate() functions on the single AuditReport that
run_audit() returns. See ARCHITECTURE.md / main.py for the actual audit
pipeline -- nothing about it changes here.

Threading contract: AuditWorker (a threading.Thread) never touches a
Tkinter widget directly. It only puts (kind, payload) tuples onto a
queue.Queue; the Tk main thread drains that queue via root.after() and
is the only thing that ever mutates widget state. This is the standard
safe pattern for keeping a Tk GUI responsive during long-running work.
"""

from __future__ import annotations

import os
import queue
import re
import socket
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

import branding
import main as audit_main
from reporting import csv_report, html_report, json_report, pdf_report
from utils.permissions import is_admin

_FORMAT_GENERATORS = {
    "json": ("JSON", json_report),
    "html": ("HTML", html_report),
    "csv": ("CSV", csv_report),
    "pdf": ("PDF", pdf_report),
}

# Friendly log labels for each collector_id in engine/rule_engine.py's
# COLLECTOR_REGISTRY. Purely cosmetic -- falls back to the raw id for any
# collector added later that isn't listed here, so this never goes stale
# in a way that breaks anything.
_COLLECTOR_LABELS = {
    "system": "System & Hardware",
    "users": "User Accounts",
    "authentication": "Authentication & Access Control",
    "security": "Windows Defender & Security",
    "firewall": "Windows Firewall",
    "network": "Network Configuration",
    "updates": "Windows Update",
    "services": "Windows Services",
    "processes": "Running Processes",
    "applications": "Installed Applications",
    "remote_access": "Remote Access (RDP)",
    "policies": "System Policies",
    "storage": "Storage & Shared Folders",
    "event_logs": "Event Logs",
    "devices": "Devices & Peripherals",
    "browser": "Browser Security",
    "backup": "Backup & Recovery",
}

_COLLECTOR_PROGRESS_SHARE = 90  # collectors fill 0-90%; report writes fill 90-100%


def _sanitize_for_filename(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", text).strip("_") or "UNKNOWN"


class AuditWorker(threading.Thread):
    """Runs exactly one real audit (main.run_audit -- never a mock) plus
    the selected report formats, all off the Tk main thread."""

    def __init__(self, user_name: str, lab: str, remarks: str, system_name: str,
                 formats: list[str], audit_start: datetime, event_queue: "queue.Queue"):
        super().__init__(daemon=True)
        self.user_name = user_name
        self.lab = lab
        self.remarks = remarks
        self.system_name = system_name
        self.formats = formats
        self.audit_start = audit_start
        self.queue = event_queue

    def _emit(self, kind: str, payload=None) -> None:
        self.queue.put((kind, payload))

    def _on_collector_progress(self, index: int, total: int, collector_id: str) -> None:
        label = _COLLECTOR_LABELS.get(collector_id, collector_id)
        self._emit("log", f"Checking {label}...")
        percent = int((index - 1) / total * _COLLECTOR_PROGRESS_SHARE) if total else 0
        self._emit("progress", percent)

    def run(self) -> None:
        try:
            self._emit("log", "Audit started.")
            if not is_admin():
                self._emit(
                    "log",
                    "NOTE: not running as Administrator -- checks requiring elevation will be "
                    "reported as UNABLE_TO_COLLECT rather than skipped silently.",
                )

            report = audit_main.run_audit(
                str(audit_main.DEFAULT_RULES_PATH),
                str(audit_main.DEFAULT_SEVERITY_CONFIG_PATH),
                user_name=self.user_name,
                lab=self.lab,
                remarks=self.remarks or None,
                audit_start=self.audit_start,
                progress_callback=self._on_collector_progress,
            )
            report.application = branding.APP_NAME
            report.organization = branding.ORGANIZATION
            report.location = branding.LOCATION
            report.ministry = branding.MINISTRY

            self._emit("progress", _COLLECTOR_PROGRESS_SHARE)
            self._emit("log", "Audit checks completed.")
            self._emit("log", "Collecting audit results...")

            output_dir = audit_main.DEFAULT_OUTPUT_DIR
            output_dir.mkdir(parents=True, exist_ok=True)
            stamp = report.generated_at.strftime("%Y%m%d_%H%M%S")
            safe_system = _sanitize_for_filename(self.system_name)

            written_paths: dict[str, Path] = {}
            format_errors: dict[str, str] = {}
            remaining_share = 100 - _COLLECTOR_PROGRESS_SHARE
            step = remaining_share / max(len(self.formats), 1)
            progress = float(_COLLECTOR_PROGRESS_SHARE)

            for fmt in self.formats:
                label, module = _FORMAT_GENERATORS[fmt]
                self._emit("log", f"Generating {label} report...")
                path = output_dir / f"CABS_DRDO_AUDITOR_{safe_system}_{stamp}.{fmt}"
                try:
                    module.generate(report, path)
                    written_paths[fmt] = path
                except Exception as e:  # noqa: BLE001 -- one format failing must not stop the others
                    format_errors[fmt] = str(e)
                    self._emit("log", f"ERROR generating {label} report: {e}")
                progress += step
                self._emit("progress", min(int(progress), 100))

            self._emit("progress", 100)
            if format_errors:
                self._emit("log", "Reports generated with errors -- see above.")
            else:
                self._emit("log", "Reports generated successfully.")
            self._emit("log", "Audit completed successfully.")

            self._emit("done", {
                "report": report,
                "written_paths": written_paths,
                "format_errors": format_errors,
                "output_dir": output_dir,
            })
        except Exception as e:  # noqa: BLE001 -- must reach the GUI, never crash silently
            self._emit("log", f"ERROR: audit failed: {e}")
            self._emit("error", str(e))


class CabsDrdoAuditorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.event_queue: "queue.Queue" = queue.Queue()
        self.worker: AuditWorker | None = None
        self.last_output_dir: Path | None = None
        self.audit_running = False
        self.admin_warning_shown = False

        self.system_name = self._detect_system_name()

        self._build_window()
        self._build_widgets()
        self._log(f"Application started.")
        self._log(f"System detected: {self.system_name}")

    # ---- setup ---------------------------------------------------------

    def _detect_system_name(self) -> str:
        # socket.gethostname() is the same source main.py already uses for
        # AuditReport.host_name -- using it here too means the GUI display
        # and every generated report can never disagree about the system
        # name. Equivalent to Win32_ComputerSystem.Name for the local
        # machine, without the cost of spawning powershell.exe just to
        # populate a GUI field.
        try:
            name = socket.gethostname()
            return name if name else "UNKNOWN"
        except Exception:
            return "UNKNOWN"

    def _build_window(self) -> None:
        self.root.title(f"\U0001F6E1 {branding.APP_NAME}")
        # Sized to comfortably fit within a 1366x768 laptop screen (the
        # common corporate baseline) after OS taskbar/title chrome --
        # not just whatever fits this dev machine's display.
        self.root.geometry("860x700")
        self.root.minsize(800, 620)
        self.root.configure(bg="#ffffff")

        icon_path = branding.get_icon_path()
        if icon_path is not None:
            try:
                self.root.iconbitmap(str(icon_path))
            except Exception:
                pass  # cosmetic only -- never block startup over a missing/bad icon

        self.font_family = "Segoe UI" if "Segoe UI" in tkfont.families(self.root) else "Arial"

    # ---- widgets ---------------------------------------------------------

    def _build_widgets(self) -> None:
        self._build_banner()

        content = tk.Frame(self.root, bg="#ffffff", padx=20, pady=14)
        content.pack(fill="both", expand=True)

        # Packed bottom-up first so Buttons and Results stay visible at the
        # bottom of the window at ANY window height -- only the status log
        # (packed last, with expand=True) grows or shrinks to fill
        # whatever space remains above them. Without this, a modest
        # default window size pushes the Start/Exit buttons off-screen
        # entirely, forcing a manual resize just to find them.
        self._build_buttons(content)
        self._build_results(content)
        self._build_audit_info(content)
        self._build_formats(content)
        self._build_progress(content)
        self._build_log(content)

    def _build_banner(self) -> None:
        banner = tk.Frame(self.root, bg=branding.NAVY_BLUE, padx=18, pady=8)
        banner.pack(fill="x")

        logo_path = branding.get_logo_path()
        if logo_path is not None:
            try:
                self._logo_image = tk.PhotoImage(file=str(logo_path))
                if self._logo_image.width() > 46:
                    factor = max(1, self._logo_image.width() // 46)
                    self._logo_image = self._logo_image.subsample(factor, factor)
                tk.Label(banner, image=self._logo_image, bg=branding.NAVY_BLUE).pack(side="left", padx=(0, 14))
            except Exception:
                pass  # cosmetic only

        text_frame = tk.Frame(banner, bg=branding.NAVY_BLUE)
        text_frame.pack(side="left", fill="x", expand=True)
        tk.Label(
            text_frame, text=f"\U0001F6E1 {branding.APP_NAME}", fg="#ffffff", bg=branding.NAVY_BLUE,
            font=(self.font_family, 15, "bold"),
        ).pack(anchor="w")
        tk.Label(
            text_frame, text=branding.ORGANIZATION, fg="#c9d6f0", bg=branding.NAVY_BLUE,
            font=(self.font_family, 10, "bold"),
        ).pack(anchor="w")

    def _labelframe(self, parent, text) -> tk.LabelFrame:
        return tk.LabelFrame(
            parent, text=text, bg="#ffffff", fg=branding.NAVY_BLUE,
            font=(self.font_family, 9, "bold"), padx=10, pady=5, bd=1, relief="solid",
        )

    def _build_audit_info(self, parent) -> None:
        frame = self._labelframe(parent, "AUDIT INFORMATION")
        frame.pack(fill="x", pady=(0, 6))
        frame.columnconfigure(1, weight=1)

        entry_font = (self.font_family, 10)

        tk.Label(frame, text="User Name:", bg="#ffffff", font=entry_font).grid(row=0, column=0, sticky="w", pady=2)
        self.user_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.user_var, font=entry_font).grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=2)

        tk.Label(frame, text="Lab:", bg="#ffffff", font=entry_font).grid(row=1, column=0, sticky="w", pady=2)
        self.lab_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.lab_var, font=entry_font).grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=2)

        tk.Label(frame, text="System Name:", bg="#ffffff", font=entry_font).grid(row=2, column=0, sticky="w", pady=2)
        tk.Entry(frame, textvariable=tk.StringVar(value=self.system_name), font=entry_font,
                 state="readonly").grid(row=2, column=1, sticky="ew", padx=(8, 0), pady=2)

        tk.Label(frame, text="Remarks:", bg="#ffffff", font=entry_font).grid(row=3, column=0, sticky="w", pady=2)
        self.remarks_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.remarks_var, font=entry_font).grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=2)

        tk.Label(frame, text="Audit Start:", bg="#ffffff", font=entry_font).grid(row=4, column=0, sticky="w", pady=2)
        self.audit_start_var = tk.StringVar(value="Will be populated when audit starts")
        tk.Entry(frame, textvariable=self.audit_start_var, font=entry_font,
                 state="readonly").grid(row=4, column=1, sticky="ew", padx=(8, 0), pady=2)

    def _build_formats(self, parent) -> None:
        frame = self._labelframe(parent, "REPORT FORMATS")
        frame.pack(fill="x", pady=(0, 6))

        self.format_vars = {fmt: tk.BooleanVar(value=True) for fmt in _FORMAT_GENERATORS}
        cb_font = (self.font_family, 10)
        for i, (fmt, (label, _mod)) in enumerate(_FORMAT_GENERATORS.items()):
            tk.Checkbutton(
                frame, text=label, variable=self.format_vars[fmt], bg="#ffffff", font=cb_font,
                anchor="w",
            ).grid(row=0, column=i, sticky="w", padx=(0, 28), pady=0)

    def _build_progress(self, parent) -> None:
        frame = self._labelframe(parent, "AUDIT PROGRESS")
        frame.pack(fill="x", pady=(0, 6))

        row = tk.Frame(frame, bg="#ffffff")
        row.pack(fill="x")
        self.progress_var = tk.IntVar(value=0)
        self.progress_bar = ttk.Progressbar(row, orient="horizontal", mode="determinate",
                                             maximum=100, variable=self.progress_var)
        self.progress_bar.pack(side="left", fill="x", expand=True)

        self.progress_label = tk.Label(row, text="0%", bg="#ffffff", font=(self.font_family, 9), width=5)
        self.progress_label.pack(side="left", padx=(8, 0))

    def _build_log(self, parent) -> None:
        frame = self._labelframe(parent, "STATUS LOG")
        frame.pack(fill="both", expand=True, pady=(0, 6))

        text_frame = tk.Frame(frame)
        text_frame.pack(fill="both", expand=True)
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")
        self.log_text = tk.Text(
            text_frame, height=4, state="disabled", bg="#0f1720", fg="#d7e3f4",
            insertbackground="#ffffff", font=("Consolas", 9), wrap="word",
            yscrollcommand=scrollbar.set,
        )
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.log_text.yview)

    def _build_results(self, parent) -> None:
        frame = self._labelframe(parent, "AUDIT RESULTS")
        frame.pack(side="bottom", fill="x", pady=(0, 6))
        self.results_label = tk.Label(
            frame, text="Waiting to start audit...", bg="#ffffff", fg="#57606a",
            font=(self.font_family, 10), justify="left", anchor="w",
        )
        self.results_label.pack(fill="x")

    def _build_buttons(self, parent) -> None:
        frame = tk.Frame(parent, bg="#ffffff")
        frame.pack(side="bottom", fill="x", pady=(4, 0))

        btn_font = (self.font_family, 10, "bold")
        self.start_btn = tk.Button(
            frame, text="▶ START AUDIT", command=self._on_start_clicked,
            bg=branding.NAVY_BLUE, fg="#ffffff", activebackground="#003080", activeforeground="#ffffff",
            font=btn_font, padx=16, pady=8, relief="flat",
        )
        self.start_btn.pack(side="left", padx=(0, 10))

        self.open_folder_btn = tk.Button(
            frame, text="\U0001F4C1 OPEN REPORTS FOLDER", command=self._on_open_reports_folder,
            state="disabled", font=btn_font, padx=16, pady=8, relief="flat",
        )
        self.open_folder_btn.pack(side="left", padx=(0, 10))

        self.exit_btn = tk.Button(
            frame, text="EXIT", command=self._on_exit, font=btn_font, padx=16, pady=8, relief="flat",
        )
        self.exit_btn.pack(side="left")

    # ---- logging / helpers ------------------------------------------------

    def _log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _set_progress(self, percent: int) -> None:
        percent = max(0, min(100, percent))
        self.progress_var.set(percent)
        self.progress_label.configure(text=f"{percent}%")

    def _set_results(self, text: str, color: str) -> None:
        self.results_label.configure(text=text, fg=color)

    # ---- validation + start ------------------------------------------------

    def _validate(self) -> str | None:
        if not self.user_var.get().strip():
            return "Please enter User Name."
        if not self.lab_var.get().strip():
            return "Please enter Lab."
        if not any(v.get() for v in self.format_vars.values()):
            return "Please select at least one report format."
        if not self.system_name or self.system_name == "UNKNOWN":
            return "System Name could not be detected. Cannot start audit."
        return None

    def _on_start_clicked(self) -> None:
        if self.audit_running:
            return  # guard against double-click / re-entry

        error = self._validate()
        if error:
            messagebox.showerror(branding.APP_NAME, error)
            return

        if not is_admin() and not self.admin_warning_shown:
            self.admin_warning_shown = True
            messagebox.showwarning(
                branding.APP_NAME,
                "This application is not running as Administrator. Some audit checks may "
                "require elevated privileges and may be reported as UNABLE_TO_COLLECT. "
                "Please run the application as Administrator for complete audit results.",
            )

        user_name = self.user_var.get().strip()
        lab = self.lab_var.get().strip()
        remarks = self.remarks_var.get().strip()
        formats = [fmt for fmt, var in self.format_vars.items() if var.get()]
        audit_start = datetime.now()

        self.audit_start_var.set(audit_start.strftime("%Y-%m-%d %H:%M:%S"))
        self._set_progress(0)
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._set_results("Audit in progress...", "#9a6700")
        self._log("Audit started.")

        self.audit_running = True
        self.start_btn.configure(state="disabled")
        self.open_folder_btn.configure(state="disabled")
        self.exit_btn.configure(state="disabled")

        self.event_queue = queue.Queue()
        self.worker = AuditWorker(user_name, lab, remarks, self.system_name, formats, audit_start, self.event_queue)
        self.worker.start()
        self.root.after(100, self._poll_queue)

    # ---- worker -> GUI event pump ------------------------------------------

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "progress":
                    self._set_progress(payload)
                elif kind == "done":
                    self._on_audit_done(payload)
                elif kind == "error":
                    self._on_audit_error(payload)
        except queue.Empty:
            pass

        if self.audit_running:
            self.root.after(100, self._poll_queue)

    def _on_audit_done(self, payload: dict) -> None:
        self.audit_running = False
        self.start_btn.configure(state="normal")
        self.exit_btn.configure(state="normal")

        report = payload["report"]
        written_paths = payload["written_paths"]
        format_errors = payload["format_errors"]
        self.last_output_dir = payload["output_dir"]

        counts = (report.scoring or {}).get("counts", {})
        summary = (
            f"Checks Passed: {counts.get('passed', '?')}   "
            f"Warnings: {counts.get('warnings', '?')}   "
            f"Failed: {counts.get('failed', '?')}"
        )

        if format_errors and not written_paths:
            self._set_results(f"Report generation failed.\n{summary}", "#cf222e")
        elif format_errors:
            failed_fmts = ", ".join(format_errors)
            self._set_results(
                f"Audit completed. Some reports failed ({failed_fmts}).\n{summary}", "#9a6700",
            )
        else:
            self._set_results(f"Audit completed successfully. Reports generated.\n{summary}", "#1a7f37")

        if written_paths:
            self.open_folder_btn.configure(state="normal")

    def _on_audit_error(self, error_message: str) -> None:
        self.audit_running = False
        self.start_btn.configure(state="normal")
        self.exit_btn.configure(state="normal")
        self._set_results(f"Audit failed: {error_message}", "#cf222e")
        messagebox.showerror(branding.APP_NAME, f"Audit failed:\n{error_message}")

    # ---- remaining buttons ------------------------------------------------

    def _on_open_reports_folder(self) -> None:
        target = self.last_output_dir or audit_main.DEFAULT_OUTPUT_DIR
        try:
            os.startfile(str(target))  # noqa: S606 -- Windows-only app, this is the standard API for it
        except Exception as e:
            messagebox.showerror(branding.APP_NAME, f"Could not open reports folder:\n{e}")

    def _on_exit(self) -> None:
        if self.audit_running:
            return  # EXIT is disabled during a running audit; extra guard just in case
        self.root.destroy()


def main() -> int:
    root = tk.Tk()
    CabsDrdoAuditorApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
