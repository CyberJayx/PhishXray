
"""
PhishXray - Cyber Security Forensic Desktop Triage Interface.
Designed for Tier-2 SOC operations to visually parse and isolate email threat vectors.
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
import re
import json

class PhishXrayUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishXray Core - SecOps Forensic Triage")
        self.root.geometry("850x650")
        self.root.configure(bg="#121824")  # Deep cyber security dark theme

        # --- Top Header ---
        header = tk.Label(
            self.root, 
            text="PHISHXRAY: AUTOMATED FORENSIC HEADER PARSER", 
            font=("Arial", 14, "bold"), 
            bg="#1b2234", 
            fg="#00ffcc", 
            pady=10
        )
        header.pack(fill=tk.X)

        # --- Main Layout Splitter ---
        main_frame = tk.Frame(self.root, bg="#121824", padx=15, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Left Column: Input Box
        left_frame = tk.Frame(main_frame, bg="#121824")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        input_label = tk.Label(left_frame, text="Paste Raw Email Text / Header Payload Here:", font=("Arial", 11, "bold"), bg="#121824", fg="#ffffff")
        input_label.pack(anchor=tk.W, pady=(0, 5))

        self.input_area = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD, width=45, height=25, bg="#1b2234", fg="#ffffff", insertbackground="white", font=("Courier", 10))
        self.input_area.pack(fill=tk.BOTH, expand=True)

        # Populate with an interactive, ready-to-test attack template right out of the box
        default_mock_data = (
            "From: Security Alert <spoofed-login@secure-bank-update.xyz>\n"
            "To: target-victim@enterprise.com\n"
            "Subject: CRITICAL: Immediate Password Reset Required\n"
            "Return-Path: <attacker-mailbox@c2-server.net>\n"
            "Authentication-Results: spf=fail dmarc=fail\n\n"
            "Please log into our database tracking terminal immediately to update your credentials:\n"
            "http://malicious-credential-harvest-login.com/auth/login"
        )
        self.input_area.insert(tk.END, default_mock_data)

        # Right Column: Visual Findings
        right_frame = tk.Frame(main_frame, bg="#121824")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))

        output_label = tk.Label(right_frame, text="Automated Forensic Report:", font=("Arial", 11, "bold"), bg="#121824", fg="#ffffff")
        output_label.pack(anchor=tk.W, pady=(0, 5))

        self.output_area = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, width=45, height=25, bg="#1b2234", fg="#00ffcc", font=("Courier", 10))
        self.output_area.pack(fill=tk.BOTH, expand=True)
        self.output_area.insert(tk.END, "[*] Waiting for forensic analysis submission...")

        # --- Control Action Buttons Bar ---
        btn_frame = tk.Frame(self.root, bg="#1b2234", pady=12)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        analyze_btn = tk.Button(btn_frame, text="RUN FORENSIC X-RAY", command=self.execute_forensic_analysis, bg="#00ffcc", fg="#121824", font=("Arial", 11, "bold"), activebackground="#00cc99", padx=20)
        analyze_btn.pack(side=tk.LEFT, padx=20)

        clear_btn = tk.Button(btn_frame, text="Clear Window", command=self.clear_fields, bg="#3a4766", fg="#ffffff", font=("Arial", 10), activebackground="#2d374f", padx=15)
        clear_btn.pack(side=tk.RIGHT, padx=20)

    def clear_fields(self):
        self.input_area.delete("1.0", tk.END)
        self.output_area.delete("1.0", tk.END)
        self.output_area.insert(tk.END, "[*] Interface cleared. Ready for next asset deployment.")

    def execute_forensic_analysis(self):
        raw_text = self.input_area.get("1.0", tk.END).strip()
        if not raw_text:
            messagebox.showwarning("Execution Error", "Please paste an email payload to scan.")
            return

        # Simple, high-speed heuristic parsing rules
        sender = re.search(r"From:\s*(.*)", raw_text, re.IGNORECASE)
        recipient = re.search(r"To:\s*(.*)", raw_text, re.IGNORECASE)
        subject = re.search(r"Subject:\s*(.*)", raw_text, re.IGNORECASE)
        return_path = re.search(r"Return-Path:\s*<(.*)>", raw_text, re.IGNORECASE)
        
        # Pull defensive authentication checks
        spf_fail = "spf=fail" in raw_text.lower()
        dmarc_fail = "dmarc=fail" in raw_text.lower()
        
        # Extract embedded target URLs
        urls = re.findall(r'https?://[^\s<>"]+', raw_text)

        # Risk scoring logic
        risk_score = 0
        reasons = []

        if spf_fail:
            risk_score += 35
            reasons.append("- Cryptographic Boundary Failure: SPF Record verification failed.")
        if dmarc_fail:
            risk_score += 35
            reasons.append("- Cryptographic Boundary Failure: DMARC Policy enforcement mismatch.")
        
        # Check spoofing envelope anomalies
        if sender and return_path:
            sender_domain = sender.group(1)
            return_domain = return_path.group(1)
            # Simple check if the sender string domain matches return path
            if return_domain.split('@')[-1] not in sender_domain:
                risk_score += 20
                reasons.append("- Spoofing Indicator: Visible 'From' domain differs from actual tracking 'Return-Path'.")

        if len(urls) > 0:
            risk_score += 10
            reasons.append(f"- Payload Link Density: Found {len(urls)} active URLs inside body content.")

        # Establish Threat Rating Verdict
        verdict = "BENIGN (Low Risk Configuration)"
        if risk_score >= 65:
            verdict = "CRITICAL / MALICIOUS PHISHING ATTEMPT"
        elif risk_score >= 30:
            verdict = "SUSPICIOUS PROFILE / HIGH RISK INDICATORS"

        # Build clean visual report
        report = []
        report.append("==================================================")
        report.append(f"          PHISHXRAY INCIDENT VERDICT: \n  {verdict}")
        report.append("==================================================")
        report.append(f"\n[+] Cumulative Threat Score: {risk_score}/100")
        report.append(f"[+] Isolated Links Discovered: {len(urls)}")
        for u in urls[:3]:
            report.append(f"    -> Target URL: {u}")
            
        report.append("\n[+] Envelope Metadata Matrix:")
        report.append(f"    From:    {sender.group(1) if sender else 'Unknown'}")
        report.append(f"    To:      {recipient.group(1) if recipient else 'Unknown'}")
        report.append(f"    Subject: {subject.group(1) if subject else 'No Subject'}")
        
        if len(reasons) > 0:
            report.append("\n[!] Triggered Risk Identifiers:")
            for reason in reasons:
                report.append(reason)
        else:
            report.append("\n[+] No immediate heuristic risk behaviors flagged.")

        # Output to screen interface
        self.output_area.delete("1.0", tk.END)
        self.output_area.insert(tk.END, "\n".join(report))

if __name__ == "__main__":
    app_window = tk.Tk()
    engine = PhishXrayUI(app_window)
    app_window.mainloop()
