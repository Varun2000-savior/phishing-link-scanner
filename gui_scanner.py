import tldextract
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import time
import threading
import base64
import requests

# === VIRUSTOTAL CONFIG ===
VT_API_KEY = "edb168a21f061562e58e5b8ef74eebb3f1afaa17f180f5aa1492c30919baba7e"
VT_HEADERS = {
    "x-apikey": VT_API_KEY
}

# === SCAN FUNCTIONS ===
def check_domain_impersonation(url):
    suspicious_domains = ["paypa1.com", "micros0ft.com", "faceb00k.com"]
    domain = tldextract.extract(url).registered_domain
    return "Suspicious" if domain in suspicious_domains else "Clean"

def analyze_keywords(url):
    bad_keywords = ["login", "secure", "update", "verify"]
    return "Suspicious" if any(word in url.lower() for word in bad_keywords) else "Clean"

def score_threat(url):
    score = 0
    if "@" in url or "//" in url: score += 1
    if any(k in url.lower() for k in ["login", "secure", "update"]): score += 1
    return "High" if score >= 2 else "Medium" if score == 1 else "Low"

def virustotal_lookup(url):
    try:
        # Submit URL
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=VT_HEADERS, data={"url": url})
        if response.status_code != 200:
            return ("Error", "Unable to submit URL to VirusTotal")

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=VT_HEADERS)
        if report.status_code != 200:
            return ("Error", "Unable to retrieve VirusTotal results")

        data = report.json()
        malicious = data['data']['attributes']['last_analysis_stats']['malicious']
        suspicious = data['data']['attributes']['last_analysis_stats']['suspicious']
        harmless = data['data']['attributes']['last_analysis_stats']['harmless']
        category = data['data']['attributes'].get('categories', {}).get('urlscan', 'Unknown')

        if malicious > 0:
            verdict = "Malicious"
        elif suspicious > 0:
            verdict = "Suspicious"
        else:
            verdict = "Clean"

        summary = f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}"        
        return (verdict, f"{summary} | Category: {category}")

    except Exception as e:
        return ("Error", str(e))

# === SAFETY PRECAUTIONS & AFTER-EFFECTS TEXT ===
def get_safety_precautions(verdict):
    if verdict == "Malicious":
        return (
            "⚠️ This link is confirmed malicious.\n"
            "- Do NOT click the link.\n"
            "- Clear your browser cache and cookies immediately.\n"
            "- Run a full antivirus scan on your system.\n"
            "- Change passwords if you entered any credentials.\n"
            "- Report the link to your security team or provider."
        )
    elif verdict == "Suspicious":
        return (
            "⚠️ This link is suspicious and may be harmful.\n"
            "- Avoid clicking unless you trust the source.\n"
            "- Use a sandbox or isolated environment to check the link.\n"
            "- Keep your antivirus and software up to date.\n"
            "- Monitor your accounts for unusual activity."
        )
    else:
        return (
            "✅ The link appears clean.\n"
            "- Still be cautious and verify URLs before clicking.\n"
            "- Use multi-factor authentication for your accounts.\n"
            "- Regularly update your browser and security software."
        )

# === GLOBALS ===
title_emojis = ["🔍", "⏳", "⌛", "🔎"]
title_index = 0
flash_on = True
scanning = False
pulse_increasing = True
pulse_alpha = 0.5
loader_frames = ["⏳", "⌛", "🕐", "🕑", "🕒", "🕓", "🕔", "🕕"]
loader_index = 0

# === ANIMATIONS ===
def animate_title():
    global title_index
    if scanning:
        app.title(f"{title_emojis[title_index]} Scanning...")
        title_index = (title_index + 1) % len(title_emojis)
    else:
        app.title("✅ Scan Complete - Phishing Link Scanner")
    app.after(500, animate_title)

def flash_status():
    global flash_on
    if scanning:
        status_label.config(foreground="yellow" if flash_on else "orange")
        flash_on = not flash_on
        app.after(600, flash_status)
    else:
        status_label.config(foreground="lightgreen")

def progressbar_update(value=0):
    if scanning:
        value = (value + 5) % 105
        progressbar["value"] = value
        app.after(100, progressbar_update, value)
    else:
        progressbar["value"] = 0

def pulse_status():
    global pulse_increasing, pulse_alpha
    if scanning:
        pulse_alpha += 0.05 if pulse_increasing else -0.05
        if pulse_alpha >= 1.0:
            pulse_alpha = 1.0
            pulse_increasing = False
        elif pulse_alpha <= 0.5:
            pulse_alpha = 0.5
            pulse_increasing = True
        intensity = int(255 * pulse_alpha)
        color = f"#{intensity:02x}{intensity:02x}00"
        status_label.config(foreground=color)
        app.after(100, pulse_status)
    else:
        status_label.config(foreground="lightgreen")

def animate_loader():
    global loader_index
    if scanning:
        loader_label.config(text=loader_frames[loader_index])
        loader_index = (loader_index + 1) % len(loader_frames)
        app.after(150, animate_loader)
    else:
        loader_label.config(text="")

def animate_result_rows(rows, index=0):
    if index < len(rows):
        iid = rows[index]
        result_table.tag_configure("fade", foreground="#ffffff")
        result_table.item(iid, tags=("fade",))
        app.after(300, animate_result_rows, rows, index + 1)

# === MAIN SCAN LOGIC ===
def scan_logic(url):
    global scanning
    scanning = True
    progressbar.pack(pady=10)
    status_label.config(text="🔍 Scanning...", foreground="yellow")
    progressbar["value"] = 0
    app.title("🔍 Scanning...")

    animate_title()
    pulse_status()
    progressbar_update()
    animate_loader()

    time.sleep(2)  # Simulated scanning time

    domain_result = check_domain_impersonation(url)
    keyword_result = analyze_keywords(url)
    threat_result = score_threat(url)
    vt_verdict, vt_details = virustotal_lookup(url)

    result_table.delete(*result_table.get_children())
    rows = []
    rows.append(result_table.insert("", "end", values=("🧪 Domain Check", domain_result)))
    rows.append(result_table.insert("", "end", values=("🧠 Keyword Analysis", keyword_result)))
    rows.append(result_table.insert("", "end", values=("⚠️ Threat Score", threat_result)))
    rows.append(result_table.insert("", "end", values=("🛰️ VirusTotal Verdict", vt_verdict)))
    rows.append(result_table.insert("", "end", values=("🗂️ VT Details", vt_details)))

    # Show safety precautions text based on verdict
    safety_text = get_safety_precautions(vt_verdict)
    safety_textbox.config(state="normal")
    safety_textbox.delete("1.0", "end")
    safety_textbox.insert("end", safety_text)
    safety_textbox.config(state="disabled")

    scanning = False
    progressbar.pack_forget()
    status_label.config(text="✅ Scan Complete!", foreground="lightgreen")
    app.title("✅ Scan Complete - Phishing Link Scanner")
    animate_result_rows(rows)

# === GUI TRIGGER ===
def scan_url():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL")
        return
    result_table.delete(*result_table.get_children())
    safety_textbox.config(state="normal")
    safety_textbox.delete("1.0", "end")
    safety_textbox.config(state="disabled")
    threading.Thread(target=scan_logic, args=(url,), daemon=True).start()

def on_enter(e):
    scan_btn.configure(bootstyle="success")

def on_leave(e):
    scan_btn.configure(bootstyle="success-outline")

# === GUI SETUP ===
app = ttk.Window(themename="cyborg")
app.title("🔒 Phishing Link Scanner")
app.geometry("620x600")
app.resizable(True, True)  # Allow resizing

ttk.Label(app, text="🔐 Phishing Link Scanner", font=("Segoe UI", 16, "bold")).pack(pady=10)
entry_frame = ttk.Frame(app, bootstyle="dark")
entry_frame.pack(pady=5, fill="x", padx=10)
url_entry = ttk.Entry(entry_frame, width=70, font=("Segoe UI", 12))
url_entry.pack(padx=10, pady=5, fill="x")

scan_btn = ttk.Button(app, text="🔎 Scan Now", command=scan_url, bootstyle="success-outline")
scan_btn.pack(pady=10)
scan_btn.bind("<Enter>", on_enter)
scan_btn.bind("<Leave>", on_leave)

progressbar = ttk.Progressbar(app, mode="determinate", bootstyle="info", maximum=100)
progressbar.pack_forget()

loader_label = ttk.Label(app, text="", font=("Segoe UI", 20))
loader_label.pack()

status_label = ttk.Label(app, text="", font=("Segoe UI", 12))
status_label.pack(pady=5)

result_table = ttk.Treeview(app, columns=("Check", "Result"), show="headings", height=7, bootstyle="dark")
result_table.heading("Check", text="Check Performed")
result_table.heading("Result", text="Result")
result_table.column("Check", width=200, anchor="w")
result_table.column("Result", width=380, anchor="w")
result_table.pack(pady=20, fill="both", expand=True, padx=10)

ttk.Label(app, text="Safety Precautions & After Effects", font=("Segoe UI", 13, "bold")).pack(pady=(10, 0))
safety_textbox = ttk.Text(app, height=7, font=("Segoe UI", 11), wrap="word")
safety_textbox.pack(padx=10, pady=5, fill="both", expand=True)
safety_textbox.config(state="disabled", bg="#222222", fg="lightgray")

app.mainloop()
