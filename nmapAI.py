#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, re, time, subprocess, sqlite3, textwrap
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

# ===================== XỬ LÝ IMPORT ĐỘNG =====================
MISSING_MODULES = []

def safe_import(module_name, pip_name=None):
    try:
        return __import__(module_name)
    except ImportError:
        MISSING_MODULES.append(pip_name or module_name)
        return None

colorama = safe_import("colorama", "colorama")
if colorama:
    from colorama import Fore, Style, init
    init(autoreset=True)
else:
    class Fore: RED=GREEN=YELLOW=BLUE=CYAN=MAGENTA=WHITE=RESET=""
    class Style: BRIGHT=RESET_ALL=""

dotenv = safe_import("dotenv", "python-dotenv")
if dotenv:
    from dotenv import load_dotenv
    load_dotenv()
else:
    def load_dotenv(): pass

openai_mod = safe_import("openai", "openai")
nmap_mod = safe_import("nmap", "python-nmap")
cryptography_fernet = safe_import("cryptography.fernet", "cryptography")
if cryptography_fernet:
    from cryptography.fernet import Fernet
else:
    Fernet = None

requests_mod = safe_import("requests", "requests")  # Dùng cho Telegram

# Reportlab chỉ dùng nếu xuất PDF
reportlab = None
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    reportlab = True
except ImportError:
    reportlab = False

if MISSING_MODULES:
    print(Fore.RED + "Thiếu các gói sau, cài bằng lệnh:")
    print("pip install " + " ".join(MISSING_MODULES))
    print("Sau đó chạy lại (nếu không cần Telegram, có thể bỏ qua requests).")
    # Không thoát, vì requests có thể không bắt buộc nếu không dùng Telegram
    # Chỉ cảnh báo
    # sys.exit(1)  # Bỏ comment nếu muốn bắt buộc

# ===================== CẤU HÌNH FILE =====================
CONFIG_FILE = os.path.expanduser("~/.ai_nmap_pro_config.json")
KEY_FILE = os.path.expanduser("~/.ai_nmap_pro_key.key")
DB_PATH = os.path.expanduser("~/.ai_nmap_scans.db")
VERSION = "3.1.0"
GITHUB_VERSION_URL = "https://raw.githubusercontent.com/yourusername/ai_nmap_pro/main/version.json"

# ===================== QUẢN LÝ KEY / MÃ HOÁ =====================
def generate_key():
    if Fernet:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key
    return None

def load_key():
    if not Fernet:
        return None
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    return generate_key()

def encrypt(data: str) -> str:
    if not Fernet:
        return data
    f = Fernet(load_key())
    return f.encrypt(data.encode()).decode()

def decrypt(token: str) -> str:
    if not Fernet:
        return token
    f = Fernet(load_key())
    return f.decrypt(token.encode()).decode()

# ===================== CONFIG =====================
class Config:
    def __init__(self, path=CONFIG_FILE):
        self.path = path
        self.defaults = {
            "output_dir": os.path.expanduser("~/nmap_scans"),
            "timeout": 300,
            "model": "gpt-3.5-turbo",
            "num_commands": 4,
            "api_key_enc": "",
            "schedule_enabled": False,
            "schedule_interval_hours": 24,
            "schedule_targets": [],
            "telegram_bot_token_enc": "",
            "telegram_chat_id": "",
            "telegram_enabled": False
        }
        self.data = self.load()

    def load(self):
        if os.path.exists(self.path):
            with open(self.path, "r") as f:
                user = json.load(f)
                return {**self.defaults, **user}
        return self.defaults.copy()

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)

    def get(self, key):
        return self.data.get(key, self.defaults.get(key))

    def set(self, key, value):
        self.data[key] = value
        self.save()

    def get_api_key(self):
        env_key = os.getenv("OPENAI_API_KEY")
        if env_key:
            return env_key
        enc = self.data.get("api_key_enc")
        if enc:
            return decrypt(enc)
        return ""

    def set_api_key(self, key):
        self.data["api_key_enc"] = encrypt(key)
        self.save()

    def get_telegram_token(self):
        enc = self.data.get("telegram_bot_token_enc")
        if enc:
            return decrypt(enc)
        return ""

    def set_telegram_token(self, token):
        self.data["telegram_bot_token_enc"] = encrypt(token)
        self.save()

# ===================== DATABASE =====================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  target TEXT NOT NULL,
                  timestamp TEXT NOT NULL,
                  commands TEXT NOT NULL,
                  results_json TEXT,
                  report_files TEXT)''')
    conn.commit()
    conn.close()

def add_scan(target, commands, results_dict, report_files):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO scans (target, timestamp, commands, results_json, report_files) VALUES (?, ?, ?, ?, ?)",
              (target, datetime.now().isoformat(), json.dumps(commands), json.dumps(results_dict), json.dumps(report_files)))
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id

def get_all_scans():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, target, timestamp FROM scans ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return rows

def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "id": row[0], "target": row[1], "timestamp": row[2],
            "commands": json.loads(row[3]), "results": json.loads(row[4]),
            "report_files": json.loads(row[5])
        }
    return None

def delete_scan(scan_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()

# ===================== AI ADVISOR =====================
class AINmapAdvisor:
    def __init__(self, api_key, model="gpt-3.5-turbo"):
        self.client = openai_mod.OpenAI(api_key=api_key)
        self.model = model
        self.cache = {}

    def suggest_commands(self, target, hint="", num=4):
        cache_key = f"{target}|{hint}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        prompt = f"""You are a cybersecurity expert. Suggest {num} useful nmap commands to scan target: {target}.
User hint: "{hint}"
Return only commands, one per line, each starting with 'nmap '.
Use realistic flags like -sV, -sC, -p-, -sU, --script, -O, -A, -T4."""
        for attempt in range(3):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role":"user","content":prompt}],
                    temperature=0.3,
                    max_tokens=300
                )
                content = resp.choices[0].message.content.strip()
                cmds = [line.strip() for line in content.split('\n') if line.strip().startswith('nmap ')]
                if cmds:
                    self.cache[cache_key] = cmds[:num]
                    return cmds[:num]
            except Exception as e:
                print(Fore.YELLOW + f"AI attempt {attempt+1} failed: {e}")
        # fallback
        fb = [
            f"nmap -sV -sC -T4 {target}",
            f"nmap -p- --min-rate=1000 -T4 {target}",
            f"nmap -sU --top-ports 100 -T4 {target}"
        ]
        self.cache[cache_key] = fb
        return fb

# ===================== NMAP SCANNER =====================
class NmapScanner:
    def __init__(self, timeout=300):
        self.timeout = timeout
        self.results = {}

    def run_command(self, command):
        if not command.startswith("nmap "):
            return {"error": "Invalid command"}
        args = command.split()[1:]
        print(Fore.CYAN + f"Running: {command}")
        try:
            proc = subprocess.run(["nmap"] + args + ["-oX", "-"],
                                  capture_output=True, text=True, timeout=self.timeout)
            xml_output = proc.stdout
            if proc.stderr:
                xml_output += "\n<!-- stderr: " + proc.stderr + " -->"
            nm = nmap_mod.PortScanner()
            nm.analyse_nmap_xml_scan(xml_output)
            parsed = self._parse_nmap(nm)
            parsed['raw_xml'] = xml_output
            return parsed
        except subprocess.TimeoutExpired:
            return {"error": "Timeout"}
        except Exception as e:
            return {"error": str(e)}

    def _parse_nmap(self, nm):
        data = {"hosts": {}}
        for host in nm.all_hosts():
            info = {
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "tcp": {}, "udp": {},
                "os": nm[host].get('os', {}),
                "script": nm[host].get('script', {})
            }
            for proto in nm[host].all_protocols():
                ports = nm[host][proto]
                for port in ports:
                    p_data = {
                        "state": ports[port]['state'],
                        "service": ports[port]['name'],
                        "product": ports[port].get('product', ''),
                        "version": ports[port].get('version', ''),
                        "extrainfo": ports[port].get('extrainfo', '')
                    }
                    info[proto][port] = p_data
            data["hosts"][host] = info
        return data

    def run_commands(self, commands):
        for cmd in commands:
            self.results[cmd] = self.run_command(cmd)
            time.sleep(1)
        return self.results

# ===================== REPORTER =====================
class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir

    def generate(self, target, results, formats=["txt","json","html"]):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^a-zA-Z0-9.\-]', '_', target)
        base = f"nmap_{safe_target}_{ts}"
        os.makedirs(self.output_dir, exist_ok=True)
        saved = {}
        if "txt" in formats:
            saved["txt"] = self._txt(target, results, base)
        if "json" in formats:
            saved["json"] = self._json(target, results, base)
        if "html" in formats:
            saved["html"] = self._html(target, results, base)
        if "pdf" in formats and reportlab:
            saved["pdf"] = self._pdf(target, results, base)
        return saved

    def _txt(self, target, results, base):
        path = os.path.join(self.output_dir, f"{base}.txt")
        with open(path, 'w') as f:
            f.write(f"AI Nmap Scan Report for {target}\n{datetime.now().isoformat()}\n\n")
            for cmd, data in results.items():
                f.write(f"> {cmd}\n")
                if 'raw_xml' in data:
                    f.write(data['raw_xml'])
                else:
                    f.write(json.dumps(data, indent=2))
                f.write("\n" + "-"*60 + "\n")
        return path

    def _json(self, target, results, base):
        path = os.path.join(self.output_dir, f"{base}.json")
        with open(path, 'w') as f:
            json.dump({"target":target,"scan_time":datetime.now().isoformat(),"commands":{cmd:data for cmd,data in results.items()}}, f, indent=2)
        return path

    def _html(self, target, results, base):
        path = os.path.join(self.output_dir, f"{base}.html")
        html = f"<html><head><meta charset='UTF-8'><title>Scan {target}</title></head><body><h1>{target}</h1>"
        for cmd, data in results.items():
            html += f"<h2>{cmd}</h2><pre>{json.dumps(data, indent=2)}</pre><hr>"
        html += "</body></html>"
        with open(path, 'w') as f:
            f.write(html)
        return path

    def _pdf(self, target, results, base):
        if not reportlab:
            return None
        path = os.path.join(self.output_dir, f"{base}.pdf")
        doc = SimpleDocTemplate(path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = [Paragraph(f"AI Nmap Report for {target}", styles['Title']), Spacer(1, 0.2*inch)]
        for cmd, data in results.items():
            story.append(Paragraph(f"Command: {cmd}", styles['Heading2']))
            text = data.get('raw_xml', json.dumps(data, indent=2))
            story.append(Preformatted(text, styles['Code'], max_line_length=80))
            story.append(Spacer(1, 0.1*inch))
        doc.build(story)
        return path

# ===================== TELEGRAM SENDER =====================
class TelegramSender:
    def __init__(self, bot_token, chat_id):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{bot_token}"

    def _check_requests(self):
        if not requests_mod:
            print(Fore.RED + "Thiếu thư viện 'requests'. Cài: pip install requests")
            return False
        return True

    def send_message(self, text):
        if not self._check_requests():
            return False
        try:
            url = f"{self.api_url}/sendMessage"
            payload = {"chat_id": self.chat_id, "text": text, "parse_mode": "Markdown"}
            r = requests_mod.post(url, json=payload, timeout=15)
            return r.json().get("ok", False)
        except Exception as e:
            print(Fore.RED + f"Lỗi gửi Telegram: {e}")
            return False

    def send_file(self, file_path, caption=None):
        if not self._check_requests():
            return False
        try:
            url = f"{self.api_url}/sendDocument"
            with open(file_path, 'rb') as f:
                files = {"document": f}
                data = {"chat_id": self.chat_id}
                if caption:
                    data["caption"] = caption
                r = requests_mod.post(url, data=data, files=files, timeout=30)
                return r.json().get("ok", False)
        except Exception as e:
            print(Fore.RED + f"Lỗi gửi file Telegram: {e}")
            return False

    def send_scan_result(self, target, saved_files, short_summary=True):
        """Gửi tóm tắt text trước, sau đó gửi file báo cáo TXT hoặc HTML."""
        # Gửi message tóm tắt
        msg = f"✅ *Quét hoàn tất cho {target}*\n"
        if short_summary:
            msg += "📄 Báo cáo được đính kèm bên dưới."
        self.send_message(msg)

        # Gửi file txt nếu có (nhỏ gọn), nếu không thì html
        preferred = saved_files.get("txt") or saved_files.get("html") or next(iter(saved_files.values()))
        if preferred and os.path.exists(preferred):
            self.send_file(preferred, caption=f"Báo cáo {target}")

# ===================== TIỆN ÍCH =====================
def is_valid_host(host):
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
        return all(0<=int(p)<=255 for p in host.split('.'))
    return re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", host) is not None

def extract_host(url):
    url = url.strip()
    if not url.startswith(('http://','https://')):
        url = 'http://' + url
    return urlparse(url).hostname

def check_nmap():
    try:
        subprocess.run(["nmap","--version"], capture_output=True, check=True)
        return True
    except:
        return False

# ===================== MENU CLI =====================
def banner():
    print(Fore.MAGENTA + Style.BRIGHT + f"""
   ╔════════════════════════════════════════╗
   ║     🧠 AI Nmap Scanner Pro v{VERSION}    ║
   ║        Termux + Telegram Edition       ║
   ╚════════════════════════════════════════╝
    """)

def main_menu(config):
    init_db()
    while True:
        banner()
        print(Fore.YELLOW + "[1] Quét mục tiêu mới")
        print("[2] Quét danh sách từ file")
        print("[3] Xem lịch sử quét")
        print("[4] Cấu hình")
        print("[5] Lập lịch quét tự động")
        print("[6] Kiểm tra cập nhật")
        print("[7] Thoát")
        choice = input(Fore.CYAN + "Chọn: ").strip()

        if choice == '1':
            scan_single(config)
        elif choice == '2':
            scan_from_file(config)
        elif choice == '3':
            history_menu()
        elif choice == '4':
            config_menu(config)
        elif choice == '5':
            schedule_menu(config)
        elif choice == '6':
            check_update()
        elif choice == '7':
            print(Fore.GREEN + "Tạm biệt!")
            break
        else:
            print(Fore.RED + "Lựa chọn không hợp lệ.")

def scan_single(config, silent_telegram=False):
    api_key = config.get_api_key()
    if not api_key:
        print(Fore.RED + "Chưa có OpenAI API Key. Vào mục Cấu hình để nhập.")
        return
    url = input("URL hoặc IP: ").strip()
    try:
        host = extract_host(url) if not is_valid_host(url) else url
    except:
        print("URL không hợp lệ."); return
    hint = input("Gợi ý cho AI (Enter để bỏ qua): ").strip()
    advisor = AINmapAdvisor(api_key, config.get("model"))
    cmds = advisor.suggest_commands(host, hint, config.get("num_commands"))
    print(Fore.MAGENTA + "\nĐề xuất lệnh:")
    for i,c in enumerate(cmds,1): print(f"  {i}. {c}")
    if input("Chạy những lệnh này? (y/n): ").lower() != 'y': return
    scanner = NmapScanner(config.get("timeout"))
    results = scanner.run_commands(cmds)
    reporter = ReportGenerator(config.get("output_dir"))
    saved = reporter.generate(host, results, ["txt","json","html","pdf"] if reportlab else ["txt","json","html"])
    add_scan(host, cmds, results, saved)
    print(Fore.GREEN + "\nBáo cáo đã lưu:")
    for fmt, path in saved.items(): print(f"  [{fmt}] {path}")

    # Gửi Telegram nếu được kích hoạt
    if config.get("telegram_enabled") and not silent_telegram:
        token = config.get_telegram_token()
        chat_id = config.get("telegram_chat_id")
        if token and chat_id:
            choice = input(Fore.CYAN + "Gửi báo cáo qua Telegram? (y/n): ").lower()
            if choice == 'y':
                sender = TelegramSender(token, chat_id)
                sender.send_scan_result(host, saved)
        else:
            print(Fore.YELLOW + "Telegram chưa được cấu hình đầy đủ.")
    elif silent_telegram and config.get("telegram_enabled"):
        token = config.get_telegram_token()
        chat_id = config.get("telegram_chat_id")
        if token and chat_id:
            sender = TelegramSender(token, chat_id)
            sender.send_scan_result(host, saved)

def scan_from_file(config):
    path = input("Đường dẫn file danh sách (mỗi dòng 1 target): ").strip()
    if not os.path.exists(path):
        print("File không tồn tại."); return
    with open(path) as f:
        targets = [line.strip() for line in f if line.strip()]
    for t in targets:
        try:
            host = extract_host(t) if not is_valid_host(t) else t
        except:
            print(f"Bỏ qua {t}"); continue
        print(f"\nĐang quét {host}...")
        api_key = config.get_api_key()
        advisor = AINmapAdvisor(api_key, config.get("model"))
        cmds = advisor.suggest_commands(host, "", config.get("num_commands"))
        scanner = NmapScanner(config.get("timeout"))
        results = scanner.run_commands(cmds)
        reporter = ReportGenerator(config.get("output_dir")
