#!/usr/bin/env python3
"""
AI Nmap Scanner cho Termux - Tự động quét với lệnh do AI đề xuất.
Yêu cầu: Nmap, Python, OpenAI API key.
Chỉ quét hệ thống bạn có quyền!
"""

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse

# Thư viện bên ngoài
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("Thiếu colorama. Cài: pip install colorama")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Thiếu python-dotenv. Cài: pip install python-dotenv")
    sys.exit(1)

try:
    from openai import OpenAI
except ImportError:
    print("Thiếu openai. Cài: pip install openai")
    sys.exit(1)

# ========== CẤU HÌNH ==========
CONFIG_FILE = os.path.expanduser("~/.ai_nmap_config.json")
HISTORY_FILE = os.path.expanduser("~/.ai_nmap_history.json")
VERSION = "2.1.0"
GITHUB_VERSION_URL = "https://raw.githubusercontent.com/yourname/ai-nmap-termux/main/version.txt"  # Đổi thành URL thật

# ========== QUẢN LÝ CẤU HÌNH ==========
class ConfigManager:
    def __init__(self, config_path=CONFIG_FILE):
        self.config_path = config_path
        self.defaults = {
            "output_dir": os.path.expanduser("~/nmap_scans"),
            "timeout": 300,
            "model": "gpt-3.5-turbo",
            "num_commands": 4
        }
        self.data = self.load()

    def load(self) -> dict:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return {**self.defaults, **json.load(f)}
            except:
                pass
        return self.defaults.copy()

    def save(self):
        with open(self.config_path, 'w') as f:
            json.dump(self.data, f, indent=2)

    def get(self, key):
        return self.data.get(key, self.defaults.get(key))

    def set(self, key, value):
        self.data[key] = value
        self.save()

    def get_api_key(self):
        # Ưu tiên biến môi trường
        key = os.getenv("OPENAI_API_KEY")
        if key:
            return key
        # Sau đó đọc từ config
        return self.data.get("api_key")

    def set_api_key(self, key):
        self.data["api_key"] = key
        self.save()
        # Cũng ghi vào .env nếu muốn
        env_path = os.path.expanduser("~/.ai_nmap.env")
        with open(env_path, "w") as f:
            f.write(f"OPENAI_API_KEY={key}\n")
        print(Fore.GREEN + "API key đã được lưu vào config và ~/.ai_nmap.env")

# ========== QUẢN LÝ LỊCH SỬ ==========
class HistoryManager:
    def __init__(self, history_path=HISTORY_FILE):
        self.history_path = history_path
        self.entries = self.load()

    def load(self) -> list:
        if os.path.exists(self.history_path):
            try:
                with open(self.history_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        return []

    def save(self):
        with open(self.history_path, 'w') as f:
            json.dump(self.entries, f, indent=2)

    def add(self, target: str, commands: List[str], results: Dict[str, str], output_files: Dict[str, str]):
        entry = {
            "id": len(self.entries) + 1,
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "commands": commands,
            "results_summary": {cmd: out[:200] + "..." if len(out)>200 else out for cmd, out in results.items()},
            "output_files": output_files
        }
        self.entries.append(entry)
        self.save()

    def list_all(self):
        return self.entries

    def get_by_id(self, id: int) -> Optional[dict]:
        for e in self.entries:
            if e["id"] == id:
                return e
        return None

# ========== TIỆN ÍCH ==========
def is_valid_host(host: str) -> bool:
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, host):
        return all(0 <= int(p) <= 255 for p in host.split('.'))
    domain_pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.match(domain_pattern, host) is not None

def extract_host(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("Không thể trích xuất host từ URL.")
    return host

def check_nmap() -> bool:
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        return True
    except:
        return False

# ========== AI ADVISOR ==========
class AINmapAdvisor:
    def __init__(self, api_key: str, model="gpt-3.5-turbo"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def suggest_commands(self, target: str, hint: str = "", num: int = 4) -> List[str]:
        prompt = f"""You are a cybersecurity expert. Suggest {num} useful nmap commands to scan target: {target}.
User hint: "{hint}"
Return only the commands, one per line, each starting with 'nmap '.
Use flags like -sV, -sC, -p-, -sU, --script, -O, -A, -T4... but be realistic.
"""
        for attempt in range(3):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,
                    max_tokens=300
                )
                content = resp.choices[0].message.content.strip()
                cmds = [line.strip() for line in content.split('\n') if line.strip().startswith('nmap ')]
                if cmds:
                    return cmds[:num]
            except Exception as e:
                print(Fore.YELLOW + f"OpenAI thử {attempt+1} lỗi: {e}")
        # Fallback
        return [
            f"nmap -sV -sC -T4 {target}",
            f"nmap -p- --min-rate=1000 -T4 {target}",
            f"nmap -sU --top-ports 100 -T4 {target}"
        ]

# ========== NMAP RUNNER ==========
class NmapRunner:
    def __init__(self, timeout=300):
        self.timeout = timeout
        self.results = {}

    def run_command(self, command: str) -> str:
        if not command.startswith("nmap "):
            return f"[!] Lệnh không hợp lệ: {command}"
        args = command.split()[1:]
        print(Fore.CYAN + f"Đang chạy: {command}")
        try:
            proc = subprocess.run(
                ["nmap"] + args,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            return proc.stdout + ("\n[STDERR]\n" + proc.stderr if proc.stderr else "")
        except subprocess.TimeoutExpired:
            return f"[!] Hết thời gian ({self.timeout}s)"
        except Exception as e:
            return f"[!] Lỗi: {e}"

    def run_commands(self, commands: List[str]) -> Dict[str, str]:
        for cmd in commands:
            self.results[cmd] = self.run_command(cmd)
            time.sleep(1)
        return self.results

    def save_reports(self, target: str, output_dir: str, formats: List[str] = None) -> Dict[str, str]:
        if not formats:
            formats = ["txt", "json"]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^a-zA-Z0-9.-]', '_', target)
        base = f"nmap_{safe_target}_{ts}"
        os.makedirs(output_dir, exist_ok=True)
        saved = {}
        data = {
            "target": target,
            "scan_time": ts,
            "commands": [{"cmd": c, "output": o} for c, o in self.results.items()]
        }

        if "txt" in formats:
            path = os.path.join(output_dir, f"{base}.txt")
            with open(path, 'w') as f:
                f.write(f"AI Nmap Report for {target}\n{ts}\n{'='*60}\n\n")
                for item in data["commands"]:
                    f.write(f"> {item['cmd']}\n{item['output']}\n{'-'*60}\n")
            saved["txt"] = path

        if "json" in formats:
            path = os.path.join(output_dir, f"{base}.json")
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
            saved["json"] = path

        if "xml" in formats:
            path = os.path.join(output_dir, f"{base}.xml")
            with open(path, 'w') as f:
                f.write('<?xml version="1.0"?>\n<nmap_scan>\n')
                f.write(f'<target>{target}</target>\n<time>{ts}</time>\n')
                for item in data["commands"]:
                    f.write(f'<command cmd="{item["cmd"]}"><![CDATA[{item["output"]}]]></command>\n')
                f.write('</nmap_scan>')
            saved["xml"] = path

        if "html" in formats:
            path = os.path.join(output_dir, f"{base}.html")
            html = f"<html><head><meta charset='UTF-8'><title>Scan {target}</title></head><body><h1>{target}</h1><p>{ts}</p>"
            for item in data["commands"]:
                html += f"<h3>{item['cmd']}</h3><pre>{item['output']}</pre><hr>"
            html += "</body></html>"
            with open(path, 'w') as f:
                f.write(html)
            saved["html"] = path

        return saved

# ========== MENU CHÍNH ==========
def print_banner():
    print(Fore.MAGENTA + Style.BRIGHT + """
   ╔══════════════════════════════════════╗
   ║     🧠 AI NMAP SCANNER TERMUX     ║
   ║        version """ + VERSION + """               ║
   ╚══════════════════════════════════════╝
    """ + Style.RESET_ALL)

def show_menu():
    print(Fore.YELLOW + "\n===== MENU CHÍNH =====")
    print("1. 🚀 Quét mục tiêu mới")
    print("2. 📋 Xem lịch sử quét")
    print("3. ⚙️  Cấu hình (API key, thư mục...)")
    print("4. 🔄 Kiểm tra cập nhật")
    print("5. ❌ Thoát")
    return input(Fore.CYAN + "Chọn (1-5): ").strip()

def scan_target(config: ConfigManager, history: HistoryManager):
    api_key = config.get_api_key()
    if not api_key:
        print(Fore.RED + "Bạn chưa có API key. Hãy cấu hình trong menu Cấu hình.")
        return
    url = input("Nhập URL hoặc IP: ").strip()
    try:
        host = extract_host(url) if not is_valid_host(url) else url
    except:
        print(Fore.RED + "URL không hợp lệ.")
        return
    hint = input("Mô tả thêm cho AI (Enter nếu không): ").strip()
    advisor = AINmapAdvisor(api_key, config.get("model"))
    print(Fore.BLUE + "AI đang đề xuất lệnh...")
    cmds = advisor.suggest_commands(host, hint, config.get("num_commands"))
    print(Fore.MAGENTA + "\n--- Các lệnh đề xuất ---")
    for i, c in enumerate(cmds, 1):
        print(f"{i}. {c}")
    yn = input(Fore.YELLOW + "Chạy các lệnh này? (y/n): ").lower()
    if yn != 'y':
        return
    runner = NmapRunner(timeout=config.get("timeout"))
    results = runner.run_commands(cmds)
    output_dir = config.get("output_dir")
    formats = ["txt", "json"]  # có thể cho tùy chọn sau
    saved = runner.save_reports(host, output_dir, formats)
    print(Fore.GREEN + "\nĐã lưu báo cáo:")
    for fmt, path in saved.items():
        print(f"  [{fmt}] {path}")
    history.add(host, cmds, results, saved)
    print(Fore.GREEN + "Đã ghi vào lịch sử.")

def view_history(history: HistoryManager):
    entries = history.list_all()
    if not entries:
        print(Fore.YELLOW + "Chưa có lịch sử quét.")
        return
    print(Fore.CYAN + "\n===== LỊCH SỬ QUÉT =====")
    for e in entries:
        print(f"[{e['id']}] {e['target']} - {e['timestamp']}")
    choice = input("Nhập ID để xem chi tiết (Enter để về): ").strip()
    if choice.isdigit():
        e = history.get_by_id(int(choice))
        if e:
            print(Fore.MAGENTA + f"\nTarget: {e['target']}")
            print(f"Thời gian: {e['timestamp']}")
            print("Các lệnh đã chạy:")
            for c in e['commands']:
                print(f"  - {c}")
            print("Kết quả tóm tắt:")
            for cmd, out in e['results_summary'].items():
                print(f"  {cmd}:\n    {out}")
            print("File báo cáo:", e.get('output_files'))
        else:
            print("ID không tồn tại.")

def configure(config: ConfigManager):
    while True:
        print(Fore.CYAN + "\n--- Cấu hình ---")
        print(f"1. API Key (hiện: {'****' if config.get_api_key() else 'Chưa có'})")
        print(f"2. Thư mục lưu báo cáo (hiện: {config.get('output_dir')})")
        print(f"3. Timeout mỗi lệnh (giây, hiện: {config.get('timeout')})")
        print(f"4. Model AI (hiện: {config.get('model')})")
        print(f"5. Số lệnh AI đề xuất (hiện: {config.get('num_commands')})")
        print("6. Quay lại")
        c = input("Chọn: ").strip()
        if c == '1':
            key = input("Nhập OpenAI API key: ").strip()
            if key:
                config.set_api_key(key)
        elif c == '2':
            d = input("Đường dẫn thư mục: ").strip()
            if d:
                config.set("output_dir", d)
        elif c == '3':
            t = input("Timeout (giây): ").strip()
            if t.isdigit():
                config.set("timeout", int(t))
        elif c == '4':
            m = input("Model (vd: gpt-3.5-turbo, gpt-4): ").strip()
            if m:
                config.set("model", m)
        elif c == '5':
            n = input("Số lệnh (2-6): ").strip()
            if n.isdigit() and 2 <= int(n) <= 6:
                config.set("num_commands", int(n))
        elif c == '6':
            break

def check_update():
    try:
        import urllib.request
        with urllib.request.urlopen(GITHUB_VERSION_URL) as resp:
            latest = resp.read().decode().strip()
            if latest > VERSION:
                print(Fore.GREEN + f"Có phiên bản mới: {latest} (hiện tại: {VERSION})")
                print("Vui lòng cập nhật từ GitHub repository.")
            else:
                print(Fore.GREEN + "Bạn đang dùng phiên bản mới nhất.")
    except Exception as e:
        print(Fore.YELLOW + f"Không kiểm tra được cập nhật: {e}")

def main():
    print_banner()
    if not check_nmap():
        print(Fore.RED + "Nmap chưa được cài đặt. Gõ: pkg install nmap")
        sys.exit(1)

    config = ConfigManager()
    history = HistoryManager()

    while True:
        try:
            choice = show_menu()
            if choice == '1':
                scan_target(config, history)
            elif choice == '2':
                view_history(history)
            elif choice == '3':
                configure(config)
            elif choice == '4':
                check_update()
            elif choice == '5':
                print(Fore.GREEN + "Tạm biệt!")
                break
            else:
                print(Fore.RED + "Chọn không hợp lệ.")
        except KeyboardInterrupt:
            print("\nThoát.")
            break
        except Exception as e:
            print(Fore.RED + f"Lỗi: {e}")

if __name__ == "__main__":
    main()
