#!/usr/bin/env python3
"""
AI Nmap Scanner – Tự động quét với các lệnh Nmap do AI đề xuất.
Chỉ sử dụng trên các hệ thống bạn có quyền kiểm thử!
"""

import os
import re
import subprocess
import sys
from urllib.parse import urlparse

import openai
import nmap

# ========== CẤU HÌNH ==========
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "your-api-key-here")
openai.api_key = OPENAI_API_KEY

def extract_host(url: str) -> str:
    """Trích xuất hostname hoặc IP từ URL."""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("Không thể trích xuất host từ URL.")
    return host

def generate_nmap_commands(host: str, user_hint: str = "") -> list:
    """
    Dùng OpenAI để sinh danh sách lệnh Nmap.
    Trả về list các chuỗi lệnh (không bao gồm 'nmap').
    """
    prompt = f"""
Bạn là chuyên gia an ninh mạng. Hãy đề xuất 3-5 lệnh Nmap hữu ích để quét mục tiêu: {host}.
Người dùng có thể bổ sung mô tả: "{user_hint}".
Chỉ trả về các lệnh, mỗi lệnh trên một dòng, không kèm giải thích.
Lệnh phải bắt đầu bằng 'nmap ' (ví dụ: nmap -sV -sC {host}).
"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=300
        )
        text = response.choices[0].message.content.strip()
        # Tách dòng và lọc những dòng bắt đầu bằng 'nmap '
        commands = [line.strip() for line in text.splitlines() if line.strip().startswith('nmap ')]
        if not commands:
            # fallback nếu AI không trả lời đúng
            commands = [
                f"nmap -sV -sC {host}",
                f"nmap -p- --min-rate=1000 {host}",
                f"nmap -sU --top-ports 100 {host}"
            ]
        return commands
    except Exception as e:
        print(f"[!] Lỗi OpenAI: {e}")
        # Dùng danh sách mặc định
        return [
            f"nmap -sV -sC {host}",
            f"nmap -p- --min-rate=1000 {host}",
            f"nmap -sU --top-ports 100 {host}"
        ]

def run_nmap(command: str) -> str:
    """Thực thi lệnh Nmap và trả về output."""
    try:
        # Tách lệnh (loại bỏ 'nmap ' ở đầu)
        args = command.split()[1:]  # bỏ 'nmap'
        # Sử dụng python-nmap để có kết quả cấu trúc, nhưng ở đây dùng subprocess cho đơn giản
        result = subprocess.run(
            ["nmap"] + args,
            capture_output=True,
            text=True,
            timeout=300  # 5 phút
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[!] Quét quá thời gian (timeout)."
    except FileNotFoundError:
        return "[!] Không tìm thấy Nmap. Hãy cài đặt Nmap và thêm vào PATH."
    except Exception as e:
        return f"[!] Lỗi: {e}"

def main():
    print("=== AI Nmap Scanner ===")
    url = input("Nhập URL (hoặc IP): ").strip()
    hint = input("Mô tả thêm (Enter nếu không có): ").strip()

    try:
        host = extract_host(url)
        print(f"[*] Mục tiêu: {host}")
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    print("[*] Đang hỏi AI đề xuất lệnh...")
    commands = generate_nmap_commands(host, hint)

    print("\n--- Các lệnh Nmap được đề xuất ---")
    for i, cmd in enumerate(commands, 1):
        print(f"{i}. {cmd}")

    confirm = input("\nBạn có muốn chạy tất cả các lệnh trên không? (y/n): ").lower()
    if confirm != 'y':
        print("Đã hủy.")
        return

    output_file = f"nmap_scan_{host.replace('.', '_')}.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"Kết quả quét cho {host}\n")
        f.write("=" * 50 + "\n\n")

        for cmd in commands:
            print(f"\n[+] Đang chạy: {cmd}")
            f.write(f"> {cmd}\n")
            result = run_nmap(cmd)
            print(result)
            f.write(result + "\n" + "-"*50 + "\n")

    print(f"\n[✓] Đã lưu kết quả vào {output_file}")

if __name__ == "__main__":
    main()
