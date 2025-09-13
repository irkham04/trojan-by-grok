#!/usr/bin/env python3
"""
Script untuk cek kumpulan akun Trojan VPN dari input.txt.
Fetch URL, decode base64, test setiap akun, simpan valid ke output.txt.
"""
import requests
import base64
import json
import os
import subprocess
from datetime import datetime

def fetch_config_from_url(url):
    """Ambil dan decode base64 config dari URL."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        base64_str = response.text.strip()
        config_json = base64.b64decode(base64_str).decode('utf-8')
        return json.loads(config_json)
    except Exception as e:
        print(f"Error fetch/decode {url}: {e}")
        return None

def get_public_ip(proxy=None):
    """Ambil IP publik, gunakan proxy jika diset."""
    try:
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        response = requests.get('https://api.ipify.org?format=json', proxies=proxies, timeout=10)
        return response.json()['ip']
    except Exception as e:
        print(f"Error ambil IP: {e}")
        return "N/A"

def check_dns_leak(domain='www.google.com', proxy=None):
    """Cek DNS via Google API, honor proxy."""
    try:
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        url = f"https://dns.google/resolve?name={domain}&type=A"
        response = requests.get(url, proxies=proxies, timeout=10)
        data = response.json()
        ips = [answer['data'] for answer in data.get('Answer', [])]
        print(f"DNS Resolution untuk {domain}: {ips}")
        return "No leak detected" if any(ip.startswith('142.') or ip.startswith('172.') or ip.startswith('8.8.') for ip in ips) else "Potential DNS leak!"
    except Exception as e:
        return f"DNS check error: {e}"

def check_speed():
    """Cek speed via speedtest-cli (honor HTTP_PROXY jika support)."""
    try:
        result = subprocess.run(['speedtest-cli', '--simple'], capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            download = lines[1].split(': ')[1] if len(lines) > 1 else 'N/A'
            upload = lines[2].split(': ')[1] if len(lines) > 2 else 'N/A'
            ping = lines[0].split(': ')[1] if len(lines) > 0 else 'N/A'
            return f"Download: {download}, Upload: {upload}, Ping: {ping}"
        else:
            return "Speedtest failed: " + result.stderr
    except Exception as e:
        return f"Speedtest error: {e}"

def test_trojan_config(config, index):
    """Test satu config Trojan, return status dan URL jika valid."""
    server = config.get('remote_addr', 'N/A')
    port = config.get('remote_port', 'N/A')
    password = config.get('password', [''])[0] if config.get('password') else ''
    sni = config.get('ssl', {}).get('sni', server)
    
    print(f"\n=== Testing Akun {index+1}: {server}:{port} ===")
    
    # Simpan config sementara untuk Trojan-Go
    with open(f'config_{index}.json', 'w') as f:
        json.dump(config, f)
    
    # Jalankan Trojan-Go
    try:
        subprocess.run(['./trojan-go', '-config', f'config_{index}.json'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        subprocess.Popen(['./trojan-go', '-config', f'config_{index}.json'])
        import time
        time.sleep(5)  # Tunggu startup
        
        # Set proxy
        proxy = 'socks5://127.0.0.1:1080'
        current_ip = get_public_ip(proxy)
        print(f"Current IP: {current_ip}")
        
        if current_ip == os.getenv('ORIGINAL_IP', 'N/A') or current_ip == 'N/A':
            print("⚠️  IP tidak berubah. Akun tidak berjalan.")
            return False, None
        
        print("✅ IP berubah. Akun berjalan!")
        dns_status = check_dns_leak(proxy=proxy)
        print(f"DNS Status: {dns_status}")
        speed_info = check_speed()
        print(f"Speed Info: {speed_info}")
        
        # Format Trojan URL
        trojan_url = f"trojan://{password}@{server}:{port}?security=tls&sni={sni}#{server}"
        return True, trojan_url
    
    except Exception as e:
        print(f"Error running Trojan: {e}")
        return False, None
    finally:
        subprocess.run(['pkill', 'trojan-go'], check=False)
        os.remove(f'config_{index}.json')

def main():
    print(f"=== Trojan VPN Checker - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
    
    # Ambil original IP
    original_ip = get_public_ip()
    print(f"Original IP (no VPN): {original_ip}")
    os.environ['ORIGINAL_IP'] = original_ip
    
    # Baca input.txt
    try:
        with open('input.txt', 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print("Error: input.txt tidak ditemukan.")
        return
    
    if not urls:
        print("Error: input.txt kosong atau hanya komentar.")
        return
    
    valid_urls = []
    for i, url in enumerate(urls):
        print(f"\nFetching config dari {url}")
        config = fetch_config_from_url(url)
        if config:
            is_valid, trojan_url = test_trojan_config(config, i)
            if is_valid and trojan_url:
                valid_urls.append(trojan_url)
    
    # Simpan output
    with open('output.txt', 'w') as f:
        for url in valid_urls:
            f.write(f"{url}\n")
    
    # Simpan report
    with open('vpn_report.txt', 'w') as f:
        f.write(f"Timestamp: {datetime.now()}\n")
        f.write(f"Original IP: {original_ip}\n")
        f.write(f"Valid Akun ({len(valid_urls)}):\n")
        for url in valid_urls:
            f.write(f"- {url}\n")
        if not valid_urls:
            f.write("Tidak ada akun valid ditemukan.\n")
    
    print(f"\nReport disimpan di vpn_report.txt")
    print(f"Valid URLs disimpan di output.txt: {len(valid_urls)} akun valid")

if __name__ == "__main__":
    main()
