#!/usr/bin/env python3
"""
Script untuk cek kumpulan akun Trojan VPN dari input.txt.
Fetch URL, decode base64 ke Trojan URI, parse ke JSON config, test, simpan valid ke output.txt.
"""
import requests
import base64
import json
import os
import subprocess
import time
import urllib.parse
from datetime import datetime
from urllib.parse import urlparse, parse_qs

def fetch_trojan_uris_from_url(input_url):
    """Fetch file dari URL, decode setiap baris base64 ke Trojan URI."""
    print(f"Fetching Trojan list dari: {input_url}")
    try:
        response = requests.get(input_url, timeout=10)
        response.raise_for_status()
        lines = response.text.strip().split('\n')
        uris = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    decoded = base64.b64decode(line).decode('utf-8')
                    if decoded.startswith('trojan://'):
                        uris.append(decoded)
                        print(f"Decoded URI: {decoded[:50]}...")
                except Exception as e:
                    print(f"Skip invalid base64 line: {e}")
        print(f"Total URIs fetched: {len(uris)}")
        return uris[:50]  # Batasi 50 untuk hindari timeout; sesuaikan jika perlu
    except Exception as e:
        print(f"Error fetching/parsing {input_url}: {e}")
        return []

def parse_trojan_uri_to_config(uri):
    """Parse Trojan URI ke dict config untuk Trojan-Go."""
    try:
        parsed = urlparse(uri)
        if parsed.scheme != 'trojan':
            return None
        password = parsed.username or ''
        server = parsed.hostname or ''
        port = parsed.port or 443
        query = parse_qs(parsed.query)
        sni = query.get('sni', [server])[0]
        
        config = {
            "run_type": "client",
            "local_addr": "127.0.0.1",
            "local_port": 1080,
            "remote_addr": server,
            "remote_port": port,
            "password": [password],
            "ssl": {
                "sni": sni
            }
        }
        return config
    except Exception as e:
        print(f"Error parsing URI {uri[:50]}...: {e}")
        return None

def get_public_ip(proxy=None):
    """Ambil IP publik, gunakan proxy jika diset."""
    print(f"Getting IP with proxy: {proxy if proxy else 'None'}")
    try:
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        response = requests.get('https://api.ipify.org?format=json', proxies=proxies, timeout=10)
        ip = response.json()['ip']
        print(f"Got IP: {ip}")
        return ip
    except Exception as e:
        print(f"Error getting IP: {e}")
        return "N/A"

def test_trojan_config(config, uri, index):
    """Test satu config Trojan, return True jika valid."""
    server = config.get('remote_addr', 'N/A')
    port = config.get('remote_port', 'N/A')
    
    print(f"\n=== Testing Akun {index+1}: {server}:{port} ===")
    
    # Simpan config sementara
    config_file = f'config_{index}.json'
    with open(config_file, 'w') as f:
        json.dump(config, f)
    
    proc = None
    try:
        # Jalankan Trojan-Go di background
        proc = subprocess.Popen(['./trojan-go', '-config', config_file], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                text=True, preexec_fn=os.setsid)  # Untuk kill group
        time.sleep(5)  # Tunggu startup
        
        # Cek apakah running
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            print(f"Trojan-Go failed to start: {stderr}")
            return False
        
        # Set proxy
        proxy = 'socks5://127.0.0.1:1080'
        current_ip = get_public_ip(proxy)
        
        if current_ip == os.getenv('ORIGINAL_IP', 'N/A') or current_ip == 'N/A':
            print("⚠️  IP tidak berubah. Akun tidak berjalan.")
            return False
        
        print("✅ IP berubah. Akun valid!")
        return True
    
    except Exception as e:
        print(f"Error testing Trojan: {e}")
        return False
    finally:
        if proc:
            os.killpg(os.getpgid(proc.pid), 15) if os.name != 'nt' else proc.terminate()  # Kill process group
            time.sleep(2)
        if os.path.exists(config_file):
            os.remove(config_file)

def main():
    print(f"=== Trojan VPN Checker - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
    
    # Ambil original IP
    original_ip = get_public_ip()
    print(f"Original IP (no VPN): {original_ip}")
    os.environ['ORIGINAL_IP'] = original_ip
    
    # Baca input.txt (URL ke daftar URIs)
    try:
        with open('input.txt', 'r') as f:
            input_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print("Error: input.txt tidak ditemukan.")
        return
    
    if not input_urls:
        print("Error: input.txt kosong.")
        return
    
    valid_uris = []
    for input_url in input_urls:
        uris = fetch_trojan_uris_from_url(input_url)
        for i, uri in enumerate(uris):
            config = parse_trojan_uri_to_config(uri)
            if config:
                if test_trojan_config(config, uri, len(valid_uris) + i):
                    valid_uris.append(uri)
    
    # Simpan output (URI valid, satu per baris)
    with open('output.txt', 'w') as f:
        for uri in valid_uris:
            f.write(f"{uri}\n")
    
    # Simpan report
    with open('vpn_report.txt', 'w') as f:
        f.write(f"Timestamp: {datetime.now()}\n")
        f.write(f"Original IP: {original_ip}\n")
        f.write(f"Valid Akun ({len(valid_uris)}):\n")
        for uri in valid_uris:
            f.write(f"- {uri}\n")
        if not valid_uris:
            f.write("Tidak ada akun valid ditemukan.\n")
    
    print(f"\nReport disimpan di vpn_report.txt")
    print(f"Valid URIs disimpan di output.txt: {len(valid_uris)} akun valid")

if __name__ == "__main__":
    main()
