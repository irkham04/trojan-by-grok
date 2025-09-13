#!/usr/bin/env python3
"""
Script untuk cek kumpulan akun Trojan/VMess VPN dari input.txt.
Fetch URL atau URI langsung, decode base64 ke URI, parse ke JSON config Xray, test, simpan valid ke output.txt.
Support WS/TCP untuk Trojan, dan VMess basic.
"""
import requests
import base64
import json
import os
import subprocess
import time
import urllib.parse
import socket
from datetime import datetime
from urllib.parse import urlparse, parse_qs

def find_free_port(start_port=1080):
    """Cari port bebas mulai dari start_port."""
    port = start_port
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except socket.error:
                port += 1
                if port > start_port + 100:
                    raise Exception("Tidak bisa menemukan port bebas.")

def check_socks_proxy(host="127.0.0.1", port=1080):
    """Cek apakah proxy SOCKS5 aktif."""
    try:
        with socket.create_connection((host, port), timeout=5):
            print(f"SOCKS5 proxy {host}:{port} aktif.")
            return True
    except Exception as e:
        print(f"SOCKS5 proxy {host}:{port} tidak aktif: {e}")
        return False

def fetch_uris_from_url(input_url):
    """Fetch file dari URL, decode setiap baris base64 ke URI (support trojan/vmess)."""
    print(f"Fetching dari: {input_url}")
    try:
        response = requests.get(input_url, timeout=30)  # Timeout lebih panjang
        response.raise_for_status()
        lines = response.text.strip().split('\n')
        print(f"Total lines fetched: {len(lines)}")
        print(f"First 5 lines (raw): {lines[:5]}")
        uris = []
        for i, line in enumerate(lines):
            line = line.strip()
            if line:
                try:
                    decoded = base64.b64decode(line).decode('utf-8', errors='ignore')
                    if decoded.startswith('trojan://') or decoded.startswith('vmess://'):
                        uris.append(decoded)
                        protocol = 'Trojan' if decoded.startswith('trojan://') else 'VMess'
                        print(f"Line {i+1}: {protocol} URI: {decoded[:50]}...")
                    else:
                        print(f"Line {i+1}: Skip non-supported: {decoded[:50]}...")
                except Exception as e:
                    print(f"Line {i+1}: Skip invalid base64: {line[:50]}... ({e})")
        print(f"Total URIs fetched: {len(uris)}")
        return uris[:50]  # Batasi 50 untuk lebih banyak test
    except Exception as e:
        print(f"Error fetching/parsing {input_url}: {e}")
        return []

def parse_trojan_uri_to_config(uri, port=1080):
    """Parse Trojan URI ke dict config untuk Xray, handle WS/TCP."""
    try:
        parsed = urlparse(uri)
        if parsed.scheme != 'trojan':
            print(f"Invalid scheme in URI: {uri[:50]}...")
            return None
        password = urllib.parse.unquote(parsed.username or '')
        server = parsed.hostname or ''
        port_remote = parsed.port or 443
        query = parse_qs(parsed.query)
        sni = query.get('sni', [server])[0]
        network = query.get('type', ['tcp'])[0]  # 'ws' atau 'tcp'
        ws_path = query.get('path', [''])[0]
        ws_host = query.get('host', [sni])[0]
        allow_insecure = query.get('allowInsecure', ['0'])[0] == '1'
        
        stream_settings = {
            "network": network,
            "security": "tls",
            "tlsSettings": {
                "serverName": sni,
                "allowInsecure": allow_insecure
            }
        }
        
        if network == 'ws':
            stream_settings["wsSettings"] = {
                "path": urllib.parse.unquote(ws_path),
                "headers": {"Host": ws_host}
            }
            print(f"Parsed WS config: network=ws, path={ws_path[:30]}..., host={ws_host}")
        else:
            print(f"Parsed TCP config: network=tcp")
        
        config = {
            "inbounds": [
                {
                    "port": port,
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    },
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
                }
            ],
            "outbounds": [
                {
                    "protocol": "trojan",
                    "settings": {
                        "servers": [
                            {
                                "address": server,
                                "port": port_remote,
                                "password": password
                            }
                        ]
                    },
                    "streamSettings": stream_settings
                }
            ]
        }
        print(f"Parsed config: server={server}, port={port_remote}, sni={sni}, local_port={port}, network={network}")
        return config
    except Exception as e:
        print(f"Error parsing URI {uri[:50]}...: {e}")
        return None

def parse_vmess_uri_to_config(uri, port=1080):
    """Parse VMess URI ke dict config untuk Xray."""
    try:
        # VMess URI: vmess://base64(JSON)
        vmess_b64 = uri[8:]  # Hilangkan 'vmess://'
        vmess_json = json.loads(base64.b64decode(vmess_b64).decode('utf-8'))
        server = vmess_json.get('add', '')
        port_remote = vmess_json.get('port', 443)
        uuid = vmess_json.get('id', '')
        aid = vmess_json.get('aid', 0)
        net = vmess_json.get('net', 'tcp')
        tls = vmess_json.get('tls', '')
        sni = vmess_json.get('host', server) if tls else ''
        allow_insecure = vmess_json.get('allowInsecure', False)
        
        stream_settings = {
            "network": net,
            "security": tls,
            "tlsSettings": {"serverName": sni, "allowInsecure": allow_insecure} if tls else {}
        }
        if net == 'ws':
            # Handle WS untuk VMess jika ada path/host di JSON (extend jika perlu)
            path = vmess_json.get('path', '')
            host = vmess_json.get('host', sni)
            if path:
                stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
        
        config = {
            "inbounds": [
                {
                    "port": port,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
                }
            ],
            "outbounds": [
                {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [
                            {
                                "address": server,
                                "port": port_remote,
                                "users": [{"id": uuid, "alterId": aid, "security": "auto"}]
                            }
                        ]
                    },
                    "streamSettings": stream_settings
                }
            ]
        }
        print(f"Parsed VMess: server={server}:{port_remote}, sni={sni}, local_port={port}, network={net}")
        return config
    except Exception as e:
        print(f"Error parsing VMess {uri[:50]}...: {e}")
        return None

def get_public_ip(proxy=None):
    """Ambil IP publik, gunakan proxy jika diset."""
    print(f"Getting IP with proxy: {proxy if proxy else 'None'}")
    try:
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        response = requests.get('https://api.ipify.org?format=json', proxies=proxies, timeout=30)
        ip = response.json()['ip']
        print(f"Got IP: {ip}")
        return ip
    except Exception as e:
        print(f"Error getting IP: {e}")
        return "N/A"

def test_config(config, uri, index):
    """Test satu config (Trojan/VMess) dengan Xray, return True jika valid."""
    server = config['outbounds'][0]['settings']['servers'][0]['address'] if 'servers' in config['outbounds'][0]['settings'] else config['outbounds'][0]['settings']['vnext'][0]['address']
    port = config['outbounds'][0]['settings']['servers'][0]['port'] if 'servers' in config['outbounds'][0]['settings'] else config['outbounds'][0]['settings']['vnext'][0]['port']
    local_port = config['inbounds'][0]['port']
    
    print(f"\n=== Testing Akun {index+1}: {server}:{port} ===")
    
    # Simpan config sementara
    config_file = f'config_{index}.json'
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    proc = None
    try:
        # Jalankan Xray di background
        proc = subprocess.Popen(['./xray', '-config', config_file], 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                               text=True, preexec_fn=os.setsid)
        time.sleep(20)  # Tunggu lebih lama untuk koneksi WS/TLS
        
        # Cek apakah Xray running
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            print(f"Xray failed to start: {stderr}")
            return False
        
        # Cek proxy SOCKS5
        if not check_socks_proxy("127.0.0.1", local_port):
            print("Proxy SOCKS5 tidak aktif, skip akun.")
            return False
        
        # Set proxy
        proxy = f'socks5://127.0.0.1:{local_port}'
        current_ip = get_public_ip(proxy)
        
        if current_ip == os.getenv('ORIGINAL_IP', 'N/A') or current_ip == 'N/A':
            print("⚠️  IP tidak berubah. Akun tidak berjalan.")
            return False
        
        print("✅ IP berubah. Akun valid!")
        return True
    
    except Exception as e:
        print(f"Error testing Xray: {e}")
        return False
    finally:
        if proc:
            os.killpg(os.getpgid(proc.pid), 15) if os.name != 'nt' else proc.terminate()
            time.sleep(2)
        if os.path.exists(config_file):
            os.remove(config_file)

def main():
    print(f"=== VPN Checker (Trojan/VMess) - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
    
    # Ambil original IP
    original_ip = get_public_ip()
    print(f"Original IP (no VPN): {original_ip}")
    os.environ['ORIGINAL_IP'] = original_ip
    
    # Baca input.txt
    try:
        with open('input.txt', 'r') as f:
            input_lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print("Error: input.txt tidak ditemukan.")
        return
    
    if not input_lines:
        print("Error: input.txt kosong.")
        return
    
    valid_uris = []
    for line in input_lines:
        if line.startswith('trojan://') or line.startswith('vmess://'):
            uris = [line]
            print(f"Processing direct URI: {line[:50]}...")
        else:
            uris = fetch_uris_from_url(line)
        for i, uri in enumerate(uris):
            port = find_free_port()  # Dapatkan port bebas
            if uri.startswith('trojan://'):
                config = parse_trojan_uri_to_config(uri, port=port)
            elif uri.startswith('vmess://'):
                config = parse_vmess_uri_to_config(uri, port=port)
            else:
                continue
            if config:
                if test_config(config, uri, len(valid_uris) + i):
                    valid_uris.append(uri)
    
    # Simpan output
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
