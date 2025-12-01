# Powershell styled, AI-Driven Commandline Interface with integrated penetration testing modules
from utils import banner
from utils.listener import Listener
import argparse, sys, os, time, json, re, random
import signal
import ollama
import subprocess
import threading
import socket
import requests
import dns.resolver
from bs4 import BeautifulSoup
import asyncio
import aiohttp
from pathlib import Path
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

class PShell:

    def __init__(self, model_name="benevolentjoker/nsfwwurm"):
        self.model_name = model_name
        self.base_path = Path(__file__).parent

    def load_wordlist(self, wordlist_name):
        """Load wordlist from wordlists directory"""
        wordlist_path = self.base_path / "wordlists" / wordlist_name
        if not wordlist_path.exists():
            # Try common locations
            for alt_name in [f"{wordlist_name}.txt", f"common_{wordlist_name}.txt"]:
                alt_path = self.base_path / "wordlists" / alt_name
                if alt_path.exists():
                    wordlist_path = alt_path
                    break
        return wordlist_path

    def ping_sweep(self, ip_base=None):
        """Integrated ping sweep functionality"""
        if ip_base is None:
            ip_base = input("[PWRSTR1KE] Enter the base IP address (e.g., 192.168.1): ")
        
        print(f"[PWRSTR1KE] Starting ping sweep for {ip_base}.1-254")
        alive_hosts = []
        
        for i in range(1, 255):
            ip = f"{ip_base}.{i}"
            try:
                result = subprocess.run(['ping', '-n', '1', '-w', '100', ip], 
                                      capture_output=True, text=True, timeout=2)
                if "Reply" in result.stdout:
                    alive_hosts.append(ip)
                    print(f"[PWRSTR1KE] Host alive: {ip}")
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
        
        return f"[PWRSTR1KE] Ping sweep completed. Found {len(alive_hosts)} hosts: {', '.join(alive_hosts)}"

    def port_scan(self, target_ip=None, ports=None):
        """Integrated port scanning functionality"""
        if target_ip is None:
            target_ip = input("[PWRSTR1KE] Enter the IP address to scan: ")
            
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        
        print(f"[PWRSTR1KE] Starting port scan on {target_ip}")
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"[PWRSTR1KE] Port {port} is open!")
                sock.close()
            except Exception:
                pass
        
        return f"[PWRSTR1KE] Port scan completed. Open ports: {open_ports}"

    def subdomain_enum(self, domain=None, record_types=None):
        """Integrated subdomain enumeration"""
        if domain is None:
            domain = input("[PWRSTR1KE] Enter the domain to enumerate: ")
            
        if record_types is None:
            record_types = ["A", "AAAA", "CNAME", "MX", "TXT"]
        
        results = []
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    result = f"{domain} {record_type} {rdata.to_text()}"
                    results.append(result)
                    print(f"[PWRSTR1KE] {result}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception as e:
                print(f"[PWRSTR1KE] DNS query error for {record_type}: {e}")
        
        return f"[PWRSTR1KE] DNS enumeration completed. Found {len(results)} records."

    def vhost_enum(self, target_ip=None, hostnames=None):
        """Integrated virtual host enumeration"""
        if target_ip is None:
            target_ip = input("[PWRSTR1KE] Enter the target IP address: ")
        if hostnames is None:
            hostnames_input = input("[PWRSTR1KE] Enter hostnames (comma-separated): ")
            hostnames = [h.strip() for h in hostnames_input.split(',')]
            
        results = []
        for hostname in hostnames:
            headers = {"Host": hostname}
            try:
                response = requests.get(f"http://{target_ip}", headers=headers, timeout=3, verify=False)
                result = f"[PWRSTR1KE] {hostname} -> Status: {response.status_code}, Length: {len(response.content)}"
                results.append(result)
                print(result)
            except requests.exceptions.RequestException as e:
                print(f"[PWRSTR1KE] Error for {hostname}: {e}")
        
        return f"[PWRSTR1KE] Virtual host enumeration completed. Tested {len(hostnames)} hostnames."

    async def directory_enum_async(self, target_url, wordlist_path=None, concurrent_requests=50):
        """Asynchronous directory enumeration"""
        if wordlist_path is None:
            wordlist_path = self.load_wordlist("common_dirs")
        
        if not os.path.exists(wordlist_path):
            return f"[PWRSTR1KE] Wordlist not found: {wordlist_path}"
        
        print(f"[PWRSTR1KE] Starting directory enumeration on {target_url}")
        found_paths = []
        
        async def check_path(session, path):
            url = f"{target_url.rstrip('/')}/{path}"
            try:
                async with session.get(url, timeout=3, allow_redirects=False) as response:
                    if response.status in [200, 204, 301, 302, 307, 401, 403]:
                        result = f"[{response.status}] {url}"
                        found_paths.append(result)
                        print(f"[PWRSTR1KE] Found: {result}")
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

        with open(wordlist_path, "r") as f:
            paths = [line.strip() for line in f if line.strip()]

        async with aiohttp.ClientSession() as session:
            tasks = []
            for path in paths:
                if len(tasks) >= concurrent_requests:
                    await asyncio.gather(*tasks)
                    tasks = []
                tasks.append(check_path(session, path))
            if tasks:
                await asyncio.gather(*tasks)

        return f"[PWRSTR1KE] Directory enumeration completed. Found {len(found_paths)} paths."

    def directory_enum(self, target_url=None, wordlist_path=None):
        """Synchronous wrapper for directory enumeration"""
        if target_url is None:
            target_url = input("[PWRSTR1KE] Enter the target URL: ")
        
        # Run async function in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(self.directory_enum_async(target_url, wordlist_path))
            return result
        finally:
            loop.close()

    def header_analyze(self, target_url=None):
        """Analyze HTTP headers for security information"""
        if target_url is None:
            target_url = input("[PWRSTR1KE] Enter the target URL: ")
            
        try:
            response = requests.get(target_url, timeout=5)
            headers = response.headers
            
            analysis = []
            analysis.append(f"[PWRSTR1KE] Server: {headers.get('Server', 'Not disclosed')}")
            analysis.append(f"[PWRSTR1KE] X-Powered-By: {headers.get('X-Powered-By', 'Not disclosed')}")
            analysis.append(f"[PWRSTR1KE] Content-Type: {headers.get('Content-Type', 'Not specified')}")
            
            # Security headers check
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content Security Policy'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    analysis.append(f"[PWRSTR1KE] ✓ {header}: {description} - PRESENT")
                else:
                    analysis.append(f"[PWRSTR1KE] ✗ {header}: {description} - MISSING")
            
            return "\n".join(analysis)
            
        except requests.exceptions.RequestException as e:
            return f"[PWRSTR1KE] Header analysis error: {e}"

    def windows_exploit_suggest(self, systeminfo_output=None):
        """Analyze Windows system info for potential exploits"""
        if systeminfo_output is None:
            print("[PWRSTR1KE] Getting system information...")
            systeminfo_output = self.run_command("systeminfo")
            
        exploits_found = []
        
        # Basic pattern matching for common vulnerabilities
        if "Windows 7" in systeminfo_output and "Service Pack 1" not in systeminfo_output:
            exploits_found.append("[PWRSTR1KE] Potential: MS17-010 (EternalBlue)")
        
        if "Windows Server 2008" in systeminfo_output:
            exploits_found.append("[PWRSTR1KE] Potential: MS08-067 (Conficker)")
        
        if "Windows 10" in systeminfo_output and "Build 10240" in systeminfo_output:
            exploits_found.append("[PWRSTR1KE] Potential: Various privilege escalation vulns")
        
        if exploits_found:
            return "\n".join(exploits_found)
        else:
            return "[PWRSTR1KE] No obvious exploit patterns detected. Manual analysis recommended."

    def system_monitor(self):
        """Get detailed system information"""
        if os.name == 'nt':  # Windows
            cmd = "powershell.exe -ExecutionPolicy Bypass -Command \"Get-ComputerInfo | Format-List\""
            return self.run_command(cmd)
        else:
            return self.run_command("uname -a && cat /proc/version")

    def execute_builtin_command(self, command_parts):
        """Execute built-in PWRSTR1KE commands"""
        cmd = command_parts[0].lower()
        
        if cmd == "ping-sweep":
            ip_base = command_parts[1] if len(command_parts) > 1 else None
            return self.ping_sweep(ip_base)
        
        elif cmd == "port-scan":
            target = command_parts[1] if len(command_parts) > 1 else None
            ports = None
            if len(command_parts) > 2:
                try:
                    ports = [int(p.strip()) for p in command_parts[2].split(',')]
                except ValueError:
                    return "[PWRSTR1KE] Invalid port format. Use comma-separated numbers."
            return self.port_scan(target, ports)
        
        elif cmd == "dns-enum":
            domain = command_parts[1] if len(command_parts) > 1 else None
            record_types = None
            if len(command_parts) > 2:
                record_types = command_parts[2].split(',')
            return self.subdomain_enum(domain, record_types)
        
        elif cmd == "vhost-enum":
            target_ip = command_parts[1] if len(command_parts) > 1 else None
            hostnames = None
            if len(command_parts) > 2:
                hostnames = command_parts[2].split(',')
            return self.vhost_enum(target_ip, hostnames)
        
        elif cmd == "dir-enum":
            target_url = command_parts[1] if len(command_parts) > 1 else None
            wordlist_path = command_parts[2] if len(command_parts) > 2 else None
            return self.directory_enum(target_url, wordlist_path)
        
        elif cmd == "header-analyze":
            target_url = command_parts[1] if len(command_parts) > 1 else None
            return self.header_analyze(target_url)
        
        elif cmd == "system-info":
            return self.system_monitor()
        
        elif cmd == "exploit-suggest":
            systeminfo_data = None
            if len(command_parts) > 1:
                if os.path.exists(command_parts[1]):
                    with open(command_parts[1], 'r') as f:
                        systeminfo_data = f.read()
                else:
                    systeminfo_data = ' '.join(command_parts[1:])
            return self.windows_exploit_suggest(systeminfo_data)
        
        elif cmd == "analyze-file":
            if len(command_parts) < 2:
                file_path = input("[PWRSTR1KE] Enter the file path to analyze: ")
            else:
                file_path = command_parts[1]
            return self.analyze_file(file_path)
        
        elif cmd == "chat":
            if len(command_parts) < 2:
                question = input("[PWRSTR1KE] Enter your question: ")
            else:
                question = ' '.join(command_parts[1:])
            return self.chat_with_ai(question)
        
        elif cmd == "help":
            return self.show_help()
        
        return None

    def show_help(self):
        """Display help for built-in commands"""
        help_text = """
[PWRSTR1KE] Built-in Commands:
╔══════════════════════════════════════════════════════════════╗
║                      PWRSTR1KE Commands                     ║
╚══════════════════════════════════════════════════════════════╝

Network Reconnaissance:
  ping-sweep [ip_base]          - Ping sweep (interactive if no args)
  port-scan [ip] [ports]        - Port scan (interactive if no args)
  dns-enum [domain] [types]     - DNS enumeration (interactive if no args)
  vhost-enum [ip] [hosts]       - Virtual host enumeration (interactive if no args)

Web Application Testing:
  dir-enum [url] [wordlist]     - Directory enumeration (auto-loads wordlist)
  header-analyze [url]          - HTTP header analysis (interactive if no args)

System Analysis:
  system-info                   - Windows system information
  exploit-suggest [systeminfo]  - Windows exploit suggestions (interactive if no args)
  analyze-file [file_path]      - Comprehensive file analysis (interactive if no args)

AI Assistant:
  chat [question]               - Chat with AI assistant (interactive if no args)

General:
  help                          - Show this help
  exit                          - Exit PWRSTR1KE
  clear                         - Clear screen

Usage Examples:
  ping-sweep 192.168.1         - Scan 192.168.1.1-254
  ping-sweep                   - Interactive mode
  port-scan 192.168.1.1        - Scan common ports
  port-scan 192.168.1.1 80,443 - Scan specific ports
  dir-enum http://example.com   - Use built-in wordlist
  dns-enum example.com A,MX     - Query specific record types
  chat What is SQL injection?   - Ask the AI assistant

Note: All commands support both argument mode and interactive mode.
If you omit arguments, the tool will prompt you for required information.
        """
        return help_text

    def run_command(self, command):
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, timeout=60)
        except subprocess.CalledProcessError as e:
            result = e.output
        except Exception as e:
            result = f"Error executing command: {e}"
        return result

    def _stream_ollama_response(self, prompt, prefix=""):
        """Stream Ollama response with real-time output"""
        try:
            print(f"[PWRSTR1KE] {prefix}", end="", flush=True)
            response_text = ""
            
            stream = ollama.generate(model=self.model_name, prompt=prompt, stream=True)
            for chunk in stream:
                if 'response' in chunk:
                    chunk_text = chunk['response']
                    print(chunk_text, end="", flush=True)
                    response_text += chunk_text
            
            print()  # New line after streaming
            return response_text
            
        except Exception as e:
            error_msg = f"AI model error: {e}"
            print(error_msg)
            return error_msg

    def analyze_result(self, result):
        """Analyze command results with streaming output"""
        prompt = (
            "You are a cybersecurity expert analyzing penetration testing results. "
            "Analyze the following command output and provide key findings, potential vulnerabilities, "
            "and security implications. Be specific and actionable:\n\n"
            f"{result}\n\n"
            "Focus on: 1) Security findings 2) Attack vectors 3) Risk assessment 4) Technical details"
        )
        
        analysis = self._stream_ollama_response(prompt, "AI Analysis: ")
        return analysis if analysis else "Analysis unavailable"

    def suggest_next_command(self, analysis):
        """Suggest next penetration testing command based on analysis"""
        prompt = (
            "Based on this penetration testing analysis, suggest the most effective next command "
            "to further investigate the attack surface. Provide only the specific command with "
            "realistic parameters (no examples or placeholders):\n\n"
            f"{analysis}\n\n"
            "Return format: [command] [actual_parameters]"
        )
        
        suggestion = self._stream_ollama_response(prompt, "Next Command Suggestion: ")
        return suggestion if suggestion else "No specific command suggested"

    def chat_with_ai(self, question):
        """Interactive chat with AI assistant"""
        prompt = (
            "You are a helpful cybersecurity assistant. Answer the following question clearly and accurately. "
            "Provide practical, actionable information for cybersecurity professionals:\n\n"
            f"Question: {question}\n\n"
            "Answer with specific details and real-world examples where appropriate."
        )
        
        response = self._stream_ollama_response(prompt, "AI Assistant: ")
        return response if response else "Unable to process your question at this time."

    def execute(self, command):
        # Check for built-in commands first
        command_parts = command.strip().split()
        if command_parts:
            # Handle built-in commands
            builtin_result = self.execute_builtin_command(command_parts)
            if builtin_result is not None:
                # Only analyze and suggest for non-chat commands
                if command_parts[0].lower() != "chat":
                    analysis = self.analyze_result(builtin_result)
                    next_command = self.suggest_next_command(analysis)
                    return {
                        "result": builtin_result,
                        "analysis": analysis,
                        "next_command": next_command
                    }
                else:
                    # For chat, just return the result
                    return {
                        "result": builtin_result,
                        "analysis": "",
                        "next_command": ""
                    }
        
        # Execute as regular system command
        result = self.run_command(command)
        analysis = self.analyze_result(result)
        next_command = self.suggest_next_command(analysis)
        return {
            "result": result,
            "analysis": analysis,
            "next_command": next_command
        }

    def generate_payload(self, payload_type):
        """Generate payload with streaming output"""
        prompt = (
            f"You are a cybersecurity expert. Generate a practical, educational payload for {payload_type} "
            "that demonstrates security vulnerabilities. Focus on techniques and methods used in professional "
            "penetration testing. Provide real implementation details, not placeholder examples."
        )
        
        payload = self._stream_ollama_response(prompt, f"Generating {payload_type} payload: ")
        return payload if payload else f"Unable to generate payload for {payload_type}"

    def fetch_and_analyze_url(self, url):
        """Fetch URL content and analyze for security vulnerabilities"""
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            analysis = []
            analysis.append(f"[PWRSTR1KE] URL Analysis for: {url}")
            analysis.append(f"[PWRSTR1KE] Response Code: {response.status_code}")
            analysis.append(f"[PWRSTR1KE] Content Length: {len(response.content)} bytes")
            
            # Extract title
            title = soup.title.string if soup.title else "No title found"
            analysis.append(f"[PWRSTR1KE] Page Title: {title}")
            
            # Find forms (potential injection points)
            forms = soup.find_all('form')
            if forms:
                analysis.append(f"[PWRSTR1KE] Found {len(forms)} form(s) - potential injection points")
                for i, form in enumerate(forms):
                    method = form.get('method', 'GET').upper()
                    action = form.get('action', 'current page')
                    analysis.append(f"[PWRSTR1KE]   Form {i+1}: {method} -> {action}")
            
            # Find links
            links = soup.find_all('a', href=True)
            if links:
                analysis.append(f"[PWRSTR1KE] Found {len(links)} link(s)")
                external_links = [link['href'] for link in links if link['href'].startswith('http')]
                if external_links:
                    analysis.append(f"[PWRSTR1KE] External links found: {len(external_links)}")
            
            # Check for common vulnerabilities indicators
            vuln_indicators = []
            text_content = soup.get_text().lower()
            
            if 'error' in text_content or 'exception' in text_content:
                vuln_indicators.append("Error messages detected - potential information disclosure")
            
            if 'admin' in text_content or 'administrator' in text_content:
                vuln_indicators.append("Admin references found - potential privileged access points")
            
            if 'login' in text_content or 'password' in text_content:
                vuln_indicators.append("Authentication forms detected - potential brute force targets")
            
            if vuln_indicators:
                analysis.append("[PWRSTR1KE] Security Indicators:")
                for indicator in vuln_indicators:
                    analysis.append(f"[PWRSTR1KE]   - {indicator}")
            
            return "\n".join(analysis)
            
        except requests.exceptions.RequestException as e:
            return f"[PWRSTR1KE] URL fetch error: {e}"

    def analyze_file(self, file_path):
        """Analyze a file for security vulnerabilities and metadata"""
        if not os.path.exists(file_path):
            return f"[PWRSTR1KE] File not found: {file_path}"
        
        try:
            file_path = Path(file_path)
            analysis = []
            
            # Basic file information
            analysis.append(f"[PWRSTR1KE] File Analysis for: {file_path.name}")
            analysis.append(f"[PWRSTR1KE] Full Path: {file_path.absolute()}")
            
            # File size
            file_size = file_path.stat().st_size
            if file_size < 1024:
                size_str = f"{file_size} bytes"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size / 1024:.2f} KB"
            else:
                size_str = f"{file_size / (1024 * 1024):.2f} MB"
            analysis.append(f"[PWRSTR1KE] File Size: {size_str}")
            
            # File extension and type
            extension = file_path.suffix.lower()
            analysis.append(f"[PWRSTR1KE] Extension: {extension if extension else 'None'}")
            
            # Calculate file hashes
            import hashlib
            with open(file_path, 'rb') as f:
                content = f.read()
                md5_hash = hashlib.md5(content).hexdigest()
                sha1_hash = hashlib.sha1(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
            
            analysis.append(f"[PWRSTR1KE] MD5: {md5_hash}")
            analysis.append(f"[PWRSTR1KE] SHA1: {sha1_hash}")
            analysis.append(f"[PWRSTR1KE] SHA256: {sha256_hash}")
            
            # File type analysis
            file_type = self._detect_file_type(content, extension)
            analysis.append(f"[PWRSTR1KE] Detected Type: {file_type}")
            
            # Security analysis based on file type
            security_analysis = self._analyze_file_security(content, extension, file_type)
            if security_analysis:
                analysis.append("[PWRSTR1KE] Security Analysis:")
                for item in security_analysis:
                    analysis.append(f"[PWRSTR1KE]   - {item}")
            
            # Check for embedded content
            embedded_analysis = self._check_embedded_content(content)
            if embedded_analysis:
                analysis.append("[PWRSTR1KE] Embedded Content:")
                for item in embedded_analysis:
                    analysis.append(f"[PWRSTR1KE]   - {item}")
            
            # Entropy analysis (for detecting packed/encrypted content)
            entropy = self._calculate_entropy(content)
            analysis.append(f"[PWRSTR1KE] Entropy: {entropy:.4f} (0=predictable, 8=random)")
            if entropy > 7.0:
                analysis.append("[PWRSTR1KE]   ⚠️ High entropy - possibly packed/encrypted")
            
            return "\n".join(analysis)
            
        except Exception as e:
            return f"[PWRSTR1KE] File analysis error: {e}"

    def _detect_file_type(self, content, extension):
        """Detect file type based on content and extension"""
        # Check magic bytes
        if content.startswith(b'\x4d\x5a'):  # MZ
            return "Windows Executable (PE)"
        elif content.startswith(b'\x7f\x45\x4c\x46'):  # ELF
            return "Linux Executable (ELF)"
        elif content.startswith(b'\x50\x4b\x03\x04'):  # ZIP
            return "ZIP Archive"
        elif content.startswith(b'\x1f\x8b\x08'):  # GZIP
            return "GZIP Compressed"
        elif content.startswith(b'\x89\x50\x4e\x47'):  # PNG
            return "PNG Image"
        elif content.startswith(b'\xff\xd8\xff'):  # JPEG
            return "JPEG Image"
        elif content.startswith(b'%PDF'):  # PDF
            return "PDF Document"
        elif content.startswith(b'#!/'):  # Shebang
            return "Script with Shebang"
        elif extension in ['.py', '.pyw']:
            return "Python Script"
        elif extension in ['.ps1', '.psm1']:
            return "PowerShell Script"
        elif extension in ['.bat', '.cmd']:
            return "Batch Script"
        elif extension in ['.js', '.jsx']:
            return "JavaScript"
        elif extension in ['.html', '.htm']:
            return "HTML Document"
        elif extension in ['.xml']:
            return "XML Document"
        elif extension in ['.json']:
            return "JSON Data"
        elif extension in ['.txt', '.log']:
            return "Text File"
        else:
            # Try to detect if it's text
            try:
                content.decode('utf-8')
                return "Text File (UTF-8)"
            except UnicodeDecodeError:
                try:
                    content.decode('ascii')
                    return "Text File (ASCII)"
                except UnicodeDecodeError:
                    return "Binary File"

    def _analyze_file_security(self, content, extension, file_type):
        """Analyze file for security concerns"""
        concerns = []
        
        # Check for suspicious patterns in text files
        if "Text" in file_type or "Script" in file_type:
            try:
                text_content = content.decode('utf-8', errors='ignore').lower()
                
                # Check for suspicious keywords
                suspicious_keywords = [
                    'powershell', 'invoke-expression', 'downloadstring', 'webclient',
                    'base64', 'frombase64string', 'shell32', 'kernel32', 'ntdll',
                    'virtualalloc', 'createthread', 'writeprocessmemory', 'shellcode',
                    'metasploit', 'meterpreter', 'payload', 'backdoor', 'rootkit',
                    'keylogger', 'password', 'credential', 'mimikatz', 'procdump'
                ]
                
                found_keywords = [kw for kw in suspicious_keywords if kw in text_content]
                if found_keywords:
                    concerns.append(f"Suspicious keywords found: {', '.join(found_keywords)}")
                
                # Check for obfuscation patterns
                if text_content.count('eval(') > 0:
                    concerns.append("Contains eval() - potential code obfuscation")
                
                if len(re.findall(r'[a-zA-Z0-9+/]{20,}={0,2}', text_content)) > 5:
                    concerns.append("Multiple Base64-like strings detected")
                
                # Check for encoded commands
                if 'encodedcommand' in text_content:
                    concerns.append("PowerShell encoded command detected")
                
            except Exception:
                concerns.append("Could not analyze text content")
        
        # Check for executable files
        if "Executable" in file_type:
            concerns.append("Executable file - requires careful analysis")
            
            # Check for common suspicious sections in PE files
            if file_type == "Windows Executable (PE)":
                if b'.rsrc' in content:
                    concerns.append("Contains resource section - may have embedded data")
                if b'kernel32' in content or b'ntdll' in content:
                    concerns.append("References Windows API - normal but noteworthy")
        
        # Archive files
        if "Archive" in file_type or "ZIP" in file_type:
            concerns.append("Archive file - may contain multiple files to analyze")
        
        return concerns

    def _check_embedded_content(self, content):
        """Check for embedded content like URLs, IPs, emails"""
        findings = []
        
        try:
            text_content = content.decode('utf-8', errors='ignore')
            
            # URLs
            url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
            urls = re.findall(url_pattern, text_content)
            if urls:
                findings.append(f"URLs found: {len(urls)} (showing first 3)")
                for url in urls[:3]:
                    findings.append(f"  {url}")
            
            # IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, text_content)
            # Filter out common false positives
            ips = [ip for ip in ips if not ip.startswith(('0.0.', '127.', '255.255.'))]
            if ips:
                findings.append(f"IP addresses found: {', '.join(set(ips))}")
            
            # Email addresses
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, text_content)
            if emails:
                findings.append(f"Email addresses found: {', '.join(set(emails))}")
            
            # Domain names (excluding IPs)
            domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'
            domains = re.findall(domain_pattern, text_content)
            if domains:
                domain_strings = [f"{match[0]}.{match[1]}" for match in domains]
                # Filter common false positives
                filtered_domains = [d for d in domain_strings if not d.endswith(('.exe', '.dll', '.txt', '.log'))]
                if filtered_domains:
                    findings.append(f"Domains found: {', '.join(set(filtered_domains[:5]))}")
            
        except Exception:
            pass
        
        return findings

    def _calculate_entropy(self, content):
        """Calculate Shannon entropy of file content"""
        import math
        
        if not content:
            return 0
        
        # Count frequency of each byte
        frequency = {}
        for byte in content:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0
        length = len(content)
        for count in frequency.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy


def main():
    os.system('clear' if os.name == 'posix' else 'cls')
    
    # Display the original banner with hacker colors
    banner_text = banner.show()
    # Apply colors to the banner
    colored_banner = ""
    for line in banner_text.split('\n'):
        if any(char in line for char in ['█', '▄', '▀', '■', '●']):
            # ASCII art lines in bright green (hacker style)
            colored_banner += Fore.GREEN + Style.BRIGHT + line + "\n"
        elif "P3N" in line or "SH3LL" in line or "POWER" in line:
            # Title lines in bright cyan (PowerShell style)
            colored_banner += Fore.CYAN + Style.BRIGHT + line + "\n"
        elif "v" in line and "." in line:
            # Version info in white
            colored_banner += Fore.WHITE + Style.DIM + line + "\n"
        else:
            # Other text in regular white
            colored_banner += Fore.WHITE + line + "\n"
    
    print(colored_banner)
    
    print(Fore.RED + Style.BRIGHT + "[!] " + Fore.YELLOW + "UNAUTHORIZED ACCESS PROHIBITED" + Style.RESET_ALL)
    print(Fore.GREEN + Style.BRIGHT + "[+] " + Fore.WHITE + "AI-Powered Penetration Testing Framework" + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "[*] " + Fore.WHITE + "Type 'help' for available commands" + Style.RESET_ALL)
    print()

    # Signal handlers for CTRL+C and CTRL+Z
    def handle_sigint(signum, frame):
        print(Fore.RED + Style.BRIGHT + "\n[!] CTRL+C detected. Exiting PWRSTR1KE immediately." + Style.RESET_ALL)
        sys.exit(0)

    def handle_sigtstp(signum, frame):
        print(Fore.YELLOW + Style.BRIGHT + "\n[!] CTRL+Z detected. Sending PWRSTR1KE to background." + Style.RESET_ALL)
        try:
            os.kill(os.getpid(), signal.SIGSTOP)
        except AttributeError:
            print(Fore.RED + "[!] Backgrounding is not supported on this OS." + Style.RESET_ALL)

    signal.signal(signal.SIGINT, handle_sigint)
    if hasattr(signal, 'SIGTSTP'):
        signal.signal(signal.SIGTSTP, handle_sigtstp)

    # Show system information on startup
    print(Fore.CYAN + Style.BRIGHT + "[PWRSTR1KE] " + Fore.WHITE + "Initializing system analysis..." + Style.RESET_ALL)
    try:
        if os.name == 'nt':  # Windows
            os.system("powershell.exe -ExecutionPolicy Bypass -Command \"Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory | Format-List\"")
    except Exception:
        pass

    Model_Name = "benevolentjoker/nsfwwurm"
    parser = argparse.ArgumentParser(description="Powershell styled, AI-Driven Commandline Interface")

    # Defines if ollama should basically analyze the command output or if an obfuscated FUD Payload should be generated
    parser.add_argument("--payload", type=str, default="pentest", help="Payload for Ollama to generate at best practices for the PShell")
    parser.add_argument("--model", type=str, default=Model_Name, help="Name of the Ollama model to use")
    parser.add_argument("--fetch-url", type=str, help="Fetch URL content and analyze for security vulnerabilities and next commands")
    parser.add_argument("--listener", type=int, help="Start the C2 listener on the specified port")
    parser.add_argument("--attach-file", type=str, help="Analyze a file for security vulnerabilities and metadata")
    args = parser.parse_args()

    # If --listener is provided, start the listener and exit
    if args.listener:
        listener = Listener(args.listener)
        try:
            listener.start()
        except KeyboardInterrupt:
            print("\n[-] Listener stopped")
        return

    pshell = PShell(model_name=args.model)

    # If --attach-file is provided, analyze the file and exit
    if args.attach_file:
        print(f"[PWRSTR1KE] Analyzing file: {args.attach_file}")
        file_analysis = pshell.analyze_file(args.attach_file)
        print(file_analysis)
        print()  # Blank line before AI analysis
        return

    # If --fetch-url is provided, analyze the URL and exit
    if args.fetch_url:
        print(f"[PWRSTR1KE] Analyzing URL: {args.fetch_url}")
        url_analysis = pshell.fetch_and_analyze_url(args.fetch_url)
        print(url_analysis)
        print()  # Blank line before AI analysis
        return

    # If a payload type is specified and not "pentest", generate payload and exit
    if args.payload and args.payload.lower() != "pentest":
        print(f"[PWRSTR1KE] Generating {args.payload} payload...")
        payload = pshell.generate_payload(args.payload)
        return

    print("\n[PWRSTR1KE] Type 'help' for available commands or use standard system commands.")
    print("[PWRSTR1KE] AI-powered analysis with real-time streaming enabled!")
    
    while True:
        command = input("\n[PWRSTR1KE][$HELL] (or 'exit' to quit): ")

        if command.lower() in ['exit', 'quit']:
            break
        if command.lower() == 'clear':
            os.system('clear' if os.name == 'posix' else 'cls')
            print(banner.show())
            continue
        if not command.strip():
            print("[PWRSTR1KE] Please enter a valid command.")
            continue
        
        if command.startswith('!'):
            command = command[1:]

        if command == 'help':
            print(pshell.show_help())
            continue
        
        try:
            output = pshell.execute(command)
            print(f"\n[PWRSTR1KE] Command Result:")
            print(output['result'])
            
            # Only show analysis for non-chat commands
            if output.get('analysis'):
                print()  # Blank line before AI analysis
                # Analysis and suggestions are already streamed with prefixes
                
        except KeyboardInterrupt:
            print("\n[PWRSTR1KE] Command interrupted.")
        except Exception as e:
            print(f"[PWRSTR1KE] Error executing command: {e}")

if __name__ == "__main__":
    main()
