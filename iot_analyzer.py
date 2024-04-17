import nmap
import requests
import paramiko
import ssl
from datetime import datetime
from urllib.parse import urlparse
import socket
import argparse
import json

class IoTDeviceSecurityAnalyzer:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.open_ports = []
        self.ssh_credentials = []
        self.ssl_info = {}
        self.vulnerabilities = []

    def scan_open_ports(self):
        print(f"Scanning open ports on {self.ip_address}...")
        nm = nmap.PortScanner()
        try:
            nm.scan(self.ip_address, '1-65535')
            self.open_ports = [(port, nm[self.ip_address]['tcp'][port]['name']) for port in nm[self.ip_address].all_tcp()]
            print(f"Open ports found: {self.open_ports}")
        except Exception as e:
            print(f"Error scanning ports: {e}")
        return self.open_ports

    def attempt_ssh_login(self, credentials):
        print("Attempting SSH login...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for username, password in credentials.items():
            try:
                ssh.connect(self.ip_address, username=username, password=password, timeout=5)
                self.ssh_credentials.append((username, password))
                print(f"SSH login successful with {username}/{password}")
                break
            except paramiko.AuthenticationException:
                continue
            except paramiko.SSHException as e:
                print(f"SSH error: {e}")
                break
        ssh.close()
        return self.ssh_credentials

    def check_ssl_certificate(self, url):
        print("Checking SSL certificate...")
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        context = ssl.create_default_context()

        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    self.ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter']
                    }
            print(f"SSL Certificate Info: {self.ssl_info}")
        except Exception as e:
            print(f"Error checking SSL certificate: {e}")
        return self.ssl_info

    def check_known_vulnerabilities(self):
        print("Checking for known vulnerabilities...")
        cve_api_url = f"https://cve.circl.lu/api/search/{self.ip_address}"
        try:
            response = requests.get(cve_api_url)
            if response.status_code == 200:
                vulnerabilities = response.json()
                for vulnerability in vulnerabilities:
                    print(f"Vulnerability found: {vulnerability['id']} - {vulnerability['summary']}")
                    self.vulnerabilities.append(vulnerability)
            else:
                print("No known vulnerabilities found.")
        except Exception as e:
            print(f"Error checking vulnerabilities: {e}")
        return self.vulnerabilities

    def suggest_mitigations(self):
        print("Suggesting mitigations...")
        mitigations = []
        if self.open_ports:
            mitigations.append("Close unnecessary ports.")
        if self.ssh_credentials:
            mitigations.append("Change SSH default credentials.")
        if self.ssl_info:
            current_time = datetime.utcnow()
            not_after = datetime.strptime(self.ssl_info['notAfter'], "%b %d %H:%M:%S %Y GMT")
            if not_after < current_time:
                mitigations.append("Update SSL certificate (expired).")
        if self.vulnerabilities:
            mitigations.append("Apply patches for known vulnerabilities.")
        if not mitigations:
            mitigations.append("No mitigations necessary. Device appears secure.")
        return mitigations

    def analyze_security(self, url=None, credentials=None):
        print(f"Starting security analysis for {self.ip_address} at {datetime.now()}...\n")
        self.scan_open_ports()
        if credentials:
            self.attempt_ssh_login(credentials)
        if url:
            self.check_ssl_certificate(url)
        self.check_known_vulnerabilities()
        mitigations = self.suggest_mitigations()
        print("\nMitigations:")
        for mitigation in mitigations:
            print(f"- {mitigation}")
        print("\nSecurity analysis completed.\n")

def run_analysis_from_file(file_path, credentials):
    with open(file_path, 'r') as file:
        devices = json.load(file)
        for device in devices:
            ip = device.get('ip')
            url = device.get('url')
            analyzer = IoTDeviceSecurityAnalyzer(ip)
            analyzer.analyze_security(url=url, credentials=credentials)

def print_help():
    help_text = """
IoT Device Security Analyzer - Help

This tool allows you to scan and analyze the security of IoT devices. Below are the available functions:

1. scan_open_ports: Scan all TCP ports on the device and identify open ports.
2. attempt_ssh_login: Attempt SSH login using default or provided credentials.
3. check_ssl_certificate: Validate the SSL certificate of the device's web interface.
4. check_known_vulnerabilities: Query public CVE databases for known vulnerabilities associated with the device.
5. suggest_mitigations: Suggest actions to mitigate identified security risks.
6. analyze_security: Perform a full security analysis combining all of the above.
7. run_analysis_from_file: Run a security analysis on multiple devices from a JSON file.

To use this tool:
- Run with the IP address and (optional) URL and credentials.
- Pass a JSON file with multiple devices to analyze them in bulk.
- Use the --help flag to see this help message.

"""
    print(help_text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IoT Device Security Analyzer")
    parser.add_argument('--file', type=str, help='Path to the JSON file containing IP addresses and URLs.')
    parser.add_argument('--ip', type=str, help='IP address of the IoT device.')
    parser.add_argument('--url', type=str, help='URL of the IoT device.')
    parser.add_argument('--credentials', type=str, help='Path to a JSON file containing custom credentials.')
    parser.add_argument('--help', action='store_true', help='Show help information.')

    args = parser.parse_args()

    if args.help:
        print_help()
    else:
        credentials = {'root': 'root', 'admin': 'admin', 'user': 'user'}  # Default credentials
        if args.credentials:
            with open(args.credentials, 'r') as creds_file:
                credentials = json.load(creds_file)

        if args.file:
            run_analysis_from_file(args.file, credentials)
        elif args.ip:
            analyzer = IoTDeviceSecurityAnalyzer(args.ip)
            analyzer.analyze_security(url=args.url, credentials=credentials)
        else:
            print("Please provide an IP address or a file containing device details.")
