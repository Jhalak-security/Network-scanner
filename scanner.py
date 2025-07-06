import socket
from datetime import datetime
import requests

# Common ports and associated services
common_ports = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql"
}

def fetch_cves(service_name, max_results=3):
    try:
        url = f"https://cve.circl.lu/api/search/{service_name}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            cve_list = []
            for item in data.get("data", [])[:max_results]:
                cve_id = item.get("id", "N/A")
                summary = item.get("summary", "No description")
                cvss = item.get("cvss", "N/A")
                cve_list.append(f"{cve_id}: {summary} [CVSS: {cvss}]")
            return cve_list
        else:
            return ["Error fetching CVE data."]
    except Exception as e:
        return [f"Exception: {str(e)}"]

def scan_target(ip):
    print(f"\n🔍 Starting scan on {ip} at {datetime.now()}\n")
    open_ports = {}

    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = common_ports[port]
                print(f"[+] Port {port} OPEN ({service})")
                open_ports[port] = service
            sock.close()
        except Exception as e:
            print(f"[-] Error scanning port {port}: {e}")

    return open_ports

def check_vulnerabilities(services):
    findings = {}
    for port, service in services.items():
        cves = fetch_cves(service)
        if cves:
            findings[port] = cves
    return findings

def generate_report(ip, open_ports, vulns):
    report_lines = []

    report_lines.append("\n📄 --- Scan Report ---\n")
    report_lines.append(f"Target IP: {ip}")
    report_lines.append(f"Scan Time: {datetime.now()}\n")

    report_lines.append("Open Ports:")
    if open_ports:
        for port, service in open_ports.items():
            report_lines.append(f"  - Port {port}: {service.upper()}")
    else:
        report_lines.append("  ❌ No open ports found.")

    if vulns:
        report_lines.append("\nPotential Vulnerabilities Found:")
        for port, issues in vulns.items():
            report_lines.append(f"  Port {port} ({open_ports[port]}):")
            for issue in issues:
                report_lines.append(f"    - {issue}")
    else:
        report_lines.append("\n✅ No known vulnerabilities found in scanned services.")

    report_lines.append("\n📌 End of Report\n")

    # Print to terminal
    for line in report_lines:
        print(line)

    # Save to file
    filename = f"scan_report_{ip.replace('.', '_')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        for line in report_lines:
            f.write(line + "\n")

    print(f"\n📁 Report saved to: {filename}")

# --- MAIN ---
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
    print("Usage: python scanner.py <target_ip>")
    sys.exit(1)

    target_ip = sys.argv[1]

    scanned_services = scan_target(target_ip)
    vulnerabilities = check_vulnerabilities(scanned_services)
    generate_report(target_ip, scanned_services, vulnerabilities)
