#!/usr/bin/env python3

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

#Stating the ports I know to be High Risk and how they are exposed.

PORT_RISKS = {
    21:  ("HIGH",   "FTP exposed; cleartext credentials and common misconfigurations."),
    22:  ("HIGH",   "SSH exposed; frequent target for brute-force and key abuse."),
    23:  ("HIGH",   "Telnet uses cleartext; credentials and sessions easily intercepted."),
    25:  ("HIGH",   "SMTP exposed; risk of spam relay, spoofing, and information leakage."),
    53:  ("MEDIUM", "DNS service exposed; can be abused for enumeration or tunnelling."),
    80:  ("HIGH",   "HTTP exposed; web vulnerabilities and outdated applications likely."),
    111: ("MEDIUM", "rpcbind exposed; can aid enumeration and access to NFS/RPC services."),
    139: ("HIGH",   "SMB/NetBIOS; file sharing and lateral movement vector."),
    445: ("HIGH",   "SMB; known for worms/exploits (e.g., EternalBlue) and lateral movement."),
    512: ("HIGH",   "rsh/exec; legacy cleartext remote execution service."),
    513: ("HIGH",   "rlogin/login; legacy cleartext remote login; trust-based abuse."),
    514: ("HIGH",   "shell/rshd; remote shell over cleartext; high risk of compromise."),
    1099:("HIGH",   "Java RMI; historically vulnerable to remote code execution."),
    1524:("HIGH",   "Backdoor bindshell present; direct remote shell access."),
    2049:("HIGH",   "NFS exposed; potential access to exported filesystems."),
    2121:("HIGH",   "Secondary FTP service; doubles FTP attack surface and misconfig risk."),
    3306:("HIGH",   "MySQL database exposed; potential data exfiltration and RCE via SQL."),
    5432:("HIGH",   "PostgreSQL database exposed; direct database and data access."),
    5900:("HIGH",   "VNC remote desktop exposed; brute force and session hijack risk."),
    6000:("HIGH",   "X11 (remote display) exposed; can allow session snooping and control."),
    6667:("MEDIUM", "IRC service; can be used for botnet C2 or internal communications."),
    8009:("HIGH",   "AJP13 exposed; misconfigurations can lead to remote code execution."),
    8180:("HIGH",   "Alternate HTTP/Tomcat; often exposes admin interfaces or apps."),
}


def run_nmap_scan(target: str) -> str:

	print(f"[+] Running Nmap scan against {target} ...")

	result = subprocess.run(
		["nmap", "-sV", "-O", "-T4", "-oX", "-", target],
		capture_output=True,
		text=True,
		check=True,
)
	print("[+] Scan completed.")

	debug_path = Path("debug_scan.xml")
	debug_path.write_text(result.stdout, encoding="utf-8")
	print(f"[+] Debug XML saved to {debug_path.resolve()}")


	return result.stdout


def parse_nmap_xml(xml_data: str):
    """
    Parses Nmap XML data and returns a structured list of hosts and their open ports.
    Each host is a dict: {"ip": str, "ports": [{"port": int, "protocol": str, "service": str}]}
    """
    hosts = []
    root = ET.fromstring(xml_data)


    for host in root.findall("host"):
        status_el = host.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        ports_info = []


        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = int(port_el.get("portid"))
            protocol = port_el.get("protocol")

            service_el = port_el.find("service")
            service_name = service_el.get("name") if service_el is not None else "unknown"

            ports_info.append({
                "port": portid,
                "protocol": protocol,
                "service": service_name,
            })

        if ports_info:
            hosts.append({
                "ip": ip,
                "ports": ports_info,
            })

    print(f"[DEBUG] Parsed {len(hosts)} host(s) with open ports from XML")
    return hosts



def classify_risks(hosts):

	for host in hosts:
		for port in host["ports"]:
			port_number = port["port"]
			if port_number in PORT_RISKS:
				risk_level, reason = PORT_RISKS[port_number]
				port["risk"] = risk_level
				port["reason"] = PORT_RISKS[port_number]
			else:
				port["risk"] = "MEDIUM"
				port["reason"] = "Service exposed; not explicity classifed but still increase attack surface."
	return hosts


def generate_markdown_report(hosts, target: str) -> str:

	lines = [ ]
	lines.append(f"# Network Exposure Report for '{target}'\n")
	lines.append("This report summarises open ports and their risk levels.\n")

	if not hosts:
		lines.append("No open ports found.\n")
		return "\n".join(lines)

	for host in hosts:
		lines.append(f"## Host: {host['ip']}\n")
		lines.append("| Port | Protocol | Service | Risk | Reason |")
		lines.append("| ---- | -------- | ------- | ---- | ------ |")
		for port in host["ports"]:
			lines.append(
				f"| {port['port']} | {port['protocol']} | {port['service']} | {port['risk']} | {port['reason']} |"
			)
		lines.append("")

	return "\n".join(lines)


def save_report(content: str, filename: str = "report.md") -> Path:
	path = Path(filename)
	path.write_text(content, encoding="utf-8")
	print(f"[+] Report saved to {path.resolve()}")
	return path

def main():
	target= input("Enter the target IP or hostname: ").strip()
	if not target:
		print("[-] No target provided. Adios. ")
		return

	xml_output = run_nmap_scan(target)
	hosts = parse_nmap_xml(xml_output)
	hosts_with_risks = classify_risks(hosts)
	report_md = generate_markdown_report(hosts_with_risks, target)
	save_report(report_md)

if __name__ == "__main__":
	main()
