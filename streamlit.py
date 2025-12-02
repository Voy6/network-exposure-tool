#!/usr/bin/env python3

import xml.etree.ElementTree as ET
from pathlib import Path

import streamlit as st


HIGH_RISK_PORTS = {
    21: "FTP often misconfigured; cleartext credentials.",
    22: "SSH is a common target for brute-force and key attacks.",
    23: "Telnet is insecure and cleartext.",
    25: "SMTP can be abused for spam or open relay.",
    80: "HTTP (web vulns, outdated apps).",
    139: "SMB/NetBIOS; lateral movement and info leakage.",
    445: "SMB (EternalBlue-style exploits).",
    3306: "MySQL database exposure.",
}


def parse_nmap_xml(xml_bytes: bytes):
    hosts = []

    root = ET.fromstring(xml_bytes)
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr = host.find("address[@addrtype='ipv4']")
        ip = addr.get("addr") if addr is not None else "unknown"

        ports_node = host.find("ports")
        open_ports = []
        if ports_node is not None:
            for port_el in ports_node.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                portid = int(port_el.get("portid"))
                proto = port_el.get("protocol", "tcp")
                service_el = port_el.find("service")
                service_name = service_el.get("name") if service_el is not None else "unknown"

                if portid in HIGH_RISK_PORTS:
                    risk = "HIGH"
                    reason = HIGH_RISK_PORTS[portid]
                else:
                    risk = "MODERATE"
                    reason = "Not in high-risk list, but still exposed."

                open_ports.append(
                    {
                        "Port": portid,
                        "Protocol": proto,
                        "Service": service_name,
                        "Risk": risk,
                        "Reason": reason,
                    }
                )

        hosts.append({"ip": ip, "ports": open_ports})

    return hosts


def main():
    st.title("Network Exposure Assessment (Nmap XML Parser)")
    st.write(
        "Upload an Nmap XML report and I’ll extract open ports, classify risk, "
        "and show a human-readable exposure summary."
    )

    uploaded_file = st.file_uploader("Upload Nmap XML file", type=["xml"])

    if uploaded_file is not None:
        try:
            xml_bytes = uploaded_file.read()
            hosts = parse_nmap_xml(xml_bytes)
        except Exception as e:
            st.error(f"Failed to parse XML: {e}")
            return

        if not hosts:
            st.warning("No up hosts with open ports found in the XML.")
            return

        for host in hosts:
            st.subheader(f"Host: {host['ip']}")
            if not host["ports"]:
                st.write("No open ports.")
                continue

            st.table(host["ports"])

        # Simple global summary
        total_hosts = len(hosts)
        total_open_ports = sum(len(h["ports"]) for h in hosts)
        high_risk_count = sum(
            1 for h in hosts for p in h["ports"] if p["Risk"] == "HIGH"
        )

        st.markdown("---")
        st.markdown("### Summary")
        st.write(f"- Hosts analysed: **{total_hosts}**")
        st.write(f"- Total open ports: **{total_open_ports}**")
        st.write(f"- High-risk services: **{high_risk_count}**")


if __name__ == "__main__":
    main()
