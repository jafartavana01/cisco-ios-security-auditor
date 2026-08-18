#!/usr/bin/env python3
"""
One-off generator for the compliance mapping JSON files shipped in mappings/.
Not part of the runtime tool -- run once to (re)produce the JSON, then discard
or keep for future maintenance. Keeping this as a script (rather than hand-
editing JSON) makes it much less error-prone to extend later.
"""
import json
from pathlib import Path

OUT_DIR = Path(__file__).parent / "mappings"
OUT_DIR.mkdir(exist_ok=True)

# =============================================================================
# NIST SP 800-53 Rev. 5  (public domain -- US government work, no copyright
# restriction on quoting control identifiers or titles)
# =============================================================================
NIST = {
    "AAA-01": [{"control": "AC-3", "title": "Access Enforcement", "relationship": "direct"}],
    "AAA-02": [{"control": "IA-2", "title": "Identification and Authentication (Organizational Users)", "relationship": "direct"}],
    "AAA-03": [{"control": "CP-2", "title": "Contingency Plan", "relationship": "supporting"}],
    "AAA-04": [{"control": "AC-6", "title": "Least Privilege", "relationship": "direct"}],
    "AAA-05": [{"control": "AC-6", "title": "Least Privilege", "relationship": "direct"}],
    "AAA-06": [{"control": "AU-2", "title": "Event Logging", "relationship": "direct"}],
    "AAA-07": [{"control": "AU-2", "title": "Event Logging", "relationship": "direct"}],
    "AAA-08": [{"control": "AC-7", "title": "Unsuccessful Logon Attempts", "relationship": "direct"}],
    "AAA-09": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"}],
    "AAA-10": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"}],
    "AAA-11": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"}],
    "USR-01": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"}],
    "USR-02": [{"control": "IA-4", "title": "Identifier Management", "relationship": "direct"}],
    "USR-03": [{"control": "AC-6", "title": "Least Privilege", "relationship": "supporting"}],
    "SSH-01": [{"control": "SC-8", "title": "Transmission Confidentiality and Integrity", "relationship": "direct"}],
    "SSH-02": [{"control": "SC-8", "title": "Transmission Confidentiality and Integrity", "relationship": "direct"},
               {"control": "AC-17", "title": "Remote Access", "relationship": "direct"}],
    "SSH-03": [{"control": "AC-17", "title": "Remote Access", "relationship": "direct"},
               {"control": "AC-4", "title": "Information Flow Enforcement", "relationship": "supporting"}],
    "SSH-04": [{"control": "AC-12", "title": "Session Termination", "relationship": "direct"}],
    "SSH-05": [{"control": "AC-12", "title": "Session Termination", "relationship": "direct"}],
    "SSH-06": [{"control": "AC-7", "title": "Unsuccessful Logon Attempts", "relationship": "direct"}],
    "SSH-07": [{"control": "SC-13", "title": "Cryptographic Protection", "relationship": "direct"}],
    "SSH-08": [{"control": "SC-13", "title": "Cryptographic Protection", "relationship": "direct"}],
    "HTTP-01": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "HTTP-02": [{"control": "AC-17", "title": "Remote Access", "relationship": "direct"}],
    "SNMP-01": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"}],
    "SNMP-02": [{"control": "SC-8", "title": "Transmission Confidentiality and Integrity", "relationship": "direct"}],
    "SNMP-03": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"},
                {"control": "SC-13", "title": "Cryptographic Protection", "relationship": "direct"}],
    "SNMP-04": [{"control": "AC-4", "title": "Information Flow Enforcement", "relationship": "direct"}],
    "NTP-01": [{"control": "AU-8", "title": "Timestamps", "relationship": "direct"}],
    "NTP-02": [{"control": "AU-8", "title": "Timestamps", "relationship": "direct"}],
    "NTP-03": [{"control": "AU-8", "title": "Timestamps", "relationship": "direct"}],
    "NTP-04": [{"control": "AC-4", "title": "Information Flow Enforcement", "relationship": "supporting"}],
    "LOG-01": [{"control": "AU-9", "title": "Protection of Audit Information", "relationship": "direct"},
               {"control": "AU-4", "title": "Audit Log Storage Capacity", "relationship": "supporting"}],
    "LOG-02": [{"control": "AU-8", "title": "Timestamps", "relationship": "direct"}],
    "LOG-03": [{"control": "AU-2", "title": "Event Logging", "relationship": "direct"}],
    "LOG-04": [{"control": "AU-2", "title": "Event Logging", "relationship": "direct"}],
    "BAN-01": [{"control": "AC-8", "title": "System Use Notification", "relationship": "direct"}],
    "DNS-01": [{"control": "SC-20", "title": "Secure Name/Address Resolution Service (Authoritative Source)", "relationship": "supporting"}],
    "MPP-01": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "EXP-RESTCONF": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "EXP-NETCONF": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "EXP-GNMI": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "EXP-IOX": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "EXP-TFTP": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"},
                 {"control": "SC-8", "title": "Transmission Confidentiality and Integrity", "relationship": "supporting"}],
    "EXP-FTP": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "EXP-SCP": [{"control": "SC-8", "title": "Transmission Confidentiality and Integrity", "relationship": "supporting"}],
    "EXP-GUESTSHELL": [{"control": "CM-7", "title": "Least Functionality", "relationship": "supporting"}],
    "PWD-01": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"}],
    "PWD-02": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"}],
    "PWD-03": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"}],
    "PWD-04": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"}],

    "L2PS-01": [{"control": "AC-3", "title": "Access Enforcement", "relationship": "direct"},
                {"control": "SC-7", "title": "Boundary Protection", "relationship": "supporting"}],
    "L2PS-02": [{"control": "AC-3", "title": "Access Enforcement", "relationship": "direct"}],
    "L2PS-03": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "supporting"}],
    "L2PS-04": [{"control": "AU-2", "title": "Event Logging", "relationship": "direct"}],
    "STP-01": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "STP-02": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "STP-03": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "supporting"}],
    "STP-04": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "supporting"}],
    "UDLD-01": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "supporting"}],
    "STORM-01": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "DHCPSNOOP-01": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"},
                      {"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "supporting"}],
    "DHCPSNOOP-02": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "DHCPSNOOP-03": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "DHCPSNOOP-04": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "DHCPSNOOP-05": [{"control": "AC-6", "title": "Least Privilege", "relationship": "supporting"}],
    "DAI-01": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "DAI-02": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "direct"}],
    "DAI-03": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "supporting"}],
    "DAI-04": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "DAI-05": [{"control": "CM-8", "title": "System Component Inventory", "relationship": "supporting"}],
    "IPSG-01": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "TRUNK-01": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "TRUNK-02": [{"control": "AC-4", "title": "Information Flow Enforcement", "relationship": "direct"}],
    "TRUNK-03": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "direct"}],
    "VTP-01": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "direct"}],
    "ECHAN-01": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "supporting"}],

    "URPF-01": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"},
                {"control": "SC-7", "title": "Boundary Protection", "relationship": "supporting"}],
    "URPF-02": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "supporting"}],
    "RTAUTH-OSPF-01": [{"control": "IA-2", "title": "Identification and Authentication (Organizational Users)", "relationship": "direct"}],
    "RTAUTH-OSPF-02": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "supporting"}],
    "RTAUTH-EIGRP-01": [{"control": "IA-2", "title": "Identification and Authentication (Organizational Users)", "relationship": "direct"}],
    "RTAUTH-RIP-01": [{"control": "IA-2", "title": "Identification and Authentication (Organizational Users)", "relationship": "direct"}],
    "RTAUTH-BGP-01": [{"control": "IA-2", "title": "Identification and Authentication (Organizational Users)", "relationship": "direct"}],
    "RTAUTH-BGP-02": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "RTAUTH-BGP-03": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "RTAUTH-BGP-04": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "supporting"}],
    "RTAUTH-ISIS-01": [{"control": "IA-2", "title": "Identification and Authentication (Organizational Users)", "relationship": "direct"}],
    "FHRP-HSRP-01": [{"control": "IA-2", "title": "Identification and Authentication (Organizational Users)", "relationship": "direct"}],
    "FHRP-HSRP-02": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"}],
    "FHRP-VRRP-01": [{"control": "IA-2", "title": "Identification and Authentication (Organizational Users)", "relationship": "direct"}],
    "ICMP-01": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "ICMP-02": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "ICMP-03": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "supporting"}],
    "ICMP-04": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "ICMP-05": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "ACL-01": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "supporting"}],
    "ACL-02": [{"control": "AC-4", "title": "Information Flow Enforcement", "relationship": "direct"}],
    "ACL-03": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "supporting"}],
    "ACL-04": [{"control": "AU-2", "title": "Event Logging", "relationship": "supporting"}],
    "ACL-05": [{"control": "AC-4", "title": "Information Flow Enforcement", "relationship": "supporting"}],
    "TRACK-01": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "supporting"}],
    "TRACK-02": [{"control": "CM-8", "title": "System Component Inventory", "relationship": "supporting"}],

    "COPP-01": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "COPP-CLASS-ICMP": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "COPP-CLASS-ROUTING": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "COPP-CLASS-ARP": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "COPP-CLASS-L2CTRL": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "COPP-CLASS-MGMT": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "COPP-CLASS-DHCP": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "COPP-CLASS-FHRP": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "COPP-CLASS-MCAST": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "CPURISK-01": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "CPURISK-02": [{"control": "CM-7", "title": "Least Functionality", "relationship": "supporting"}],
    "CPURISK-03": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "CPURISK-04": [{"control": "CM-7", "title": "Least Functionality", "relationship": "supporting"}],
    "CPURISK-05": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "supporting"}],
    "CPURISK-06": [{"control": "AU-2", "title": "Event Logging", "relationship": "supporting"}],

    "VPN-01": [{"control": "SC-13", "title": "Cryptographic Protection", "relationship": "direct"}],
    "VPN-02": [{"control": "SC-8", "title": "Transmission Confidentiality and Integrity", "relationship": "supporting"}],
    "VPN-03": [{"control": "SC-13", "title": "Cryptographic Protection", "relationship": "direct"}],
    "VPN-04": [{"control": "SC-12", "title": "Cryptographic Key Establishment and Management", "relationship": "direct"}],
    "VPN-05": [{"control": "SC-12", "title": "Cryptographic Key Establishment and Management", "relationship": "direct"}],
    "VPN-06": [{"control": "SC-13", "title": "Cryptographic Protection", "relationship": "supporting"}],
    "VPN-07": [{"control": "SC-12", "title": "Cryptographic Key Establishment and Management", "relationship": "direct"}],

    "ZBFW-01": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "ZBFW-02": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "ZBFW-03": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "ZBFW-04": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],

    "PKI-01": [{"control": "SC-17", "title": "Public Key Infrastructure Certificates", "relationship": "direct"}],
    "PKI-02": [{"control": "SC-17", "title": "Public Key Infrastructure Certificates", "relationship": "direct"}],
    "PKI-03": [{"control": "SC-17", "title": "Public Key Infrastructure Certificates", "relationship": "supporting"}],
    "PKI-04": [{"control": "SC-17", "title": "Public Key Infrastructure Certificates", "relationship": "supporting"}],
    "PKI-05": [{"control": "SC-13", "title": "Cryptographic Protection", "relationship": "direct"}],
    "PKI-06": [{"control": "SC-12", "title": "Cryptographic Key Establishment and Management", "relationship": "direct"}],
    "PKI-07": [{"control": "SC-17", "title": "Public Key Infrastructure Certificates", "relationship": "direct"}],
    "PKI-08": [{"control": "SC-17", "title": "Public Key Infrastructure Certificates", "relationship": "direct"}],
    "PKI-09": [{"control": "SC-17", "title": "Public Key Infrastructure Certificates", "relationship": "direct"}],
    "PKI-10": [{"control": "SC-17", "title": "Public Key Infrastructure Certificates", "relationship": "direct"}],
    "PKI-11": [{"control": "SC-17", "title": "Public Key Infrastructure Certificates", "relationship": "supporting"}],

    "PHYS-01": [{"control": "MP-6", "title": "Media Sanitization", "relationship": "supporting"},
                {"control": "PE-3", "title": "Physical Access Control", "relationship": "supporting"}],
    "PHYS-02": [{"control": "AC-12", "title": "Session Termination", "relationship": "direct"}],
    "PHYS-03": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "PHYS-04": [{"control": "MP-6", "title": "Media Sanitization", "relationship": "direct"}],
    "PHYS-05": [{"control": "PE-3", "title": "Physical Access Control", "relationship": "direct"}],
    "BOOT-01": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "direct"}],
    "BOOT-02": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "supporting"}],
    "BOOT-03": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "BOOT-04": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "direct"}],
    "BOOT-05": [{"control": "SI-7", "title": "Software, Firmware, and Information Integrity", "relationship": "direct"}],
    "BOOT-06": [{"control": "SI-7", "title": "Software, Firmware, and Information Integrity", "relationship": "supporting"}],
    "BOOT-07": [{"control": "SC-28", "title": "Protection of Information at Rest", "relationship": "supporting"}],
    "BOOT-08": [{"control": "IA-5", "title": "Authenticator Management", "relationship": "direct"}],
    "BOOT-09": [{"control": "SI-7", "title": "Software, Firmware, and Information Integrity", "relationship": "supporting"}],

    "SVC-01": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "SVC-02": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "SVC-03": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "SVC-04": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "SVC-05": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "SVC-06": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "SVC-07": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "SVC-08": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"},
               {"control": "SI-3", "title": "Malicious Code Protection", "relationship": "supporting"}],
    "SVC-09": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "SVC-10": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "MISC-01": [{"control": "SI-4", "title": "System Monitoring", "relationship": "supporting"}],
    "MISC-02": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "supporting"}],
    "MISC-03": [{"control": "CM-7", "title": "Least Functionality", "relationship": "direct"}],
    "MISC-04": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "supporting"}],
    "MISC-05": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "VER-01": [{"control": "SI-2", "title": "Flaw Remediation", "relationship": "supporting"}],

    "CORR-01": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "CORR-02": [{"control": "CM-8", "title": "System Component Inventory", "relationship": "supporting"}],
    "CORR-03": [{"control": "AC-17", "title": "Remote Access", "relationship": "direct"},
                {"control": "AC-4", "title": "Information Flow Enforcement", "relationship": "supporting"}],
    "CORR-04": [{"control": "AC-4", "title": "Information Flow Enforcement", "relationship": "direct"}],
    "CORR-05": [{"control": "SC-7", "title": "Boundary Protection", "relationship": "direct"}],
    "CORR-06": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "supporting"}],
    "CORR-07": [{"control": "SC-5", "title": "Denial-of-Service Protection", "relationship": "direct"}],
    "CORR-08": [{"control": "SC-17", "title": "Public Key Infrastructure Certificates", "relationship": "direct"}],
    "CORR-09": [{"control": "CM-6", "title": "Configuration Settings", "relationship": "direct"}],
    "CORR-10": [{"control": "CM-7", "title": "Least Functionality", "relationship": "supporting"}],
}

# =============================================================================
# ISO/IEC 27002:2022 -- control numbers + short conventional titles only
# (no descriptive/guidance text reproduced -- that content is ISO's
# copyrighted, commercially-sold material)
# =============================================================================
ISO = {
    "AAA-01": [{"control": "5.15", "title": "Access control", "relationship": "direct"}],
    "AAA-02": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "AAA-03": [{"control": "5.29", "title": "Information security during disruption", "relationship": "supporting"}],
    "AAA-04": [{"control": "8.2", "title": "Privileged access rights", "relationship": "direct"}],
    "AAA-05": [{"control": "8.2", "title": "Privileged access rights", "relationship": "direct"}],
    "AAA-06": [{"control": "8.15", "title": "Logging", "relationship": "direct"}],
    "AAA-07": [{"control": "8.15", "title": "Logging", "relationship": "direct"}],
    "AAA-08": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "AAA-09": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "AAA-10": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "AAA-11": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "USR-01": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "USR-02": [{"control": "5.16", "title": "Identity management", "relationship": "direct"}],
    "USR-03": [{"control": "8.2", "title": "Privileged access rights", "relationship": "direct"}],
    "SSH-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "SSH-02": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "SSH-03": [{"control": "8.20", "title": "Networks security", "relationship": "direct"},
               {"control": "5.15", "title": "Access control", "relationship": "supporting"}],
    "SSH-04": [{"control": "8.5", "title": "Secure authentication", "relationship": "supporting"}],
    "SSH-05": [{"control": "8.5", "title": "Secure authentication", "relationship": "supporting"}],
    "SSH-06": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "SSH-07": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "SSH-08": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "HTTP-01": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "HTTP-02": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "SNMP-01": [{"control": "8.24", "title": "Use of cryptography", "relationship": "supporting"},
                {"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "SNMP-02": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "SNMP-03": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "SNMP-04": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "NTP-01": [{"control": "8.17", "title": "Clock synchronization", "relationship": "direct"}],
    "NTP-02": [{"control": "8.17", "title": "Clock synchronization", "relationship": "direct"}],
    "NTP-03": [{"control": "8.17", "title": "Clock synchronization", "relationship": "direct"}],
    "NTP-04": [{"control": "8.20", "title": "Networks security", "relationship": "supporting"}],
    "LOG-01": [{"control": "8.15", "title": "Logging", "relationship": "direct"}],
    "LOG-02": [{"control": "8.17", "title": "Clock synchronization", "relationship": "supporting"}],
    "LOG-03": [{"control": "8.16", "title": "Monitoring activities", "relationship": "direct"}],
    "LOG-04": [{"control": "8.16", "title": "Monitoring activities", "relationship": "supporting"}],
    "BAN-01": [{"control": "5.10", "title": "Acceptable use of information and other associated assets", "relationship": "supporting"}],
    "DNS-01": [{"control": "8.20", "title": "Networks security", "relationship": "supporting"}],
    "MPP-01": [{"control": "8.22", "title": "Segregation of networks", "relationship": "direct"}],
    "EXP-RESTCONF": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "EXP-NETCONF": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "EXP-GNMI": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "EXP-IOX": [{"control": "8.19", "title": "Installation of software on operational systems", "relationship": "direct"}],
    "EXP-TFTP": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "EXP-FTP": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "EXP-SCP": [{"control": "8.24", "title": "Use of cryptography", "relationship": "supporting"}],
    "EXP-GUESTSHELL": [{"control": "8.19", "title": "Installation of software on operational systems", "relationship": "supporting"}],
    "PWD-01": [{"control": "8.24", "title": "Use of cryptography", "relationship": "supporting"}],
    "PWD-02": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "PWD-03": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "PWD-04": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],

    "L2PS-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "L2PS-02": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "L2PS-03": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],
    "L2PS-04": [{"control": "8.16", "title": "Monitoring activities", "relationship": "direct"}],
    "STP-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "STP-02": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "STP-03": [{"control": "8.20", "title": "Networks security", "relationship": "supporting"}],
    "STP-04": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],
    "UDLD-01": [{"control": "8.20", "title": "Networks security", "relationship": "supporting"}],
    "STORM-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "DHCPSNOOP-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "DHCPSNOOP-02": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "DHCPSNOOP-03": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "DHCPSNOOP-04": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "DHCPSNOOP-05": [{"control": "8.2", "title": "Privileged access rights", "relationship": "supporting"}],
    "DAI-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "DAI-02": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "DAI-03": [{"control": "8.20", "title": "Networks security", "relationship": "supporting"}],
    "DAI-04": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "DAI-05": [{"control": "8.16", "title": "Monitoring activities", "relationship": "supporting"}],
    "IPSG-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "TRUNK-01": [{"control": "8.22", "title": "Segregation of networks", "relationship": "direct"}],
    "TRUNK-02": [{"control": "8.22", "title": "Segregation of networks", "relationship": "direct"}],
    "TRUNK-03": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "VTP-01": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "ECHAN-01": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],

    "URPF-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "URPF-02": [{"control": "8.20", "title": "Networks security", "relationship": "supporting"}],
    "RTAUTH-OSPF-01": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "RTAUTH-OSPF-02": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],
    "RTAUTH-EIGRP-01": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "RTAUTH-RIP-01": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "RTAUTH-BGP-01": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "RTAUTH-BGP-02": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "RTAUTH-BGP-03": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "RTAUTH-BGP-04": [{"control": "8.20", "title": "Networks security", "relationship": "supporting"}],
    "RTAUTH-ISIS-01": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "FHRP-HSRP-01": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "FHRP-HSRP-02": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "FHRP-VRRP-01": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "ICMP-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "ICMP-02": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "ICMP-03": [{"control": "8.20", "title": "Networks security", "relationship": "supporting"}],
    "ICMP-04": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "ICMP-05": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "ACL-01": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],
    "ACL-02": [{"control": "8.3", "title": "Information access restriction", "relationship": "direct"}],
    "ACL-03": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],
    "ACL-04": [{"control": "8.16", "title": "Monitoring activities", "relationship": "supporting"}],
    "ACL-05": [{"control": "8.3", "title": "Information access restriction", "relationship": "supporting"}],
    "TRACK-01": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],
    "TRACK-02": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],

    "COPP-01": [{"control": "8.6", "title": "Capacity management", "relationship": "direct"}],
    "COPP-CLASS-ICMP": [{"control": "8.6", "title": "Capacity management", "relationship": "direct"}],
    "COPP-CLASS-ROUTING": [{"control": "8.6", "title": "Capacity management", "relationship": "direct"}],
    "COPP-CLASS-ARP": [{"control": "8.6", "title": "Capacity management", "relationship": "direct"}],
    "COPP-CLASS-L2CTRL": [{"control": "8.6", "title": "Capacity management", "relationship": "direct"}],
    "COPP-CLASS-MGMT": [{"control": "8.6", "title": "Capacity management", "relationship": "direct"}],
    "COPP-CLASS-DHCP": [{"control": "8.6", "title": "Capacity management", "relationship": "direct"}],
    "COPP-CLASS-FHRP": [{"control": "8.6", "title": "Capacity management", "relationship": "direct"}],
    "COPP-CLASS-MCAST": [{"control": "8.6", "title": "Capacity management", "relationship": "direct"}],
    "CPURISK-01": [{"control": "8.6", "title": "Capacity management", "relationship": "direct"}],
    "CPURISK-02": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],
    "CPURISK-03": [{"control": "8.32", "title": "Change management", "relationship": "direct"}],
    "CPURISK-04": [{"control": "8.6", "title": "Capacity management", "relationship": "supporting"}],
    "CPURISK-05": [{"control": "8.6", "title": "Capacity management", "relationship": "supporting"}],
    "CPURISK-06": [{"control": "8.16", "title": "Monitoring activities", "relationship": "supporting"}],

    "VPN-01": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "VPN-02": [{"control": "8.20", "title": "Networks security", "relationship": "supporting"}],
    "VPN-03": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "VPN-04": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "VPN-05": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "VPN-06": [{"control": "8.24", "title": "Use of cryptography", "relationship": "supporting"}],
    "VPN-07": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],

    "ZBFW-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "ZBFW-02": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "ZBFW-03": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "ZBFW-04": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],

    "PKI-01": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "PKI-02": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "PKI-03": [{"control": "8.24", "title": "Use of cryptography", "relationship": "supporting"}],
    "PKI-04": [{"control": "8.24", "title": "Use of cryptography", "relationship": "supporting"}],
    "PKI-05": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "PKI-06": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "PKI-07": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "PKI-08": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "PKI-09": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "PKI-10": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "PKI-11": [{"control": "8.24", "title": "Use of cryptography", "relationship": "supporting"}],

    "PHYS-01": [{"control": "7.10", "title": "Storage media", "relationship": "supporting"}],
    "PHYS-02": [{"control": "8.5", "title": "Secure authentication", "relationship": "supporting"}],
    "PHYS-03": [{"control": "7.9", "title": "Security of assets off-premises", "relationship": "supporting"}],
    "PHYS-04": [{"control": "7.10", "title": "Storage media", "relationship": "direct"},
                {"control": "7.14", "title": "Secure disposal or re-use of equipment", "relationship": "direct"}],
    "PHYS-05": [{"control": "7.1", "title": "Physical security perimeters", "relationship": "direct"}],
    "BOOT-01": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "BOOT-02": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],
    "BOOT-03": [{"control": "7.9", "title": "Security of assets off-premises", "relationship": "supporting"}],
    "BOOT-04": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "BOOT-05": [{"control": "8.19", "title": "Installation of software on operational systems", "relationship": "direct"}],
    "BOOT-06": [{"control": "8.19", "title": "Installation of software on operational systems", "relationship": "supporting"}],
    "BOOT-07": [{"control": "8.24", "title": "Use of cryptography", "relationship": "supporting"}],
    "BOOT-08": [{"control": "8.5", "title": "Secure authentication", "relationship": "direct"}],
    "BOOT-09": [{"control": "8.8", "title": "Management of technical vulnerabilities", "relationship": "supporting"}],

    "SVC-01": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "SVC-02": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "SVC-03": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "SVC-04": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "SVC-05": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "SVC-06": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "SVC-07": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "SVC-08": [{"control": "8.8", "title": "Management of technical vulnerabilities", "relationship": "direct"}],
    "SVC-09": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "SVC-10": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "MISC-01": [{"control": "8.16", "title": "Monitoring activities", "relationship": "supporting"}],
    "MISC-02": [{"control": "8.20", "title": "Networks security", "relationship": "supporting"}],
    "MISC-03": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "MISC-04": [{"control": "8.20", "title": "Networks security", "relationship": "supporting"}],
    "MISC-05": [{"control": "8.22", "title": "Segregation of networks", "relationship": "direct"}],
    "VER-01": [{"control": "8.8", "title": "Management of technical vulnerabilities", "relationship": "supporting"}],

    "CORR-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "CORR-02": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],
    "CORR-03": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "CORR-04": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "CORR-05": [{"control": "8.22", "title": "Segregation of networks", "relationship": "direct"}],
    "CORR-06": [{"control": "8.9", "title": "Configuration management", "relationship": "supporting"}],
    "CORR-07": [{"control": "8.6", "title": "Capacity management", "relationship": "direct"}],
    "CORR-08": [{"control": "8.24", "title": "Use of cryptography", "relationship": "direct"}],
    "CORR-09": [{"control": "8.9", "title": "Configuration management", "relationship": "direct"}],
    "CORR-10": [{"control": "8.19", "title": "Installation of software on operational systems", "relationship": "supporting"}],
}

# =============================================================================
# CIS Cisco IOS-XE 17.x Benchmark v2.1.0 (03-29-2024)
# ONLY entries below were directly confirmed against real search-result
# snippets of this specific document. Everything else is intentionally left
# unmapped ("needs_verification") rather than guessed -- CIS numbering
# differs across benchmark versions (15 / 16 / 17.x) and the full PDF is
# gated behind a CIS SecureSuite login I don't have access to verify against.
# =============================================================================
CIS = {
    "AAA-01": [{"control": "1.1.1", "title": "Enable 'aaa new-model' (Automated)", "relationship": "direct",
                "source": "CIS Cisco IOS XE 17.x Benchmark v2.1.0"}],
    "AAA-02": [{"control": "1.1.2", "title": "Enable 'aaa authentication login' (Automated)", "relationship": "direct",
                "source": "CIS Cisco IOS XE 17.x Benchmark v2.1.0"}],
}

# =============================================================================
# DISA STIG -- Cisco IOS Switch L2S (V-IDs V-2206xx) and Cisco IOS Router RTR
# (V-IDs V-2165xx/V-2169xx/V-2301xx), sourced from the actual current task
# files of two open-source (MIT-licensed) Ansible remediation roles:
#   - ansible-lockdown/CISCO-IOS-L2S-STIG (explicitly Version 2, Release 2,
#     23 Jul 2021 per that repo's README)
#   - ansible-lockdown/CISCO-IOS-RTR-STIG (version/date not reliably stated
#     in that repo's own README -- it appears to be a copy/paste error
#     referencing the L2S STIG instead; the V-21xxxx ID range is used here
#     as the citation anchor instead of an unverifiable date)
# Every Group ID (CISC-L2-*/CISC-RT-*), Vulnerability ID (V-*), and title
# below was extracted directly from those repos' YAML task files, not
# guessed or reconstructed from memory. DISA STIG content is a U.S.
# government work (public domain) -- titles are quoted in full deliberately,
# unlike the CIS/ISO entries where only short titles are used.
#
# KNOWN LIMITATION: STIG documents are revised periodically and Group/
# Vulnerability IDs CAN change between revisions for a given requirement,
# though V-IDs are generally more stable than the "SV-...r...rule" revision
# suffix. Treat this mapping as a strong starting point sourced from a real,
# specific STIG revision -- not a guarantee of exact alignment with whatever
# is the *current* DISA-published STIG at the time you read this. Verify
# against the live document (dl.dod.cyber.mil) before using as formal ATO
# evidence.
# =============================================================================
_L2S_SRC = "DISA Cisco IOS Switch L2S STIG V2R2 (23 Jul 2021), via ansible-lockdown/CISCO-IOS-L2S-STIG"
_RTR_SRC = "DISA Cisco IOS Router RTR STIG (V-21xxxx ID range; exact revision/date not confirmable from source repo), via ansible-lockdown/CISCO-IOS-RTR-STIG"

STIG = {
    # --- Layer 2 domain -----------------------------------------------------
    "STP-01": [{"control": "CISC-L2-000100", "v_id": "V-220630",
                "title": "The Cisco switch must have Bridge Protocol Data Unit (BPDU) Guard enabled on all "
                         "user-facing or untrusted access switch ports.",
                "relationship": "direct", "source": _L2S_SRC}],
    "STP-02": [{"control": "CISC-L2-000090", "v_id": "V-220629",
                "title": "The Cisco switch must have Root Guard enabled on all switch ports connecting to "
                         "access layer switches.",
                "relationship": "direct", "source": _L2S_SRC}],
    "STP-03": [{"control": "CISC-L2-000110", "v_id": "V-220631",
                "title": "The Cisco switch must have Spanning Tree Protocol (STP) Loop Guard enabled.",
                "relationship": "direct", "source": _L2S_SRC}],
    "STP-04": [{"control": "CISC-L2-000180", "v_id": "V-220638",
                "title": "The Cisco switch must implement Rapid Spanning Tree Protocol (STP) where VLANs span "
                         "multiple switches with redundant links.",
                "relationship": "direct", "source": _L2S_SRC}],
    "UDLD-01": [{"control": "CISC-L2-000190", "v_id": "V-220639",
                 "title": "The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect "
                          "against one-way connections.",
                 "relationship": "direct", "source": _L2S_SRC}],
    "STORM-01": [{"control": "CISC-L2-000160", "v_id": "V-220636",
                  "title": "The Cisco switch must have Storm Control configured on all host-facing switchports.",
                  "relationship": "direct", "source": _L2S_SRC}],
    "DHCPSNOOP-01": [{"control": "CISC-L2-000130", "v_id": "V-220633",
                       "title": "The Cisco switch must have DHCP snooping for all user VLANs to validate DHCP "
                                "messages from untrusted sources.",
                       "relationship": "direct", "source": _L2S_SRC}],
    "DHCPSNOOP-02": [{"control": "CISC-L2-000130", "v_id": "V-220633", "title": "(see DHCPSNOOP-01)",
                       "relationship": "supporting", "source": _L2S_SRC}],
    "DHCPSNOOP-03": [{"control": "CISC-L2-000130", "v_id": "V-220633", "title": "(see DHCPSNOOP-01)",
                       "relationship": "supporting", "source": _L2S_SRC}],
    "DHCPSNOOP-04": [{"control": "CISC-L2-000130", "v_id": "V-220633", "title": "(see DHCPSNOOP-01)",
                       "relationship": "supporting", "source": _L2S_SRC}],
    "DAI-01": [{"control": "CISC-L2-000150", "v_id": "V-220635",
                "title": "The Cisco switch must have Dynamic Address Resolution Protocol (ARP) Inspection "
                         "(DAI) enabled on all user VLANs.",
                "relationship": "direct", "source": _L2S_SRC}],
    "DAI-02": [{"control": "CISC-L2-000150", "v_id": "V-220635", "title": "(see DAI-01)",
                "relationship": "supporting", "source": _L2S_SRC}],
    "DAI-03": [{"control": "CISC-L2-000150", "v_id": "V-220635", "title": "(see DAI-01)",
                "relationship": "supporting", "source": _L2S_SRC}],
    "DAI-04": [{"control": "CISC-L2-000150", "v_id": "V-220635", "title": "(see DAI-01)",
                "relationship": "supporting", "source": _L2S_SRC}],
    "IPSG-01": [{"control": "CISC-L2-000140", "v_id": "V-220634",
                 "title": "The Cisco switch must have IP Source Guard enabled on all user-facing or "
                          "untrusted access switch ports.",
                 "relationship": "direct", "source": _L2S_SRC}],
    "TRUNK-01": [{"control": "CISC-L2-000260", "v_id": "V-220646",
                  "title": "The Cisco switch must have the native VLAN assigned to an ID other than the "
                           "default VLAN for all 802.1q trunk links.",
                  "relationship": "direct", "source": _L2S_SRC}],
    "TRUNK-02": [{"control": "CISC-L2-000230", "v_id": "V-220643",
                  "title": "The Cisco switch must have the default VLAN pruned from all trunk ports that do "
                           "not require it.",
                  "relationship": "direct", "source": _L2S_SRC}],
    "TRUNK-03": [{"control": "CISC-L2-000200", "v_id": "V-220640",
                  "title": "The Cisco switch must have all trunk links enabled statically.",
                  "relationship": "direct", "source": _L2S_SRC}],
    "VTP-01": [{"control": "CISC-L2-000030", "v_id": "V-220624",
                "title": "The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a "
                         "hash function using the most secured cryptographic algorithm available.",
                "relationship": "supporting", "source": _L2S_SRC}],
    "L2PS-01": [{"control": "CISC-L2-000080", "v_id": "V-220628",
                 "title": "The Cisco switch must authenticate all endpoint devices before establishing any "
                          "connection.",
                 "relationship": "supporting", "source": _L2S_SRC,
                 "note": "STIG rule targets 802.1X endpoint authentication specifically; port-security MAC "
                         "limiting is a different (complementary, not equivalent) control for the same "
                         "unauthorized-device threat -- hence 'supporting' not 'direct'."}],
    "SVC-01": [{"control": "CISC-L2-000010", "v_id": "V-220622",
                "title": "The Cisco switch must be configured to disable non-essential capabilities.",
                "relationship": "direct", "source": _L2S_SRC}],
    "SVC-02": [{"control": "CISC-L2-000010", "v_id": "V-220622", "title": "(see SVC-01)",
                "relationship": "direct", "source": _L2S_SRC}],
    "SVC-03": [{"control": "CISC-L2-000010", "v_id": "V-220622", "title": "(see SVC-01)",
                "relationship": "direct", "source": _L2S_SRC}],
    "SVC-04": [{"control": "CISC-L2-000010", "v_id": "V-220622", "title": "(see SVC-01)",
                "relationship": "direct", "source": _L2S_SRC}],
    "SVC-05": [{"control": "CISC-L2-000010", "v_id": "V-220622", "title": "(see SVC-01)",
                "relationship": "direct", "source": _L2S_SRC}],
    "SVC-09": [{"control": "CISC-RT-000370", "v_id": "V-216585",
                "title": "The Cisco perimeter router must be configured to have Cisco Discovery Protocol "
                         "(CDP) disabled on all external interfaces.",
                "relationship": "supporting", "source": _RTR_SRC,
                "note": "STIG rule is scoped to perimeter/external interfaces specifically; this check is "
                        "broader (global CDP posture)."}],
    "SVC-10": [{"control": "CISC-RT-000360", "v_id": "V-216584",
                "title": "The Cisco perimeter router must be configured to have Link Layer Discovery "
                         "Protocol (LLDP) disabled on all external interfaces.",
                "relationship": "supporting", "source": _RTR_SRC,
                "note": "STIG rule is scoped to perimeter/external interfaces specifically; this check is "
                        "broader (global LLDP posture)."}],
    "CPURISK-01": [{"control": "CISC-L2-000040", "v_id": "V-220625",
                     "title": "The Cisco switch must manage excess bandwidth to limit the effects of "
                              "packet-flooding types of denial-of-service (DoS) attacks.",
                     "relationship": "supporting", "source": _L2S_SRC}],

    # --- Layer 3 / routing domain --------------------------------------------
    "RTAUTH-OSPF-01": [{"control": "CISC-RT-000020", "v_id": "V-216986",
                         "title": "The Cisco router must be configured to implement message authentication "
                                  "for all control plane protocols.",
                         "relationship": "direct", "source": _RTR_SRC}],
    "RTAUTH-EIGRP-01": [{"control": "CISC-RT-000020", "v_id": "V-216986", "title": "(see RTAUTH-OSPF-01)",
                          "relationship": "direct", "source": _RTR_SRC}],
    "RTAUTH-RIP-01": [{"control": "CISC-RT-000020", "v_id": "V-216986", "title": "(see RTAUTH-OSPF-01)",
                        "relationship": "direct", "source": _RTR_SRC}],
    "RTAUTH-BGP-01": [{"control": "CISC-RT-000050", "v_id": "V-216555",
                        "title": "The Cisco router must be configured to authenticate all routing protocol "
                                 "messages using NIST-validated FIPS 198-1 message authentication code "
                                 "algorithm.",
                        "relationship": "direct", "source": _RTR_SRC}],
    "RTAUTH-BGP-02": [{"control": "CISC-RT-000470", "v_id": "V-216991",
                        "title": "The Cisco BGP router must be configured to enable the Generalized TTL "
                                 "Security Mechanism (GTSM).",
                        "relationship": "direct", "source": _RTR_SRC}],
    "RTAUTH-BGP-03": [{"control": "CISC-RT-000560", "v_id": "V-216604",
                        "title": "The Cisco BGP router must be configured to use the maximum prefixes "
                                 "feature to protect against route table flooding and prefix "
                                 "de-aggregation attacks.",
                        "relationship": "direct", "source": _RTR_SRC}],
    "URPF-01": [{"control": "CISC-RT-000740", "v_id": "V-216617",
                 "title": "The Cisco PE router must be configured with Unicast Reverse Path Forwarding "
                          "(uRPF) loose mode enabled on all CE-facing interfaces.",
                 "relationship": "supporting", "source": _RTR_SRC,
                 "note": "STIG rule is specifically scoped to MPLS PE/CE-facing interfaces; this check "
                         "applies uRPF more generally."}],
    "ICMP-01": [{"control": "CISC-RT-000190", "v_id": "V-216567",
                 "title": "The Cisco router must be configured to have Internet Control Message Protocol "
                          "(ICMP) redirect messages disabled on all external interfaces.",
                 "relationship": "direct", "source": _RTR_SRC}],
    "ICMP-02": [{"control": "CISC-RT-000380", "v_id": "V-216586",
                 "title": "The Cisco perimeter router must be configured to have Proxy ARP disabled on all "
                          "external interfaces.",
                 "relationship": "direct", "source": _RTR_SRC}],
    "ICMP-03": [{"control": "CISC-RT-000170", "v_id": "V-216565",
                 "title": "The Cisco router must be configured to have Internet Control Message Protocol "
                          "(ICMP) unreachable messages disabled on all external interfaces.",
                 "relationship": "direct", "source": _RTR_SRC}],
    "ICMP-05": [{"control": "CISC-RT-000120", "v_id": "V-216560",
                 "title": "The Cisco router must be configured to protect against or limit the effects of "
                          "denial-of-service (DoS) attacks by employing control plane protection.",
                 "relationship": "supporting", "source": _RTR_SRC}],

    # --- Control Plane (CoPP) domain -----------------------------------------
    "COPP-01": [{"control": "CISC-RT-000120", "v_id": "V-216560",
                 "title": "The Cisco router must be configured to protect against or limit the effects of "
                          "denial-of-service (DoS) attacks by employing control plane protection.",
                 "relationship": "direct", "source": _RTR_SRC}],
    "COPP-CLASS-MCAST": [{"control": "CISC-RT-000790", "v_id": "V-216622",
                           "title": "The Cisco multicast router must be configured to disable Protocol "
                                    "Independent Multicast (PIM) on all interfaces that are not required to "
                                    "support multicast routing.",
                           "relationship": "supporting", "source": _RTR_SRC}],

    # --- Physical Security domain --------------------------------------------
    "PHYS-03": [{"control": "CISC-RT-000230", "v_id": "V-216571",
                 "title": "The Cisco router must be configured to disable the auxiliary port unless it is "
                          "connected to a secured modem providing encryption and authentication.",
                 "relationship": "direct", "source": _RTR_SRC}],

    # --- Misc domain -----------------------------------------------------------
    "MISC-02": [{"control": "CISC-RT-000790", "v_id": "V-216622", "title": "(see COPP-CLASS-MCAST)",
                 "relationship": "supporting", "source": _RTR_SRC}],
}


def _normalize_placeholder_titles(mapping: dict) -> None:
    """Replace '(see X)' placeholder titles with the real title from whichever
    entry for that control number actually has one -- keeps the raw JSON
    self-explanatory for anyone reading it directly, not just the tool's
    report generator (which only reads the first entry per control anyway)."""
    real_title_by_control: dict[str, str] = {}
    for entries in mapping.values():
        for e in entries:
            if e.get("title") and not e["title"].startswith("(see "):
                real_title_by_control.setdefault(e["control"], e["title"])
    for entries in mapping.values():
        for e in entries:
            if e.get("title", "").startswith("(see "):
                e["title"] = real_title_by_control.get(e["control"], e["title"])


_normalize_placeholder_titles(STIG)


def write_mapping(filename: str, framework_meta: dict, checks: dict):
    payload = {**framework_meta, "checks": checks}
    path = OUT_DIR / filename
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote {path}  ({len(checks)} check IDs mapped)")


write_mapping("nist_800_53_rev5.json", {
    "framework_id": "nist_800_53",
    "framework_name": "NIST SP 800-53 Rev. 5",
    "license_note": "Public domain (U.S. government work). Control identifiers and titles reproduced freely.",
}, NIST)

write_mapping("iso27002_2022.json", {
    "framework_id": "iso27002",
    "framework_name": "ISO/IEC 27002:2022",
    "license_note": "Copyrighted, commercially published by ISO. Only control numbers and short "
                     "conventional titles are referenced here -- no descriptive/guidance text from "
                     "the standard is reproduced. Not an official ISO document.",
}, ISO)

write_mapping("cis_ios_xe_benchmark.json", {
    "framework_id": "cis_benchmark",
    "framework_name": "CIS Cisco IOS XE 17.x Benchmark v2.1.0",
    "license_note": "CIS Benchmarks are freely referenceable; full PDF requires CIS SecureSuite "
                     "registration. Only directly-verified entries are populated -- see comments "
                     "in generate_mappings.py for scope.",
}, CIS)

write_mapping("disa_stig_cisco_iosxe.json", {
    "framework_id": "disa_stig",
    "framework_name": "DISA STIG -- Cisco IOS Switch L2S / Router RTR",
    "license_note": "Public domain (U.S. DoD work). Group IDs, Vulnerability IDs (V-*), and titles below "
                     "were extracted directly from two open-source Ansible remediation roles' current task "
                     "files (ansible-lockdown/CISCO-IOS-L2S-STIG and CISCO-IOS-RTR-STIG), not reconstructed "
                     "from memory. L2S is confirmed as V2R2 (23 Jul 2021); RTR's exact revision/date could "
                     "not be confirmed from that repo's own documentation (see comments in "
                     "generate_mappings.py). STIG IDs can shift between revisions -- verify against the "
                     "current DISA-published document (dl.dod.cyber.mil) before using as formal ATO "
                     "evidence. NDM (management-plane) sub-STIG remains unmapped -- no equivalent "
                     "open-source role was found for it.",
}, STIG)

print("\nDone.")
