import base64
import email
from email import policy
import ipaddress
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from typing import Dict, List, Any, Optional


class PhishingHeaderParser:
    """Automated Email Header Parser with AbuseIPDB and VirusTotal Threat Intel Enrichment."""

    def __init__(
        self,
        eml_file_path: str,
        abuseipdb_key: Optional[str] = None,
        virustotal_key: Optional[str] = None,
    ):
        self.eml_file_path = eml_file_path
        self.msg = self._load_eml()

        # Retrieve API keys from parameters or system environment variables
        self.abuseipdb_key = abuseipdb_key or os.getenv("ABUSEIPDB_API_KEY")
        self.virustotal_key = virustotal_key or os.getenv("VIRUSTOTAL_API_KEY")

    def _load_eml(self) -> email.message.EmailMessage:
        """Loads and parses the .eml file using standard Python email policy."""
        try:
            with open(self.eml_file_path, "rb") as f:
                return email.message_from_binary_file(f, policy=policy.default)
        except Exception as e:
            raise FileNotFoundError(f"Error loading .eml file: {e}")

    def extract_basic_headers(self) -> Dict[str, str]:
        """Extracts standard email headers."""
        return {
            "From": str(self.msg.get("From", "N/A")),
            "To": str(self.msg.get("To", "N/A")),
            "Subject": str(self.msg.get("Subject", "N/A")),
            "Date": str(self.msg.get("Date", "N/A")),
            "Return-Path": str(self.msg.get("Return-Path", "N/A")),
            "Reply-To": str(self.msg.get("Reply-To", "N/A")),
            "Message-ID": str(self.msg.get("Message-ID", "N/A")),
        }

    def detect_sender_mismatches(self) -> Dict[str, Any]:
        """Compares From, Return-Path, and Reply-To headers to identify potential spoofing."""
        headers = self.extract_basic_headers()

        def extract_address(raw_header: str) -> str:
            match = re.search(r"[\w\.-]+@[\w\.-]+", raw_header)
            return match.group(0).lower() if match else raw_header.lower()

        from_addr = extract_address(headers["From"])
        return_path_addr = extract_address(headers["Return-Path"])
        reply_to_addr = extract_address(headers["Reply-To"])

        mismatches = []

        if return_path_addr != "n/a" and from_addr and from_addr != return_path_addr:
            mismatches.append(
                f"[ALERT] From ({from_addr}) does not match Return-Path ({return_path_addr})"
            )

        if reply_to_addr != "n/a" and from_addr and from_addr != reply_to_addr:
            mismatches.append(
                f"[WARNING] From ({from_addr}) does not match Reply-To ({reply_to_addr})"
            )

        return {
            "has_mismatch": len(mismatches) > 0,
            "mismatch_alerts": mismatches,
        }

    def parse_authentication_results(self) -> Dict[str, str]:
        """Extracts SPF, DKIM, and DMARC status from Authentication-Results headers."""
        auth_header = str(self.msg.get("Authentication-Results", ""))
        spf_header = str(self.msg.get("Received-SPF", ""))

        auth_summary = {"SPF": "UNKNOWN", "DKIM": "UNKNOWN", "DMARC": "UNKNOWN"}

        combined_spf = (auth_header + " " + spf_header).lower()
        if "spf=pass" in combined_spf or "pass" in spf_header.lower():
            auth_summary["SPF"] = "PASS"
        elif "spf=fail" in combined_spf or "fail" in spf_header.lower():
            auth_summary["SPF"] = "FAIL"
        elif "spf=softfail" in combined_spf:
            auth_summary["SPF"] = "SOFTFAIL"

        if "dkim=pass" in auth_header.lower():
            auth_summary["DKIM"] = "PASS"
        elif "dkim=fail" in auth_header.lower():
            auth_summary["DKIM"] = "FAIL"

        if "dmarc=pass" in auth_header.lower():
            auth_summary["DMARC"] = "PASS"
        elif "dmarc=fail" in auth_header.lower():
            auth_summary["DMARC"] = "FAIL"

        return auth_summary

    def extract_origin_ip_and_hops(self) -> Dict[str, Any]:
        """Extracts Received headers to trace email routing and identify originating IP."""
        received_headers = self.msg.get_all("Received", [])
        ips = []
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

        for header in received_headers:
            found_ips = re.findall(ip_pattern, str(header))
            for ip in found_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not ip_obj.is_private and not ip_obj.is_loopback:
                        ips.append(ip)
                except ValueError:
                    continue

        originating_ip = ips[-1] if ips else None

        return {
            "originating_ip": originating_ip,
            "total_hops": len(received_headers),
            "external_ips": ips,
        }

    def extract_embedded_urls(self) -> List[str]:
        """Extracts all HTTP/HTTPS URLs embedded in email body."""
        urls = set()
        url_pattern = r"https?://[^\s<>\"']+"

        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    try:
                        body = part.get_content()
                        urls.update(re.findall(url_pattern, str(body)))
                    except Exception:
                        continue
        else:
            try:
                body = self.msg.get_content()
                urls.update(re.findall(url_pattern, str(body)))
            except Exception:
                pass

        return list(urls)

    # =========================================================================
    # THREAT INTELLIGENCE ENRICHMENT METHODS (APIs)
    # =========================================================================

    def check_ip_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Queries AbuseIPDB v2 API to check public IP reputation score."""
        if not self.abuseipdb_key:
            return {"status": "API Key Missing", "score": "N/A"}

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": self.abuseipdb_key}

        try:
            req = urllib.request.Request(
                f"{url}?{urllib.parse.urlencode(params)}", headers=headers
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                res_data = json.loads(response.read().decode())["data"]
                return {
                    "status": "Success",
                    "abuse_confidence_score": res_data.get("abuseConfidenceScore", 0),
                    "country": res_data.get("countryCode", "N/A"),
                    "isp": res_data.get("isp", "N/A"),
                    "total_reports": res_data.get("totalReports", 0),
                }
        except Exception as e:
            return {"status": "API Error", "details": str(e)}

    def check_url_virustotal(self, target_url: str) -> Dict[str, Any]:
        """Queries VirusTotal v3 API using URL base64 identifier."""
        if not self.virustotal_key:
            return {"status": "API Key Missing", "score": "N/A"}

        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            req = urllib.request.Request(api_url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as response:
                res_data = json.loads(response.read().decode())["data"]
                stats = res_data["attributes"]["last_analysis_stats"]
                return {
                    "status": "Success",
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "harmless_count": stats.get("harmless", 0),
                    "total_vendors": sum(stats.values()),
                }
        except Exception as e:
            return {"status": "API Error / Not Scanned Yet", "details": str(e)}

    # =========================================================================
    # REPORT GENERATOR
    # =========================================================================

    def generate_report(self):
        """Prints an enriched SOC triage report."""
        headers = self.extract_basic_headers()
        mismatches = self.detect_sender_mismatches()
        auth = self.parse_authentication_results()
        routing = self.extract_origin_ip_and_hops()
        urls = self.extract_embedded_urls()

        print("=" * 65)
        print("     SOC PHISHING TELEMETRY & ENRICHED THREAT REPORT     ")
        print("=" * 65)

        print("\n[+] BASIC HEADER INFORMATION")
        for k, v in headers.items():
            print(f"  - {k:12}: {v}")

        print("\n[+] SENDER MISMATCH & SPOOFING ANALYSIS")
        if mismatches["has_mismatch"]:
            for alert in mismatches["mismatch_alerts"]:
                print(f"  {alert}")
        else:
            print("  [OK] No direct From/Return-Path/Reply-To mismatches detected.")

        print("\n[+] AUTHENTICATION CHECKS (SPF / DKIM / DMARC)")
        for proto, status in auth.items():
            print(f"  - {proto:6}: {status}")

        print("\n[+] ROUTING & IP ENRICHMENT (AbuseIPDB)")
        origin_ip = routing["originating_ip"]
        print(f"  - Originating IP : {origin_ip or 'Public IP Not Found'}")
        print(f"  - Total Hops     : {routing['total_hops']}")

        if origin_ip:
            ip_intel = self.check_ip_abuseipdb(origin_ip)
            if ip_intel.get("status") == "Success":
                score = ip_intel["abuse_confidence_score"]
                flag = "[HIGH RISK]" if score > 25 else "[LOW RISK]"
                print(f"  - Threat Intel   : {flag} Abuse Confidence: {score}%")
                print(f"  - Country / ISP  : {ip_intel['country']} | {ip_intel['isp']}")
                print(f"  - Total Reports  : {ip_intel['total_reports']}")
            else:
                print(f"  - Threat Intel   : {ip_intel.get('status')}")

        print(f"\n[+] EMBEDDED URLS & THREAT INTEL (VirusTotal) ({len(urls)})")
        if urls:
            for u in urls:
                print(f"  - Link: {u}")
                vt_intel = self.check_url_virustotal(u)
                if vt_intel.get("status") == "Success":
                    mal = vt_intel["malicious_count"]
                    tot = vt_intel["total_vendors"]
                    risk = "[ALERT - MALICIOUS]" if mal > 0 else "[CLEAN]"
                    print(
                        f"    └─ VT Detection: {risk} {mal}/{tot} security vendors flagged"
                    )
                else:
                    print(f"    └─ VT Detection: {vt_intel.get('status')}")
        else:
            print("  - No URLs extracted.")

        print("=" * 65)


# =========================================================================
# DYNAMIC COMMAND-LINE EXECUTION (METHOD 2)
# =========================================================================
if __name__ == "__main__":
    # Checks if a file path was passed in terminal (e.g., python3 script.py file.eml)
    if len(sys.argv) > 1:
        sample_eml = sys.argv[1]
    else:
        sample_eml = "sample_phish.eml"  # Fallback default file name

    print(f"\n[*] Target File: {sample_eml}\n")

    try:
        parser = PhishingHeaderParser(sample_eml)
        parser.generate_report()
    except FileNotFoundError:
        print(
            f"[!] Error: Could not find file '{sample_eml}'. Check the path and try again."
        )