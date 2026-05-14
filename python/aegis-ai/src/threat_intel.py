from typing import List
"""
AEGIS Threat Intel — Hardened
================================
Changes vs original:
  M-01  MITRE check normalised: lowercase, basename resolution,
        expanded pattern set (Python, Ruby, Perl downloaders, base64)
"""

import os
import re
import logging
from pathlib import Path
import httpx

logger = logging.getLogger("aegis_threat_intel")


class ThreatIntelligence:
    """
    Integrates with VirusTotal and MITRE ATT&CK for external validation.
    """

    def __init__(self):
        self.vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")

    def check_ip_reputation(self, ip_address: str) -> bool:
        """Returns False if IP is malicious according to VirusTotal."""
        if not self.vt_api_key:
            return True   # Safe fallback when no key configured

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {"x-apikey": self.vt_api_key}
            logger.info("Querying VirusTotal for %s", ip_address)
            
            with httpx.Client(timeout=5.0) as client:
                response = client.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    last_analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious_count = last_analysis_stats.get("malicious", 0)
                    suspicious_count = last_analysis_stats.get("suspicious", 0)
                    
                    if malicious_count > 0 or suspicious_count > 1:
                        logger.warning("BLOCK: VirusTotal flagged IP %s (Malicious: %d, Suspicious: %d)", 
                                       ip_address, malicious_count, suspicious_count)
                        return False
            return True
        except Exception as e:
            logger.error("VirusTotal check failed for %s: %s", ip_address, str(e))
            return True # Fail open on network errors to avoid DoS, but log it

    # ── M-01: Comprehensive, normalised MITRE ATT&CK tactic check ────────────

    # Compiled patterns for T1059 (Command & Scripting Interpreter), T1105 (Ingress Tool Transfer),
    # T1218 (System Binary Proxy Execution / LOLBins), T1027 (Obfuscation)
    _DANGEROUS_PATTERNS: list[re.Pattern] = [
        # Network download tools (exact basename match)
        re.compile(r"\b(wget|curl|fetch|lwp-download)\b"),
        # Reverse shells
        re.compile(r"\b(nc|ncat|netcat)\b.*-e"),
        re.compile(r"bash\s+-i\s+>&?"),
        re.compile(r"python[23]?\s+-c"),
        re.compile(r"ruby\s+-e"),
        re.compile(r"perl\s+-e"),
        re.compile(r"php\s+-r"),
        # Base64 decode + execute
        re.compile(r"base64\s+(-d|--decode)"),
        re.compile(r"echo\s+[A-Za-z0-9+/]{20,}.*\|\s*(bash|sh|python)"),
        # Privilege escalation helpers
        re.compile(r"\bsudo\b"),
        re.compile(r"\bchmod\s+[0-7]*[67][0-7]{2}\b"),
        # Fork bombs
        re.compile(r":\(\)\{.*:\|:&\}"),
        # T1059.001: PowerShell abuse patterns
        re.compile(r"\bpowershell\b.*(-enc|-encodedcommand|-nop|-noprofile|-w\s+hidden|-windowstyle\s+hidden)", re.IGNORECASE),
        re.compile(r"\bpowershell\b.*iex\b", re.IGNORECASE),
        re.compile(r"\bpowershell\b.*invoke-expression", re.IGNORECASE),
        re.compile(r"\bpowershell\b.*downloadstring", re.IGNORECASE),
        # T1218: Windows LOLBins (Living-off-the-Land Binaries)
        re.compile(r"\bcertutil\b.*(-(decode|urlcache|-f))", re.IGNORECASE),
        re.compile(r"\bmshta\b\s+(https?://|javascript:)", re.IGNORECASE),
        re.compile(r"\bregsvr32\b.*(/s|/u|scrobj)", re.IGNORECASE),
        re.compile(r"\bwscript\b.*\.(js|vbs|hta)\b", re.IGNORECASE),
        re.compile(r"\bcmd\b.*(/c|/k)\s+(start|powershell|wscript|cscript|mshta)", re.IGNORECASE),
        re.compile(r"\brundll32\b", re.IGNORECASE),
        # T1027: Obfuscation via string concatenation or char codes
        re.compile(r"\[char\]\s*\d{2,3}"),          # PowerShell char obfuscation
        re.compile(r"set\s+\w+=.*&&.*%\w+:~\d+,\d+%"),  # cmd env var substring obfuscation
        # T1589: Secret/Credential Exposure (High entropy markers)
        re.compile(r"(api_key|secret|token|password|passwd|access_key|private_key)\s*[:=]\s*['\"][A-Za-z0-9+/]{20,}['\"]", re.IGNORECASE),
        re.compile(r"AIza[0-9A-Za-z-_]{35}"),        # Google API Key
        re.compile(r"sk-[0-9A-Za-z]{48}"),           # OpenAI Key
    ]

    _COMBINED_PATTERN: re.Pattern = re.compile(
        "|".join(
            f"(?i:{p.pattern})" if p.flags & re.IGNORECASE else f"(?:{p.pattern})"
            for p in _DANGEROUS_PATTERNS
        )
    )

    def check_mitre_tactic(self, command: str) -> str:
        """
        Checks if a command matches a known MITRE ATT&CK tactic.
        Normalises case and resolves basename to defeat simple bypass attempts.
        """
        # Normalise: lowercase, resolve basename of leading token
        tokens = command.strip().split()
        if tokens:
            tokens[0] = Path(tokens[0]).name.lower()
        normalized = " ".join(tokens).lower()

        m = self._COMBINED_PATTERN.search(normalized)
        if m:
            return f"Tactic Matched: Execution/Command and Scripting Interpreter ({m.group()})"

        return "Clean"

    def scan_documentation(self, content: str) -> List[str]:
        """
        Scans documentation (README, etc.) for dangerous copy-paste commands.
        Protects against social engineering in malware repos.
        """
        findings = []
        # Look for code blocks with dangerous patterns
        code_blocks = re.findall(r"```(?:bash|sh|powershell|pwsh)?\n(.*?)\n```", content, re.DOTALL)
        for block in code_blocks:
            for line in block.splitlines():
                tactic = self.check_mitre_tactic(line)
                if tactic != "Clean":
                    findings.append(f"Dangerous command found in documentation: {line.strip()}")
        return findings


threat_intel = ThreatIntelligence()
