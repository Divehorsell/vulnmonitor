import re
from loguru import logger


RCE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"remote\s*code\s*execution",
        r"RCE",
        r"arbitrary\s*code\s*execution",
        r"code\s*injection",
        r"command\s*injection",
        r"OS\s*command\s*injection",
        r"remote\s*command\s*execution",
        r"arbitrary\s*command\s*execution",
        r"unauthenticated\s*RCE",
        r"pre-auth\s*RCE",
        r"remote\s*code\s*injection",
        r"server\s*side\s*request\s*forgery",
        r"SSRF",
        r"deserialization",
        r"insecure\s*deserialization",
        r"Java\s*deserialization",
        r"unsafe\s*deserialization",
        r"object\s*deserialization",
        r"remote\s*procedure\s*call",
        r"arbitrary\s*file\s*write",
        r"arbitrary\s*file\s*upload",
        r"unrestricted\s*file\s*upload",
        r"webshell\s*upload",
        r"path\s*traversal",
        r"directory\s*traversal",
        r"arbitrary\s*file\s*read",
        r"SQL\s*injection",
        r"authenticated\s*RCE",
        r"post-auth\s*RCE",
        r"privilege\s*escalation",
        r"privilege\s*escalation\s*to\s*root",
        r"kernel\s*exploit",
        r"buffer\s*overflow",
        r"heap\s*overflow",
        r"stack\s*overflow",
        r"use.after.free",
        r"double.free",
        r"out.of.bounds\s*write",
        r"out.of.bounds\s*read",
        r"type\s*confusion",
        r"integer\s*overflow",
        r"race\s*condition",
        r"TOCTOU",
        r"sandbox\s*escape",
        r"container\s*escape",
        r"VM\s*escape",
        r"hypervisor\s*escape",
        r"authentication\s*bypass",
        r"auth\s*bypass",
        r"access\s*control\s*bypass",
        r"authorization\s*bypass",
        r"zero.click",
        r"0.click",
        r"no.user.interaction",
        r"unauthenticated",
        r"pre.authentication",
        r"default\s*credentials",
        r"hardcoded\s*credentials",
        r"hardcoded\s*password",
        r"backdoor",
        r"supply\s*chain",
        r"dependency\s*confusion",
        r"typosquatting",
        r"malicious\s*package",
        r"XEE",
        r"XML\s*external\s*entity",
        r"template\s*injection",
        r"SSTI",
        r"server.side.template.injection",
        r"expression\s*language\s*injection",
        r"EL\s*injection",
        r"SpEL\s*injection",
        r"OGNL\s*injection",
        r"JNDI\s*injection",
        r"log4shell",
        r"log4j",
        r"JNDI",
        r"LDAP\s*injection",
        r"reverse\s*shell",
        r"webshell",
        r"reverse\s*tcp",
        r"bind\s*shell",
        r"memory\s*corruption",
        r"arbitrary\s*write",
        r"arbitrary\s*read",
        r"type\s*juggling",
        r"prototype\s*pollution",
        r"prototype\s*chain\s*pollution",
    ]
]

EXCLUDE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bXSS\b",
        r"cross.site.scripting",
        r"\bCSRF\b",
        r"cross.site.request.forgery",
        r"\bLPE\b",
        r"local.privilege.escalation",
        r"\bDoS\b",
        r"denial.of.service",
        r"information.disclosure",
        r"info.leak",
        r"open.redirect",
        r"clickjacking",
        r"CRLF\s*injection",
        r"content.spoofing",
        r"cache.poisoning",
        r"mixed.content",
    ]
]

ASSET_KEYWORDS = [
    "Fortinet", "FortiGate", "FortiManager", "FortiAnalyzer", "FortiWeb", "FortiMail", "FortiSandbox",
    "Palo Alto", "PAN-OS", "GlobalProtect", "Cortex", "Prisma",
    "Cisco", "IOS", "ASA", "FirePOWER", "NX-OS", "ACI", "Umbrella", "Duo",
    "Microsoft", "Windows", "Exchange", "Active Directory", "IIS", "SharePoint", "Azure AD",
    "Apache", "Nginx", "Tomcat", "Struts", "Spring", "Log4j",
    "VMware", "vCenter", "ESXi", "vSphere", "Workstation",
    "Oracle", "WebLogic", "Oracle DB", "MySQL",
    "Linux", "Ubuntu", "Debian", "CentOS", "RHEL", "Kernel",
    "OpenSSL", "OpenSSH", "Dropbear",
    "Jenkins", "GitLab", "GitHub", "Bitbucket",
    "WordPress", "Drupal", "Joomla", "Confluence", "Jira",
    "SAP", "Salesforce", "ServiceNow",
    "F5", "BIG-IP", "Citrix", "NetScaler", "ADC",
    "Juniper", "Junos", "SRX",
    "Check Point", "Firewall",
    "Sophos", "XG Firewall",
    "Ivanti", "Connect Secure", "Policy Secure",
    "Atlassian", "Confluence", "Jira", "Bitbucket",
    "Zimbra", "Postfix", "Dovecot",
    "Redis", "MongoDB", "Elasticsearch", "Kafka", "RabbitMQ",
    "Docker", "Kubernetes", "containerd",
    "PHP", "Python", "Node.js", "Ruby", "Go",
    "Chrome", "Firefox", "Safari", "Edge",
    "iOS", "macOS", "Android",
    "Samba", "SMB", "RDP", "VPN", "IPSec", "SSL VPN",
    "SolarWinds", "ManageEngine", "FortiSIEM",
    "Ivanti", "Epic", "Cerner",
    "Openfire", "Spark",
    "Git", "Subversion",
    "OpenStack", "CloudStack",
    "Hadoop", "Spark",
]


class FilterEngine:
    def __init__(self):
        self.rce_patterns = RCE_PATTERNS
        self.exclude_patterns = EXCLUDE_PATTERNS
        self.asset_keywords = ASSET_KEYWORDS

    def is_rce_related(self, vuln: dict) -> bool:
        text = f"{vuln.get('title', '')} {vuln.get('description', '')}"
        for pattern in self.rce_patterns:
            if pattern.search(text):
                return True
        return False

    def is_excluded(self, vuln: dict) -> bool:
        text = f"{vuln.get('title', '')} {vuln.get('description', '')}"
        for pattern in self.exclude_patterns:
            if pattern.search(text):
                return True
        return False

    def match_asset_keywords(self, vuln: dict) -> list[str]:
        text = f"{vuln.get('title', '')} {vuln.get('description', '')} {vuln.get('affected_products', '')}"
        matched = []
        for keyword in self.asset_keywords:
            if keyword.lower() in text.lower():
                matched.append(keyword)
        return matched

    def filter(self, vulnerabilities: list[dict], rce_only: bool = True) -> list[dict]:
        filtered = []
        excluded_count = 0
        no_rce_count = 0

        for vuln in vulnerabilities:
            if self.is_excluded(vuln):
                excluded_count += 1
                continue

            if rce_only and not self.is_rce_related(vuln):
                no_rce_count += 1
                continue

            matched_assets = self.match_asset_keywords(vuln)
            if matched_assets:
                vuln["matched_assets"] = matched_assets

            filtered.append(vuln)

        logger.info(
            f"Filter: {len(vulnerabilities)} -> {len(filtered)} "
            f"({excluded_count} excluded, {no_rce_count} non-RCE)"
        )
        return filtered
