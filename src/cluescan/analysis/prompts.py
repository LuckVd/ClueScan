"""Prompt builders and the vulnerability pattern library.

Two analyzers share the "real vuln, not style" posture:
  * SECURITY  — injection/crypto/auth/secrets etc. (source->sink five-step)
  * LOGIC     — business-logic flaws, with a HARD-EVIDENCE contract
                (missing_check + entry_point + attack_path all required)

Both emit strict JSON. Hallucination is suppressed downstream by verifying
file:line against the real repo (analysis.verifier).
"""

from __future__ import annotations

# Concise but useful pattern library to prime the model. Not exhaustive — the
# LLM may report categories outside this list, but these anchor the common ones.
VULN_PATTERNS: dict[str, dict] = {
    "sql_injection": {
        "cwe": "CWE-89", "owasp": "A03:2021",
        "sinks": ["execute(", "executemany(", "raw(", "query(", "cursor.execute"],
        "sanitizers": ["parameterized", "placeholder", "%s", "?", "PreparedStatement", "ORM"],
    },
    "command_injection": {
        "cwe": "CWE-78", "owasp": "A03:2021",
        "sinks": ["os.system", "subprocess", "popen", "exec(", "shell=True", "Runtime.exec"],
        "sanitizers": ["shell=False", "shlex.quote", "arg list", "allowlist"],
    },
    "xss": {
        "cwe": "CWE-79", "owasp": "A03:2021",
        "sinks": ["innerHTML", "dangerouslySetInnerHTML", "render_template_string", "|safe", "document.write"],
        "sanitizers": ["escape", "autoescape", "DOMPurify", "textContent"],
    },
    "path_traversal": {
        "cwe": "CWE-22", "owasp": "A01:2021",
        "sinks": ["open(", "read_file", "send_file", "File(", "..", "join(user"],
        "sanitizers": ["realpath", "abspath + prefix check", "basename", "allowlist"],
    },
    "ssrf": {
        "cwe": "CWE-918", "owasp": "A10:2021",
        "sinks": ["requests.get", "urlopen", "http.Get", "fetch(", "axios"],
        "sanitizers": ["allowlist host", "block internal IPs", "no redirects"],
    },
    "insecure_deserialization": {
        "cwe": "CWE-502", "owasp": "A08:2021",
        "sinks": ["pickle.loads", "yaml.load", "unserialize", "ObjectInputStream", "eval("],
        "sanitizers": ["yaml.safe_load", "SafeConstructor", "JSON.parse", "signed/typed"],
    },
    "hardcoded_secrets": {
        "cwe": "CWE-798", "owasp": "A07:2021",
        "sinks": ["password =", "api_key =", "secret =", "AKIA", "-----BEGIN"],
        "sanitizers": ["env var", "secret manager", "vault"],
    },
    "weak_crypto": {
        "cwe": "CWE-327", "owasp": "A02:2021",
        "sinks": ["md5(", "sha1(", "DES", "ECB", "random(", "rand("],
        "sanitizers": ["bcrypt", "argon2", "secrets.token", "AES-GCM", "PBKDF2"],
    },
    "open_redirect": {
        "cwe": "CWE-601", "owasp": "A01:2021",
        "sinks": ["redirect(", "Location:", "res.redirect"],
        "sanitizers": ["allowlist", "relative path only"],
    },
    "log_injection": {
        "cwe": "CWE-117", "owasp": "A09:2021",
        "sinks": ["logger.info", "console.log", "logging"],
        "sanitizers": ["sanitize newlines", "encode"],
    },
}


def _pattern_blurb() -> str:
    lines = []
    for key, p in VULN_PATTERNS.items():
        sinks = ", ".join(p["sinks"][:5])
        san = ", ".join(p["sanitizers"][:4])
        lines.append(f"- {key} ({p['cwe']}): sinks=[{sinks}] sanitizers=[{san}]")
    return "\n".join(lines)


SECURITY_SYSTEM = """You are an elite application security reviewer auditing a code change.
Find REAL, EXPLOITABLE vulnerabilities and serious fragility — NOT style, formatting,
naming, or minor quality issues. Stay silent rather than speculate.

Method (for each suspected issue):
  1. SOURCE: is the input user-controlled / untrusted? (trace a caller or entry point)
  2. FLOW: how does it reach the sink?
  3. SINK: is it a dangerous operation (below)?
  4. SANITIZATION: is there a real guard between source and sink?
  5. IMPACT: what can an attacker actually do?

Only report an issue if tainted, user-controlled data reaches a dangerous sink WITHOUT
effective sanitization (or a hardcoded secret / weak crypto / dangerous deserialize etc.
is introduced). If the change is benign, return an empty findings list.

Common categories:
{patterns}

Respond with ONLY a JSON object (no prose, no fences) of this exact shape:
{{
  "findings": [
    {{
      "category": "sql_injection",
      "severity": "critical|high|medium|low",
      "confidence": 0.0-1.0,
      "title": "short",
      "description": "what + why exploitable, cite the data flow",
      "fix_suggestion": "concrete fix",
      "file": "repo-relative path",
      "line": <int>,
      "end_line": <int or null>,
      "function": "name or null",
      "cwe": "CWE-xx",
      "owasp": "A0x:2021",
      "source": "the tainted variable/origin",
      "sink": "the dangerous call",
      "data_flow": "source -> ... -> sink, one line"
    }}
  ]
}}
""".format(patterns=_pattern_blurb())


LOGIC_SYSTEM = """You are an expert in BUSINESS-LOGIC security: authorization bypass, IDOR /
insecure direct object reference, missing access control, price/quantity/quota manipulation,
race conditions in critical flows, state-machine violations, and missing validation that
enables abuse or fraud. NOT injection (another reviewer covers that), NOT style.

You operate under a STRICT HARD-EVIDENCE CONTRACT. Every finding MUST include all three:
  - missing_check: the concrete control/authorization/validation that is ABSENT
  - entry_point: a concrete externally-reachable handler/route that reaches this code
  - attack_path: step-by-step how an attacker abuses it
If you cannot supply all three with confidence, DO NOT report the finding. Prefer silence.

Cap your confidence realistically — logic issues are inherently less certain than injection.

Respond with ONLY a JSON object (no prose, no fences):
{{
  "findings": [
    {{
      "category": "missing_authz" | "idor" | "price_manipulation" | "race_condition" | "state_violation" | "missing_validation" | ...,
      "severity": "critical|high|medium|low",
      "confidence": 0.0-1.0,
      "title": "short",
      "description": "the logic flaw and its business impact",
      "fix_suggestion": "concrete control to add",
      "file": "repo-relative path",
      "line": <int>,
      "function": "name or null",
      "cwe": "CWE-xx (e.g. CWE-862 missing authz, CWE-639 IDOR, CWE-362 race)",
      "missing_check": "...",
      "entry_point": "...",
      "attack_path": "step1; step2; step3"
    }}
  ]
}}
"""


SECURITY_USER_TMPL = """Audit this code change for real exploitable security issues.

{digest}
"""

LOGIC_USER_TMPL = """Assess this code change for BUSINESS-LOGIC security flaws only.
Remember the hard-evidence contract (missing_check + entry_point + attack_path all required).

{digest}
"""


def security_prompts(digest: str) -> tuple[str, str]:
    return SECURITY_SYSTEM, SECURITY_USER_TMPL.format(digest=digest)


def logic_prompts(digest: str) -> tuple[str, str]:
    return LOGIC_SYSTEM, LOGIC_USER_TMPL.format(digest=digest)
