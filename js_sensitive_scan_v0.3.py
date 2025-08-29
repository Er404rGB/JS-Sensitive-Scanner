#!/usr/bin/env python3
# JS Sensitive Scanner v0.3 — for authorized security testing only
import os, re, sys, json, argparse, math
from typing import List, Dict, Any

BANNER = "JS Sensitive Scanner v0.3 — for authorized security testing only"

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

def redact(s: str, keep=4) -> str:
    if s is None:
        return ""
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "*" * max(0, len(s) - keep*2) + s[-keep:]

def iter_files(paths: List[str], include_node_modules: bool=False) -> List[str]:
    exts = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".env"}
    out = []
    for p in paths:
        if os.path.isfile(p):
            out.append(p)
        else:
            for root, dirs, files in os.walk(p):
                if not include_node_modules:
                    dirs[:] = [d for d in dirs if d != "node_modules" and not d.startswith(".git")]
                for f in files:
                    _, ext = os.path.splitext(f)
                    if ext.lower() in exts or f.lower() in ("dockerfile",):
                        out.append(os.path.join(root, f))
    return out

PATTERNS: List[Dict[str, Any]] = [
    {"name":"AWS Access Key ID", "severity":"high", "regex": re.compile(r"AKIA[0-9A-Z]{16}")},
    {"name":"AWS Secret Access Key", "severity":"high", "regex": re.compile(r"(?i)aws(.{0,20})?(secret|sk|access[_-]?key|secret[_-]?access[_-]?key)(.{0,20})?[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]")},
    {"name":"Google API Key", "severity":"high", "regex": re.compile(r"AIza[0-9A-Za-z\-_]{35}")},
    {"name":"GitHub Token", "severity":"high", "regex": re.compile(r"ghp_[A-Za-z0-9]{36,}")},
    {"name":"Stripe Key", "severity":"high", "regex": re.compile(r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}")},
    {"name":"Slack Token", "severity":"high", "regex": re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,}")},
    {"name":"JWT", "severity":"medium", "regex": re.compile(r"eyJ[a-zA-Z0-9_\-]{5,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}")},
    {"name":"Private Key (PEM)", "severity":"critical", "regex": re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----")},
    {"name":"Generic API Key / Token", "severity":"medium", "regex": re.compile(r"(?i)\b(api[_-]?key|token|secret|client[_-]?secret|app[_-]?secret)\b\s*[:=]\s*['\"][A-Za-z0-9/_\-\.\+=]{8,}['\"]")},
    {"name":"Password Hardcoded", "severity":"high", "regex": re.compile(r"(?i)\b(pass(word)?|pwd)\b\s*[:=]\s*['\"][^'\"\\]{6,}['\"]")},
    {"name":"Connection String", "severity":"high", "regex": re.compile(r"(?i)\b(?:mongodb|postgres(?:ql)?|mysql|mssql|redis|amqp|mqtt)(?:\+srv)?:\/\/[^'\"\s]{10,}")},
    {"name":"Basic Auth URL", "severity":"medium", "regex": re.compile(r"https?:\/\/[^\/\s:@]+:[^\/\s:@]+@[^\/\s]+")},
    {"name":"Firebase Config Key", "severity":"low", "regex": re.compile(r"(?i)\bapiKey\b\s*:\s*['\"][A-Za-z0-9_\-]{20,}['\"]")},
    {"name":"document.cookie usage", "severity":"info", "regex": re.compile(r"\bdocument\.cookie\b")},
    {"name":"localStorage usage", "severity":"info", "regex": re.compile(r"\blocalStorage\.setItem\s*\(")},
    {"name":"eval usage", "severity":"medium", "regex": re.compile(r"\beval\s*\(")},
    {"name":"Function constructor", "severity":"medium", "regex": re.compile(r"\bnew\s+Function\s*\(")},
]

BASE64ISH = re.compile(r"\b[A-Za-z0-9+\/=]{20,}\b")
HEXISH = re.compile(r"\b[0-9a-fA-F]{32,}\b")

def entropy_candidates(line: str, min_entropy: float=4.5) -> List[str]:
    cands = set()
    for pat in (BASE64ISH, HEXISH):
        for m in pat.finditer(line):
            token = m.group(0)
            if len(token) < 20:
                continue
            ent = shannon_entropy(token)
            if ent >= min_entropy:
                cands.add(token)
    return list(cands)

def scan_text(text: str, filename: str, min_entropy: float=4.5) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        for pat in PATTERNS:
            for m in pat["regex"].finditer(line):
                secret = m.group(0)
                findings.append({
                    "type": pat["name"],
                    "severity": pat["severity"],
                    "file": filename,
                    "line": i,
                    "match": redact(secret),
                    "raw_len": len(secret)
                })
        for token in entropy_candidates(line, min_entropy=min_entropy):
            findings.append({
                "type": "High-entropy candidate",
                "severity": "medium",
                "file": filename,
                "line": i,
                "match": redact(token),
                "raw_len": len(token),
                "entropy": round(shannon_entropy(token), 3)
            })
    return findings

def scan_files(paths: List[str], include_node_modules: bool, min_entropy: float) -> List[Dict[str, Any]]:
    results = []
    files = iter_files(paths, include_node_modules=include_node_modules)
    for f in files:
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
            results.extend(scan_text(text, f, min_entropy=min_entropy))
        except Exception as e:
            results.append({
                "type": "error",
                "severity": "info",
                "file": f,
                "line": 0,
                "match": f"Read error: {e}",
            })
    return results

def pretty_print(findings: List[Dict[str, Any]], top_n: int=None):
    if not findings:
        print("✓ Ничего подозрительного не найдено.")
        return
    to_show = findings if top_n is None else findings[:top_n]
    width_type = max(len(x["type"]) for x in to_show) if to_show else 10
    width_sev = max(len(x["severity"]) for x in to_show) if to_show else 6
    print(f"{'TYPE'.ljust(width_type)}  {'SEV'.ljust(width_sev)}  FILE:LINE  MATCH")
    print("-" * (width_type + width_sev + 25))
    for f in to_show:
        print(f"{f['type'].ljust(width_type)}  {f['severity'].ljust(width_sev)}  {os.path.basename(f['file'])}:{f['line']}  {f['match']}")

def save_json(findings: List[Dict[str, Any]], out_path: str):
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, ensure_ascii=False, indent=2)
    print(f"JSON отчёт сохранён: {out_path}")

def main():
    parser = argparse.ArgumentParser(description=BANNER)
    src = parser.add_mutually_exclusive_group(required=False)
    src.add_argument("--stdin", action="store_true", help="читать код из STDIN")
    parser.add_argument("paths", nargs="*", help="файлы или папки для сканирования")
    parser.add_argument("--include-node-modules", action="store_true", help="включить node_modules в обход")
    parser.add_argument("--min-entropy", type=float, default=4.5, help="порог энтропии для кандидатов (по умолчанию 4.5)")
    parser.add_argument("--json", dest="json_out", metavar="PATH", help="сохранить результаты в JSON")
    parser.add_argument("--top", type=int, default=None, help="показать только первые N находок")
    args = parser.parse_args()

    if not args.stdin and not args.paths:
        parser.print_help()
        sys.exit(1)

    if args.stdin:
        text = sys.stdin.read()
        findings = scan_text(text, filename="<stdin>", min_entropy=args.min_entropy)
    else:
        findings = scan_files(args.paths, include_node_modules=args.include_node_modules, min_entropy=args.min_entropy)

    severity_order = {"critical":0, "high":1, "medium":2, "low":3, "info":4}
    findings.sort(key=lambda x: (severity_order.get(x.get("severity","info"), 5), x.get("type",""), x.get("file",""), x.get("line",0)))

    pretty_print(findings, top_n=args.top)
    if args.json_out:
        save_json(findings, args.json_out)

if __name__ == "__main__":
    main()
