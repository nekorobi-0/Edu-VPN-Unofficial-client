#!/usr/bin/env python3
"""Discover public YNU web names, resolve with dig, and match cached IPs/CIDRs."""
import argparse
import concurrent.futures
from datetime import datetime, timezone
from html.parser import HTMLParser
import html
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = Path(__file__).resolve().parents[1]
DEFAULT = BASE / "data/ynu-web-ips.json"
SEEDS = ["https://www.ynu.ac.jp/", "https://www.ynu.ac.jp/about/link/",
         "https://itsc.ynu.ac.jp/", "https://www.lib.ynu.ac.jp/"]
WHOIS = "https://whois.nic.ad.jp/cgi-bin/whois_gw?key=133.34.0.0&submit=query"


def now():
    return datetime.now(timezone.utc).isoformat()


def ynu_name(name):
    name = (name or "").lower().rstrip(".")
    return bool(re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*ynu\.ac\.jp", name))


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "ynu-vpn-route-inventory/0.1"})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read(2_000_001)
        if len(body) > 2_000_000:
            raise ValueError("page exceeds 2 MB")
        charset = response.headers.get_content_charset() or "utf-8"
        return body.decode(charset, errors="replace"), response.geturl()


class Links(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base = base
        self.urls = set()

    def handle_starttag(self, tag, attrs):
        if tag not in {"a", "link", "iframe", "form"}:
            return
        for key, value in attrs:
            if key in {"href", "src", "action"} and value:
                url = urllib.parse.urljoin(self.base, value)
                parts = urllib.parse.urlsplit(url)
                if parts.scheme in {"http", "https"} and ynu_name(parts.hostname):
                    self.urls.add(url)


def discover(url):
    try:
        page, final = fetch(url)
        parser = Links(final)
        parser.feed(page)
        names = {}
        for link in parser.urls | {url, final}:
            host = urllib.parse.urlsplit(link).hostname
            if ynu_name(host):
                names.setdefault(host, set()).add(url)
        return names, {"url": url, "final_url": final, "status": "ok"}
    except (OSError, ValueError) as exc:
        return {}, {"url": url, "status": "error", "error": str(exc)}


def dig(host, record_type, resolver=None):
    args = ["dig", "+time=2", "+tries=1", "+noall", "+comments", "+answer", host, record_type]
    if resolver:
        args.insert(1, "@" + resolver)
    completed = subprocess.run(args, text=True, capture_output=True, timeout=8)
    match = re.search(r"status: ([A-Z]+)", completed.stdout)
    status = match.group(1) if match else "ERROR"
    records = []
    for line in completed.stdout.splitlines():
        cols = line.split()
        if len(cols) >= 5 and cols[2] == "IN" and cols[1].isdigit():
            records.append({"name": cols[0].rstrip("."), "ttl": int(cols[1]),
                            "type": cols[3], "value": " ".join(cols[4:]).rstrip(".")})
    if completed.returncode:
        status = "ERROR"
    return {"type": record_type, "status": status, "records": records}


def resolve(host, sources, networks, resolver=None):
    timestamp = now()
    try:
        queries = [dig(host, kind, resolver) for kind in ("A", "AAAA")]
        records = {json.dumps(r, sort_keys=True): r for q in queries for r in q["records"]}
        addresses = []
        for item in records.values():
            if item["type"] not in {"A", "AAAA"}:
                continue
            addr = ipaddress.ip_address(item["value"])
            matched = [str(n) for n in networks if addr.version == n.version and addr in n]
            addresses.append({"ip": str(addr), "family": addr.version, "ttl": item["ttl"],
                              "matched_cidrs": matched, "university_range_match": bool(matched),
                              "global": addr.is_global})
        addresses.sort(key=lambda a: (a["family"], int(ipaddress.ip_address(a["ip"]))))
        return {"hostname": host, "sources": sorted(sources), "resolved_at": timestamp,
                "dns_queries": queries, "addresses": addresses,
                "cnames": sorted({r["value"] for r in records.values() if r["type"] == "CNAME"}),
                "web_status": "public_web_link_candidate_not_http_probed"}
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return {"hostname": host, "sources": sorted(sources), "resolved_at": timestamp,
                "addresses": [], "dns_queries": [], "cnames": [], "error": str(exc)}


def refresh(args):
    # Require a university-specific authoritative record; APNIC's 133/8 parent is insufficient.
    whois_text, _ = fetch(WHOIS)
    whois_plain = html.unescape(re.sub(r"<[^>]*>", "", whois_text))
    if "133.34.0.0/16" not in whois_plain or "Yokohama National University" not in whois_plain:
        raise ValueError("JPNIC WHOIS ownership confirmation failed; no routing ranges generated")
    data_dir = args.output.parent
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "jnic-133.34.0.0-16.txt").write_text(whois_plain, encoding="utf-8")
    network = ipaddress.ip_network("133.34.0.0/16")
    names = {}
    pages = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for found, page in pool.map(discover, SEEDS):
            pages.append(page)
            for host, sources in found.items():
                names.setdefault(host, set()).update(sources)
        # One bounded discovery wave from institution pages linked by the university.
        roots = ["https://" + host + "/" for host in sorted(names)
                 if host.startswith("www.") and host not in {"www.ynu.ac.jp", "www.lib.ynu.ac.jp"}]
        for found, page in pool.map(discover, roots[:args.max_pages]):
            pages.append(page)
            for host, sources in found.items():
                names.setdefault(host, set()).update(sources)
    if args.hosts:
        for line in args.hosts.read_text().splitlines():
            host = line.partition("#")[0].strip().lower().rstrip(".")
            if not host:
                continue
            if not ynu_name(host):
                raise ValueError("extra hostname must belong to ynu.ac.jp: " + host)
            names.setdefault(host, set()).add("local-hosts-file")
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda h: resolve(h, names[h], [network], args.resolver), sorted(names)))
    inventory = {"schema_version": 1, "generated_at": now(), "domain": "ynu.ac.jp",
                 "scope": "public web links from official pages; not an exhaustive DNS zone inventory",
                 "dns_resolver": args.resolver or "system resolver used by dig",
                 "ranges": [{"cidr": str(network), "organization": "Yokohama National University",
                             "network_name": "YNUNET", "source": WHOIS, "verified_at": now()}],
                 "ipv6_range_status": "university allocation not verified; AAAA addresses still recorded",
                 "discovery_pages": pages, "hosts": rows}
    temporary = args.output.with_suffix(".tmp")
    temporary.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(args.output)
    unique = {a["ip"] for h in rows for a in h["addresses"]}
    matching = {a["ip"] for h in rows for a in h["addresses"] if a["university_range_match"]}
    print(json.dumps({"output": str(args.output), "hosts": len(rows), "unique_ips": len(unique),
                      "university_ips": len(matching), "outside_university_range_ips": len(unique - matching)}))


def match(args):
    inventory = json.loads(args.inventory.read_text())
    networks = [ipaddress.ip_network(n["cidr"]) for n in inventory["ranges"]]
    hosts = inventory["hosts"]
    try:
        ips = [ipaddress.ip_address(args.query)]
    except ValueError:
        hostname = args.query.lower().rstrip(".")
        selected = next((h for h in hosts if h["hostname"] == hostname), None)
        if selected is None:
            raise ValueError("hostname not in this inventory; refresh with --hosts")
        ips = [ipaddress.ip_address(a["ip"]) for a in selected["addresses"]]
    results = []
    for addr in ips:
        cidrs = [str(n) for n in networks if n.version == addr.version and addr in n]
        names = [h["hostname"] for h in hosts if any(a["ip"] == str(addr) for a in h["addresses"])]
        results.append({"ip": str(addr), "university_range_match": bool(cidrs), "matched_cidrs": cidrs,
                        "web_ip_match": bool(names), "matched_hostnames": names})
    print(json.dumps({"query": args.query, "inventory_generated_at": inventory["generated_at"],
                      "results": results}, ensure_ascii=False, indent=2))


def routes(args):
    inventory = json.loads(args.inventory.read_text())
    cidrs = [ipaddress.ip_network(n["cidr"]) for n in inventory["ranges"]]
    if args.include_external_web:
        for host in inventory["hosts"]:
            for address in host["addresses"]:
                ip = ipaddress.ip_address(address["ip"])
                if ip.is_global and not any(ip.version == n.version and ip in n for n in cidrs):
                    cidrs.append(ipaddress.ip_network(str(ip) + ("/32" if ip.version == 4 else "/128")))
    print(json.dumps({"ipv4": sorted({str(n) for n in cidrs if n.version == 4}),
                      "ipv6": sorted({str(n) for n in cidrs if n.version == 6})}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("refresh")
    p.add_argument("--output", type=Path, default=DEFAULT)
    p.add_argument("--hosts", type=Path)
    p.add_argument("--resolver")
    p.add_argument("--max-pages", type=int, default=24)
    p.set_defaults(func=refresh)
    p = commands.add_parser("match")
    p.add_argument("query")
    p.add_argument("--inventory", type=Path, default=DEFAULT)
    p.set_defaults(func=match)
    p = commands.add_parser("routes")
    p.add_argument("--inventory", type=Path, default=DEFAULT)
    p.add_argument("--include-external-web", action="store_true")
    p.set_defaults(func=routes)
    args = parser.parse_args()
    try:
        args.func(args)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
