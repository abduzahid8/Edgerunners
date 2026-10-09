#!/usr/bin/env python3
"""
Edgerunners - Real Threat Intelligence Providers

Every lookup returns real data from public sources. When a source is
unreachable or an optional API key is missing, the result explicitly
reports {"status": "unavailable", "reason": ...} — never fabricated values.

Keyless sources:
    - CISA KEV catalog (Known Exploited Vulnerabilities)
    - NVD API v2.0 (CVE data, CVSS scores)
    - RDAP (registration data for IP addresses)
    - ip-api.com (geolocation / datacenter classification)
    - Reverse DNS (PTR lookup)

Optional free-tier API keys (environment variables):
    NVD_API_KEY          - higher NVD rate limits (https://nvd.nist.gov/developers)
    ABUSEIPDB_API_KEY    - IP abuse confidence scoring (https://www.abuseipdb.com/api/v2)
    VIRUSTOTAL_API_KEY   - IP/hash detection stats (https://www.virustotal.com/gui/my-apikey)
"""

import ipaddress
import os
import re
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RDAP_URL = "https://rdap.org/ip/{ip}"
IP_API_URL = "http://ip-api.com/json/{ip}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_RESOURCE_URL = "https://www.virustotal.com/api/v3/{kind}/{resource}"

USER_AGENT = "Edgerunners/6.0 (open-source security automation)"
REQUEST_TIMEOUT = 15
KEV_CACHE_TTL = 3600
LANDSCAPE_CACHE_TTL = 900
NVD_MIN_INTERVAL = 6.0
NVD_MIN_INTERVAL_KEYED = 0.7

THREAT_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]

_session = requests.Session()
_session.headers.update({"User-Agent": USER_AGENT})

_kev_cache: Dict[str, Any] = {"data": None, "fetched_at": 0.0}
_landscape_cache: Dict[str, Any] = {"data": None, "fetched_at": 0.0}
_nvd_last_request = 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get(url: str, params: Optional[Dict[str, Any]] = None,
         headers: Optional[Dict[str, str]] = None,
         timeout: int = REQUEST_TIMEOUT) -> tuple:
    try:
        response = _session.get(url, params=params, headers=headers,
                                timeout=timeout, allow_redirects=True)
        return response, None
    except requests.RequestException as exc:
        return None, str(exc)


def _max_level(a: str, b: str) -> str:
    try:
        return a if THREAT_LEVELS.index(a) >= THREAT_LEVELS.index(b) else b
    except ValueError:
        return a


def _nvd_get(params: Dict[str, Any]) -> tuple:
    global _nvd_last_request
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    interval = NVD_MIN_INTERVAL_KEYED if api_key else NVD_MIN_INTERVAL
    wait = interval - (time.time() - _nvd_last_request)
    if wait > 0:
        time.sleep(wait)
    headers = {"apiKey": api_key} if api_key else None
    _nvd_last_request = time.time()
    return _get(NVD_URL, params=params, headers=headers, timeout=30)


def _normalize_nvd_cve(cve_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not cve_data:
        return None
    cve_id = cve_data.get("id", "Unknown")
    metrics = cve_data.get("metrics", {})
    cvss_score = 0.0
    severity = "UNKNOWN"
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            cvss = metrics[key][0].get("cvssData", {})
            cvss_score = cvss.get("baseScore", 0.0)
            severity = cvss.get("baseSeverity", "UNKNOWN").upper()
            break
    else:
        if metrics.get("cvssMetricV2"):
            cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score > 0:
                severity = "LOW"

    description = "No description available"
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", description)
            break

    references = [ref.get("url", "") for ref in cve_data.get("references", [])][:5]

    affected_software = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", [])[:3]:
                cpe_name = cpe.get("criteria", "")
                if cpe_name.startswith("cpe:2.3:"):
                    parts = cpe_name.split(":")
                    if len(parts) >= 6:
                        vendor, product = parts[3], parts[4]
                        version = parts[5] if parts[5] != "*" else "all versions"
                        affected_software.append(f"{vendor} {product} {version}")

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "published_date": cve_data.get("published", ""),
        "last_modified": cve_data.get("lastModified", ""),
        "affected_software": affected_software[:5],
        "references": references,
        "source": "NVD",
    }


def fetch_kev(force_refresh: bool = False) -> Dict[str, Any]:
    """Fetch the CISA Known Exploited Vulnerabilities catalog (keyless, cached 1h)."""
    now = time.time()
    cached = _kev_cache["data"]
    if not force_refresh and cached is not None and now - _kev_cache["fetched_at"] < KEV_CACHE_TTL:
        return cached

    response, error = _get(KEV_URL, timeout=30)
    if response is None or response.status_code != 200:
        reason = error or (f"HTTP {response.status_code}" if response is not None else "no response")
        if cached is not None:
            stale = dict(cached)
            stale["stale"] = True
            stale["stale_reason"] = reason
            return stale
        return {"success": False, "error": f"CISA KEV unavailable: {reason}",
                "vulnerabilities": [], "source": "CISA KEV"}

    try:
        catalog = response.json()
    except ValueError as exc:
        return {"success": False, "error": f"CISA KEV invalid JSON: {exc}",
                "vulnerabilities": [], "source": "CISA KEV"}

    result = {
        "success": True,
        "title": catalog.get("title", "CISA KEV Catalog"),
        "catalog_version": catalog.get("catalogVersion", ""),
        "date_released": catalog.get("dateReleased", ""),
        "count": len(catalog.get("vulnerabilities", [])),
        "vulnerabilities": catalog.get("vulnerabilities", []),
        "source": "CISA KEV",
        "retrieved_at": _now_iso(),
    }
    _kev_cache["data"] = result
    _kev_cache["fetched_at"] = time.time()
    return result


def kev_entries_for(keyword: str, limit: int = 20) -> Dict[str, Any]:
    """Match a product/keyword against the CISA KEV catalog (confirmed exploited in the wild)."""
    kev = fetch_kev()
    if not kev.get("success"):
        return {"success": False, "error": kev.get("error", "CISA KEV unavailable"),
                "entries": [], "matched": 0, "source": "CISA KEV"}

    keyword_fold = keyword.casefold().strip()
    tokens = [t for t in re.split(r"[^a-z0-9.]+", keyword_fold) if len(t) >= 3]
    matched = []
    for vuln in kev.get("vulnerabilities", []):
        haystack = " ".join([
            str(vuln.get("vendorProject", "")),
            str(vuln.get("product", "")),
            str(vuln.get("vulnerabilityName", "")),
        ]).casefold()
        if keyword_fold and keyword_fold in haystack:
            matched.append(vuln)
        elif tokens and any(token in haystack for token in tokens):
            matched.append(vuln)

    matched.sort(key=lambda v: str(v.get("dateAdded", "")), reverse=True)
    return {
        "success": True,
        "entries": matched[:limit],
        "matched": len(matched),
        "keyword": keyword,
        "source": "CISA KEV",
        "retrieved_at": _now_iso(),
    }


def _nvd_keyword_query(params: Dict[str, Any]) -> tuple:
    response, error = _nvd_get(params)
    if response is None:
        return None, 0, f"NVD unreachable: {error}"
    if response.status_code != 200:
        return None, 0, f"NVD HTTP {response.status_code}"
    try:
        payload = response.json()
    except ValueError as exc:
        return None, 0, f"NVD invalid JSON: {exc}"
    entries = []
    for item in payload.get("vulnerabilities", []):
        entry = _normalize_nvd_cve(item.get("cve", {}))
        if entry:
            entries.append(entry)
    return entries, payload.get("totalResults", len(entries)), None


def search_product_cves(keyword: str, limit: int = 20) -> Dict[str, Any]:
    """Real CVE search for a product via NVD keywordSearch, cross-referenced with CISA KEV."""
    page_size = min(max(int(limit) * 5, 25), 100)
    now = datetime.now(timezone.utc)
    window_days = 120

    params = {
        "keywordSearch": keyword,
        "pubStartDate": (now - timedelta(days=window_days)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "resultsPerPage": page_size,
    }
    cves, total, error = _nvd_keyword_query(params)
    if cves is None:
        return {"success": False, "error": error,
                "cves": [], "data_sources": ["NVD API v2.0"]}
    publication_window = f"published in last {window_days} days"

    if not cves:
        cves, total, error = _nvd_keyword_query({
            "keywordSearch": keyword,
            "resultsPerPage": page_size,
        })
        if cves is None:
            return {"success": False, "error": error,
                    "cves": [], "data_sources": ["NVD API v2.0"]}
        publication_window = "all time (nothing published in the last 120 days)"

    cves.sort(key=lambda c: str(c.get("published_date", "")), reverse=True)
    cves = cves[:limit]

    data_sources = ["NVD API v2.0"]
    kev = fetch_kev()
    if kev.get("success"):
        data_sources.append("CISA KEV")
        kev_index = {v.get("cveID"): v for v in kev.get("vulnerabilities", [])}
        for entry in cves:
            kev_hit = kev_index.get(entry["cve_id"])
            if kev_hit:
                entry["known_exploited"] = True
                entry["kev"] = {
                    "date_added": kev_hit.get("dateAdded"),
                    "vendor": kev_hit.get("vendorProject"),
                    "product": kev_hit.get("product"),
                    "ransomware_use": kev_hit.get("knownRansomwareCampaignUse"),
                }
            else:
                entry["known_exploited"] = False

    return {
        "success": True,
        "cves": cves,
        "total_results": total,
        "keyword": keyword,
        "publication_window": publication_window,
        "data_sources": data_sources,
        "retrieved_at": _now_iso(),
    }


def _rdap_lookup(ip: str) -> tuple:
    response, error = _get(RDAP_URL.format(ip=ip), timeout=15)
    if response is None:
        return None, error or "RDAP unreachable"
    if response.status_code != 200:
        return None, f"RDAP HTTP {response.status_code}"
    try:
        data = response.json()
    except ValueError:
        return None, "RDAP invalid JSON"
    remarks = " ".join(
        str(r.get("description", "")) for r in data.get("remarks", [])
        if isinstance(r.get("description"), list)
    )
    return {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "country": data.get("country"),
        "status": data.get("status", []),
        "type": data.get("type"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "remarks": remarks[:500],
        "source": "RDAP",
    }, None


def _geo_lookup(ip: str) -> tuple:
    fields = "status,message,country,countryCode,regionName,city,isp,org,as,hosting,proxy,query"
    response, error = _get(IP_API_URL.format(ip=ip) + f"?fields={fields}", timeout=10)
    if response is None:
        return None, error or "ip-api unreachable"
    try:
        data = response.json()
    except ValueError:
        return None, "ip-api invalid JSON"
    if data.get("status") != "success":
        return None, data.get("message", "ip-api query failed")
    return {
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "as": data.get("as"),
        "datacenter_hosting": data.get("hosting"),
        "proxy_vpn": data.get("proxy"),
        "source": "ip-api.com",
    }, None


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(3)
        try:
            return socket.gethostbyaddr(ip)[0]
        finally:
            socket.setdefaulttimeout(previous)
    except (socket.herror, socket.gaierror, OSError, TimeoutError):
        return None


def _abuseipdb_lookup(ip: str) -> tuple:
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return None, "ABUSEIPDB_API_KEY not set"
    response, error = _get(
        ABUSEIPDB_URL,
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=15,
    )
    if response is None:
        return None, error or "AbuseIPDB unreachable"
    if response.status_code != 200:
        return None, f"AbuseIPDB HTTP {response.status_code}"
    try:
        data = response.json().get("data", {})
    except ValueError:
        return None, "AbuseIPDB invalid JSON"
    return {
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "last_reported_at": data.get("lastReportedAt"),
        "isp": data.get("isp"),
        "country_code": data.get("countryCode"),
        "domain": data.get("domain"),
        "source": "AbuseIPDB",
    }, None


def _virustotal_lookup(kind: str, resource: str) -> tuple:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return None, "VIRUSTOTAL_API_KEY not set"
    response, error = _get(
        VT_RESOURCE_URL.format(kind=kind, resource=resource),
        headers={"x-apikey": api_key},
        timeout=20,
    )
    if response is None:
        return None, error or "VirusTotal unreachable"
    if response.status_code == 404:
        return {"malicious": 0, "suspicious": 0, "undetected": 0,
                "known_to_virustotal": False, "source": "VirusTotal"}, None
    if response.status_code != 200:
        return None, f"VirusTotal HTTP {response.status_code}"
    try:
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    except ValueError:
        return None, "VirusTotal invalid JSON"
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "known_to_virustotal": True,
        "source": "VirusTotal",
    }, None


def _level_from_signals(abuse_score: int, vt_malicious: int,
                        reputation_available: bool) -> tuple:
    score = 0
    level = "UNKNOWN"
    if abuse_score:
        score = max(score, abuse_score)
    if vt_malicious:
        score = max(score, min(vt_malicious * 10, 100))
    if abuse_score >= 75 or vt_malicious >= 10:
        level = "CRITICAL"
    elif abuse_score >= 25 or vt_malicious >= 3:
        level = "HIGH"
    elif abuse_score > 0 or vt_malicious >= 1:
        level = "MEDIUM"
    elif reputation_available:
        level = "LOW"
    return level, score


def ip_reputation(ip: str) -> Dict[str, Any]:
    """Real IP reputation: RDAP + geo + PTR + optional AbuseIPDB/VirusTotal free tiers."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return {"success": False, "error": f"Invalid IP address: {ip}",
                "threat_level": "UNKNOWN", "threat_score": 0,
                "sources_queried": [], "sources_unavailable": [],
                "retrieved_at": _now_iso()}

    result: Dict[str, Any] = {
        "success": True,
        "ip": str(addr),
        "version": addr.version,
        "is_global": addr.is_global,
        "is_private": addr.is_private,
        "is_reserved": addr.is_reserved,
        "is_loopback": addr.is_loopback,
        "is_multicast": addr.is_multicast,
        "retrieved_at": _now_iso(),
    }
    queried: List[str] = []
    unavailable: List[Dict[str, str]] = []

    rdap, rdap_error = _rdap_lookup(str(addr))
    if rdap:
        result["rdap"] = rdap
        queried.append("RDAP")
    else:
        unavailable.append({"source": "RDAP", "reason": str(rdap_error)})

    if addr.is_global:
        geo, geo_error = _geo_lookup(str(addr))
        if geo:
            result["geo"] = geo
            queried.append("ip-api.com")
        else:
            unavailable.append({"source": "ip-api.com", "reason": str(geo_error)})

    ptr = _reverse_dns(str(addr))
    if ptr:
        result["reverse_dns"] = ptr

    abuse, abuse_error = _abuseipdb_lookup(str(addr))
    reputation_available = False
    abuse_score = 0
    if abuse:
        result["abuseipdb"] = abuse
        queried.append("AbuseIPDB")
        abuse_score = int(abuse.get("abuse_confidence_score", 0) or 0)
        reputation_available = True
    else:
        unavailable.append({"source": "AbuseIPDB", "reason": str(abuse_error)})

    vt, vt_error = _virustotal_lookup("ip_addresses", str(addr))
    vt_malicious = 0
    if vt:
        result["virustotal"] = vt
        queried.append("VirusTotal")
        vt_malicious = int(vt.get("malicious", 0) or 0)
        reputation_available = True
    else:
        unavailable.append({"source": "VirusTotal", "reason": str(vt_error)})

    if not addr.is_global:
        level, score = "INFO", 0
    else:
        level, score = _level_from_signals(abuse_score, vt_malicious, reputation_available)
        geo_flags = result.get("geo", {})
        if geo_flags.get("proxy_vpn") and level in ("LOW", "UNKNOWN"):
            level = "MEDIUM"
            score = max(score, 40)

    result["threat_level"] = level
    result["threat_score"] = score
    result["sources_queried"] = queried
    result["sources_unavailable"] = unavailable
    if not reputation_available and addr.is_global:
        result["note"] = ("Reputation engines unavailable — set ABUSEIPDB_API_KEY / "
                          "VIRUSTOTAL_API_KEY (free tiers) for real abuse scoring. "
                          "threat_level stays UNKNOWN without them.")
    return result


def hash_reputation(hash_value: str) -> Dict[str, Any]:
    """Real file-hash reputation via VirusTotal (free-tier key). Locally classifies the hash type."""
    value = str(hash_value).strip().lower()
    algorithms = {32: "md5", 40: "sha1", 64: "sha256"}
    if not re.fullmatch(r"[a-f0-9]+", value) or len(value) not in algorithms:
        return {"success": False,
                "error": f"Not a valid MD5/SHA1/SHA256 hash: {hash_value}",
                "threat_level": "UNKNOWN", "threat_score": 0,
                "sources_queried": [], "sources_unavailable": [],
                "retrieved_at": _now_iso()}

    result: Dict[str, Any] = {
        "success": True,
        "hash": value,
        "algorithm": algorithms[len(value)],
        "retrieved_at": _now_iso(),
    }
    queried: List[str] = []
    unavailable: List[Dict[str, str]] = []

    vt, vt_error = _virustotal_lookup("files", value)
    level = "UNKNOWN"
    score = 0
    if vt:
        result["virustotal"] = vt
        queried.append("VirusTotal")
        detections = int(vt.get("malicious", 0) or 0) + int(vt.get("suspicious", 0) or 0)
        if detections >= 10:
            level = "CRITICAL"
        elif detections >= 3:
            level = "HIGH"
        elif detections >= 1:
            level = "MEDIUM"
        else:
            level = "LOW"
        score = min(detections * 10, 100)
    else:
        unavailable.append({"source": "VirusTotal", "reason": str(vt_error)})

    result["threat_level"] = level
    result["threat_score"] = score
    result["sources_queried"] = queried
    result["sources_unavailable"] = unavailable
    if not queried:
        result["note"] = ("Set VIRUSTOTAL_API_KEY (free tier) for real hash detection stats. "
                          "threat_level stays UNKNOWN without it.")
    return result


def check_url(url: str) -> Dict[str, Any]:
    """Reachability check for a repository/source URL (no content analysis)."""
    if not str(url).startswith(("http://", "https://")):
        return {"reachable": False, "error": "Only http(s) URLs are supported"}
    try:
        response = _session.head(url, timeout=10, allow_redirects=True)
        return {"reachable": True, "status_code": response.status_code,
                "final_url": str(response.url)}
    except requests.RequestException as exc:
        return {"reachable": False, "error": str(exc)}


def threat_landscape(critical_hours: int = 168, top_n: int = 10) -> Dict[str, Any]:
    """Real threat landscape: latest critical NVD CVEs + recent CISA KEV additions."""
    now = time.time()
    if _landscape_cache["data"] is not None and now - _landscape_cache["fetched_at"] < LANDSCAPE_CACHE_TTL:
        cached = dict(_landscape_cache["data"])
        cached["cached"] = True
        return cached

    sources_status: Dict[str, str] = {}
    data_sources: List[str] = []

    critical_cves: List[Dict[str, Any]] = []
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=critical_hours)
    response, error = _nvd_get({
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": top_n,
    })
    if response is not None and response.status_code == 200:
        try:
            for item in response.json().get("vulnerabilities", [])[:top_n]:
                entry = _normalize_nvd_cve(item.get("cve", {}))
                if entry:
                    critical_cves.append(entry)
            sources_status["nvd"] = "ok"
            data_sources.append("NVD API v2.0")
        except ValueError:
            sources_status["nvd"] = "invalid JSON"
    else:
        sources_status["nvd"] = error or (
            f"HTTP {response.status_code}" if response is not None else "no response")

    recent_kev: List[Dict[str, Any]] = []
    trending_products: List[Dict[str, Any]] = []
    kev = fetch_kev()
    if kev.get("success"):
        sources_status["cisa_kev"] = "ok"
        data_sources.append("CISA KEV")
        vulnerabilities = kev.get("vulnerabilities", [])
        recent_kev = sorted(
            vulnerabilities, key=lambda v: str(v.get("dateAdded", "")), reverse=True
        )[:top_n]
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")
        product_counts: Dict[str, int] = {}
        for vuln in vulnerabilities:
            if str(vuln.get("dateAdded", "")) >= cutoff:
                key = f"{vuln.get('vendorProject', '?')}/{vuln.get('product', '?')}"
                product_counts[key] = product_counts.get(key, 0) + 1
        trending_products = [
            {"product": product, "kev_entries_90d": count}
            for product, count in sorted(product_counts.items(),
                                          key=lambda kv: kv[1], reverse=True)[:8]
        ]
    else:
        sources_status["cisa_kev"] = kev.get("error", "unavailable")

    degraded = sources_status.get("nvd") != "ok" or sources_status.get("cisa_kev") != "ok"
    result = {
        "success": bool(critical_cves) or bool(recent_kev),
        "degraded": degraded,
        "critical_cves_last_7_days": critical_cves,
        "recent_kev_additions": recent_kev,
        "trending_products": trending_products,
        "summary": {
            "critical_cve_count": len(critical_cves),
            "recent_kev_count": len(recent_kev),
            "trending_product_count": len(trending_products),
        },
        "sources_status": sources_status,
        "data_sources": data_sources,
        "retrieved_at": _now_iso(),
    }
    if result["success"]:
        _landscape_cache["data"] = result
        _landscape_cache["fetched_at"] = time.time()
    return result
