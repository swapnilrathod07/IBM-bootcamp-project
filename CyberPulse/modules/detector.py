"""
IOC Type Detection and Sanitization (Defang / Refang) Engine.
Supports: IPv4 (with CIDR & Ports, leading zeros, hex octets),
IPv6 (with CIDR & Ports, zone IDs, compressed/exploded normalization),
MD5, SHA-1, SHA-256 (with whitespace/hyphen tolerance & invalid length detection),
Domain (with IDN / Punycode & Ports), URL (with unconventional defanging & IPv6 hosts).
"""
import re
import ipaddress
from typing import Dict, Any, Optional, Tuple


IOC_TYPES = {
    "IPV4": "IPv4 Address",
    "IPV6": "IPv6 Address",
    "MD5": "MD5 Hash",
    "SHA1": "SHA-1 Hash",
    "SHA256": "SHA-256 Hash",
    "DOMAIN": "Domain Name",
    "URL": "Uniform Resource Locator (URL)",
    "UNKNOWN": "Unknown / Unsupported",
}

# Hex hash regexes
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

# Domain regex (supports alphanumeric labels, hyphens, and underscores)
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_\-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,63}$"
)

# URL regex (supports standard hosts, domains, ports, and bracketed IPv6 hosts)
URL_REGEX = re.compile(
    r"^(?:https?|ftp):\/\/"  # Scheme
    r"(?:(?:\[[a-fA-F0-9:]+(?:%[a-zA-Z0-9_\-]+)?\]|[a-zA-Z0-9_\-\.]+)(?::\d+)?)?"  # Host & Optional Port
    r"(?:\/[^\s]*)?$",  # Path and query string
    re.IGNORECASE
)


def refang_ioc(indicator: str) -> str:
    """
    Refangs a defanged IOC string for querying live APIs and threat repositories.
    Handles nested brackets, bracketed schemes, dot obfuscations, port brackets,
    and unconventional schemes (hxxp, hxxps, meow, meows).
    Examples:
      - 'hxxps[://]bad[.]com' -> 'https://bad.com'
      - 'meow://evil.com/path' -> 'http://evil.com/path'
      - 'meows[:]//evil.com/path' -> 'https://evil.com/path'
      - '192[[.]]168[[.]]1[[.]]1' -> '192.168.1.1'
      - 'hxxp[s]://evil[.]com' -> 'https://evil.com'
      - '192[.]168[.]1(dot)1' -> '192.168.1.1'
    """
    if not indicator:
        return ""

    s = indicator.strip().strip("'\"")

    # 1. Unconventional & defanged protocol refanging:
    # Matches meow/meows, hxxp/hxxps, http/https with bracketed separators [://], [:]//, [:], [//], //, ://
    def _scheme_repl(m):
        scheme_prefix = m.group(1).lower()
        is_ssl = 's' in scheme_prefix
        return 'https://' if is_ssl else 'http://'

    s = re.sub(
        r'(?i)\b(hxxp\[s\]|http\[s\]|meow\[s\]|hxxps|https|meows|hxxp|http|meow)\s*(?:\[:\/\/\]|\[:\]\/\/|\[:\]\[\/\/\]|\[\/\/\]|\[:\]|\/\/|:\/\/|:\s*\/)',
        _scheme_repl,
        s
    )


    # 2. Iterative bracket stripping for dots and colons
    s = re.sub(r'\[+(\.|\bdot\b)\]+', '.', s, flags=re.IGNORECASE)
    s = re.sub(r'\(+(\.|\bdot\b)\)+', '.', s, flags=re.IGNORECASE)
    s = re.sub(r'\{+(\.|\bdot\b)\}+', '.', s, flags=re.IGNORECASE)

    for _ in range(3):
        s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
        s = s.replace("[dot]", ".").replace("(dot)", ".").replace("{dot}", ".")
        s = s.replace("[:]", ":").replace("(:)", ":").replace("{:}", ":")
        s = s.replace("[colon]", ":").replace("(colon)", ":")

    return s.strip()


def defang_ioc(indicator: str) -> str:
    """
    Defangs an IOC so it cannot be accidentally navigated to or executed.
    Idempotent: safe to run on already-defanged indicators.
    Examples:
      - 'https://bad.com/payload' -> 'hxxps://bad[.]com/payload'
      - '1.1.1.1' -> '1[.]1[.]1[.]1'
    """
    if not indicator:
        return ""

    # Normalize/refang first to ensure idempotence
    s = refang_ioc(indicator.strip())

    # Protocol defanging
    s = re.sub(r'(?i)\bhttps:\/\/', 'hxxps://', s)
    s = re.sub(r'(?i)\bhttp:\/\/', 'hxxp://', s)

    # Dot defanging
    s = s.replace(".", "[.]")

    return s


def normalize_ipv4_candidate(candidate: str) -> Optional[str]:
    """
    Parses IPv4 candidate string handling leading zeroes (e.g. 192.168.01.1)
    and mixed-case hex octets (e.g. 0x7f.0.0.1).
    Returns canonical dotted-decimal string or None.
    """
    if not candidate or not isinstance(candidate, str):
        return None
    parts = candidate.strip().split(".")
    if len(parts) != 4:
        return None

    octets = []
    for p in parts:
        p_clean = p.strip()
        if not p_clean:
            return None
        try:
            if p_clean.lower().startswith("0x"):
                val = int(p_clean, 16)
            else:
                val = int(p_clean, 10)
            if 0 <= val <= 255:
                octets.append(str(val))
            else:
                return None
        except ValueError:
            return None

    canonical = ".".join(octets)
    try:
        ip = ipaddress.IPv4Address(canonical)
        return str(ip)
    except ValueError:
        return None


def is_loopback_ipv4(candidate: str) -> bool:
    """Checks if candidate is an IPv4 loopback address (127.0.0.0/8)."""
    norm = normalize_ipv4_candidate(candidate)
    if not norm:
        return False
    try:
        ip = ipaddress.IPv4Address(norm)
        return ip.is_loopback or norm.startswith("127.")
    except ValueError:
        return False


def is_valid_ipv4(candidate: str) -> Tuple[bool, bool]:
    """
    Validates if candidate is a valid IPv4.
    Returns: (is_valid, is_private_or_reserved)
    """
    norm = normalize_ipv4_candidate(candidate)
    if not norm:
        return False, False
    try:
        ip = ipaddress.IPv4Address(norm)
        is_private = ip.is_private or ip.is_loopback or ip.is_link_local
        return True, is_private
    except ValueError:
        return False, False


def normalize_ipv6_candidate(candidate: str) -> Tuple[bool, bool, Optional[str], Optional[str]]:
    """
    Parses IPv6 candidate string, stripping zone IDs and normalizing compressed/exploded formats.
    Returns: (is_valid, is_private, normalized_compressed_ip, zone_id)
    """
    if not candidate or not isinstance(candidate, str):
        return False, False, None, None

    clean = candidate.strip()
    zone_id = None
    if "%" in clean:
        parts = clean.split("%", 1)
        clean = parts[0]
        zone_id = parts[1]

    try:
        ip = ipaddress.IPv6Address(clean)
        is_private = ip.is_private or ip.is_loopback or ip.is_link_local
        # str(ip) returns the canonical RFC 5952 compressed representation
        return True, is_private, str(ip), zone_id
    except ValueError:
        return False, False, None, None


def is_loopback_ipv6(candidate: str) -> bool:
    """Checks if candidate is an IPv6 loopback address (::1)."""
    valid, _, norm, _ = normalize_ipv6_candidate(candidate)
    if not valid or not norm:
        return False
    try:
        ip = ipaddress.IPv6Address(norm)
        return ip.is_loopback
    except ValueError:
        return False


def is_valid_ipv6(candidate: str) -> Tuple[bool, bool]:
    """
    Validates if candidate is a valid IPv6.
    Returns: (is_valid, is_private_or_reserved)
    """
    valid, is_priv, _, _ = normalize_ipv6_candidate(candidate)
    return valid, is_priv


def is_rfc1918_or_internal_ip(ip_obj) -> bool:
    """Checks if IP is RFC 1918 private, RFC 6598 CGNAT, RFC 3927 link-local, RFC 1122 unspecified, or RFC 4193 ULA."""
    if isinstance(ip_obj, ipaddress.IPv4Address):
        if ip_obj.is_unspecified:
            return True
        octets = ip_obj.exploded.split(".")
        o0, o1 = int(octets[0]), int(octets[1])
        if o0 == 10:
            return True
        if o0 == 172 and 16 <= o1 <= 31:
            return True
        if o0 == 192 and o1 == 168:
            return True
        if o0 == 169 and o1 == 254:
            return True
        if o0 == 100 and 64 <= o1 <= 127:
            return True
        return False
    elif isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.is_unspecified:
            return True
        return ip_obj.is_private and not ip_obj.is_multicast and not ip_obj.is_loopback
    return False


def check_host_internal_and_loopback(host: Optional[str]) -> Tuple[bool, bool, str]:
    """
    Evaluates whether host string (IP or hostname) is private/internal or loopback.
    Returns: (is_private, is_loopback, diagnostic_note)
    """
    if not host or not isinstance(host, str):
        return False, False, ""

    clean = host.strip().lower()
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]
    if "%" in clean:
        clean = clean.split("%", 1)[0]

    # 1. Hostnames
    if clean == "localhost" or clean.endswith(".localhost"):
        return True, True, "Local loopback host (RFC 6761)"
    if clean in ("localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        return True, True, "Local loopback host"
    if clean.endswith((".local", ".internal", ".lan", ".home", ".corp")):
        return True, False, "Internal non-routable domain name"

    # 2. Try IPv4
    norm_v4 = normalize_ipv4_candidate(clean)
    if norm_v4:
        try:
            ip4 = ipaddress.IPv4Address(norm_v4)
            is_loop = ip4.is_loopback or norm_v4.startswith("127.")
            if is_loop:
                return True, True, "Local loopback IPv4 address (RFC 1122 / RFC 5735)"
            if ip4.is_unspecified:
                return True, False, "RFC 1122 / Local host unspecified address (0.0.0.0)"
            if is_rfc1918_or_internal_ip(ip4):
                return True, False, "RFC 1918 / Private IPv4 subnet"
            return False, False, ""
        except ValueError:
            pass

    # 3. Try IPv6
    try:
        ip6 = ipaddress.IPv6Address(clean)
        is_loop = ip6.is_loopback
        if is_loop:
            return True, True, "Local loopback IPv6 address (RFC 4291)"
        if ip6.is_unspecified:
            return True, False, "RFC 4291 / Unspecified IPv6 address (::)"
        if is_rfc1918_or_internal_ip(ip6):
            return True, False, "Private / Local IPv6 address (RFC 4193)"
        return False, False, ""
    except ValueError:
        pass

    return False, False, ""



def detect_ioc_type(raw_input: str) -> Dict[str, Any]:
    """
    Analyzes an input string, detects whether it is defanged, refangs it,
    and categorizes it as IPv4, IPv6, MD5, SHA-1, SHA-256, Domain, URL, or Unknown.
    Handles CIDR subnets (v4 & v6), IP:port combinations, domain:port notations,
    IDN/Punycode domains, hash whitespace tolerance, and informative diagnostics.
    Identifies internal/RFC 1918 private assets and local loopbacks (127.0.0.1, localhost, ::1).
    """
    if not raw_input or not isinstance(raw_input, str):
        return {
            "raw": "",
            "normalized": "",
            "type": "UNKNOWN",
            "type_label": IOC_TYPES["UNKNOWN"],
            "is_defanged": False,
            "is_private": False,
            "is_loopback": False,
            "valid": False,
            "notes": "Empty input provided."
        }

    raw = raw_input.strip().strip("'\"")
    refanged = refang_ioc(raw)
    is_defanged = (raw != refanged)

    # 1. Cryptographic Hashes (with whitespace & hyphen tolerance, and prefix stripping)
    refanged_nohash_prefix = re.sub(r'(?i)^(?:md5|sha1|sha256|hash)\s*:\s*', '', refanged)
    compact_hash = re.sub(r"[\s\-]+", "", refanged_nohash_prefix)
    if MD5_REGEX.match(compact_hash):
        return {
            "raw": raw,
            "normalized": compact_hash.lower(),
            "type": "MD5",
            "type_label": IOC_TYPES["MD5"],
            "is_defanged": is_defanged or (compact_hash != refanged),
            "is_private": False,
            "is_loopback": False,
            "valid": True,
            "notes": "Valid 32-character MD5 cryptographic hash."
        }

    if SHA1_REGEX.match(compact_hash):
        return {
            "raw": raw,
            "normalized": compact_hash.lower(),
            "type": "SHA1",
            "type_label": IOC_TYPES["SHA1"],
            "is_defanged": is_defanged or (compact_hash != refanged),
            "is_private": False,
            "is_loopback": False,
            "valid": True,
            "notes": "Valid 40-character SHA-1 cryptographic hash."
        }

    if SHA256_REGEX.match(compact_hash):
        return {
            "raw": raw,
            "normalized": compact_hash.lower(),
            "type": "SHA256",
            "type_label": IOC_TYPES["SHA256"],
            "is_defanged": is_defanged or (compact_hash != refanged),
            "is_private": False,
            "is_loopback": False,
            "valid": True,
            "notes": "Valid 64-character SHA-256 cryptographic hash."
        }

    # 1b. Hex string with invalid hash length diagnostic
    if re.fullmatch(r"^[a-fA-F0-9]+$", compact_hash) and (28 <= len(compact_hash) <= 70) and len(compact_hash) not in (32, 40, 64):
        return {
            "raw": raw,
            "normalized": compact_hash.lower(),
            "type": "UNKNOWN",
            "type_label": IOC_TYPES["UNKNOWN"],
            "is_defanged": is_defanged,
            "is_private": False,
            "is_loopback": False,
            "valid": False,
            "notes": f"Invalid cryptographic hash length ({len(compact_hash)} hex characters). Supported standards: MD5 (32 chars), SHA-1 (40 chars), SHA-256 (64 chars)."
        }

    # 2. CIDR Blocks (IPv4 and IPv6)
    if "/" in refanged and not refanged.startswith(("http://", "https://", "ftp://")):
        cidr_parts = refanged.split("/", 1)
        ip_part = cidr_parts[0]
        prefix_part = cidr_parts[1]

        # Try IPv4 CIDR
        norm_v4_prefix = normalize_ipv4_candidate(ip_part)
        if norm_v4_prefix:
            try:
                net = ipaddress.IPv4Network(f"{norm_v4_prefix}/{prefix_part}", strict=False)
                norm_ip = str(net.network_address)
                is_loop = is_loopback_ipv4(norm_ip) or net.is_loopback
                is_priv = is_loop or is_rfc1918_or_internal_ip(net.network_address)
                note = f"IPv4 CIDR network block /{net.prefixlen} (network host {norm_ip} targeted for reputation check)."
                if net.prefixlen == 32:
                    note = "Single IPv4 host via /32 CIDR notation."
                if is_loop:
                    note += " (Local loopback range)."
                elif is_priv:
                    note += " (RFC 1918 / Private range)."
                return {
                    "raw": raw,
                    "normalized": norm_ip,
                    "type": "IPV4",
                    "type_label": IOC_TYPES["IPV4"],
                    "is_defanged": is_defanged,
                    "is_private": is_priv,
                    "is_loopback": is_loop,
                    "valid": True,
                    "notes": note
                }
            except ValueError:
                pass

        # Try IPv6 CIDR
        try:
            net6 = ipaddress.IPv6Network(refanged, strict=False)
            norm_ip6 = str(net6.network_address)
            is_loop6 = is_loopback_ipv6(norm_ip6) or net6.is_loopback
            is_priv6 = is_loop6 or is_rfc1918_or_internal_ip(net6.network_address)
            note = f"IPv6 CIDR network block /{net6.prefixlen} (network address {norm_ip6} targeted for threat lookup)."
            if is_loop6:
                note += " (Local loopback range)."
            elif is_priv6:
                note += " (Private / Local range)."
            return {
                "raw": raw,
                "normalized": norm_ip6,
                "type": "IPV6",
                "type_label": IOC_TYPES["IPV6"],
                "is_defanged": is_defanged,
                "is_private": is_priv6,
                "is_loopback": is_loop6,
                "valid": True,
                "notes": note
            }
        except ValueError:
            pass

    # 3. IPv4 with Port (e.g. 185.220.101.5:9001, 127.0.0.1:5000 or 010.0.0.1:8080)
    m_ip_port = re.match(r"^([^:]+):(\d{1,5})$", refanged)
    if m_ip_port:
        ip_cand, port_cand = m_ip_port.groups()
        norm_v4_cand = normalize_ipv4_candidate(ip_cand)
        if norm_v4_cand and 0 < int(port_cand) <= 65535:
            is_ipv4_cand, is_priv_cand = is_valid_ipv4(norm_v4_cand)
            if is_ipv4_cand:
                is_loop_cand = is_loopback_ipv4(norm_v4_cand)
                note = f"Public IPv4 address on port {port_cand} (port stripped for threat engine lookup)."
                if is_loop_cand:
                    note = f"Local loopback IPv4 address on port {port_cand} (RFC 1122 / RFC 5735)."
                elif is_priv_cand:
                    note = f"Private/RFC 1918 IPv4 address on port {port_cand}."
                return {
                    "raw": raw,
                    "normalized": norm_v4_cand,
                    "type": "IPV4",
                    "type_label": IOC_TYPES["IPV4"],
                    "is_defanged": is_defanged,
                    "is_private": is_priv_cand,
                    "is_loopback": is_loop_cand,
                    "valid": True,
                    "port": int(port_cand),
                    "notes": note
                }

    # 4. Standard IPv4
    norm_v4 = normalize_ipv4_candidate(refanged)
    if norm_v4:
        is_ipv4, is_priv_v4 = is_valid_ipv4(norm_v4)
        if is_ipv4:
            is_loop_v4 = is_loopback_ipv4(norm_v4)
            note = "Public IPv4 address ready for reputation check."
            if is_loop_v4:
                note = "Local loopback IPv4 address (RFC 1122 / RFC 5735). Non-routable on public threat intelligence feeds."
            elif is_priv_v4:
                note = "RFC 1918 / Reserved private address. Public threat lookups may return no external records."
            return {
                "raw": raw,
                "normalized": norm_v4,
                "type": "IPV4",
                "type_label": IOC_TYPES["IPV4"],
                "is_defanged": is_defanged or (norm_v4 != refanged),
                "is_private": is_priv_v4,
                "is_loopback": is_loop_v4,
                "valid": True,
                "notes": note
            }

    # 5. IPv6 (supports bracketed [2001:db8::1], bracketed with port [2001:db8::1]:8080, and zone IDs %eth0)
    clean_v6 = refanged
    v6_port = None
    is_bracketed_v6_url = False
    if clean_v6.startswith("[") and "]" in clean_v6:
        end_idx = clean_v6.index("]")
        bracket_content = clean_v6[1:end_idx]
        remainder = clean_v6[end_idx + 1:]
        if "/" in remainder:
            is_bracketed_v6_url = True
        elif remainder.startswith(":") and remainder[1:].isdigit():
            try:
                p_val = int(remainder[1:])
                if 0 < p_val <= 65535:
                    v6_port = p_val
            except ValueError:
                pass
            clean_v6 = bracket_content
        elif not remainder:
            clean_v6 = bracket_content
        else:
            is_bracketed_v6_url = True

    if not is_bracketed_v6_url:
        is_ipv6, is_priv_v6, norm_v6, zone_id = normalize_ipv6_candidate(clean_v6)
        if is_ipv6 and norm_v6:
            is_loop_v6 = is_loopback_ipv6(norm_v6)
            note = "Standard IPv6 address."
            if zone_id:
                note = f"IPv6 address with scoped zone ID '%{zone_id}' (zone ID stripped for threat engine lookup)."
            if v6_port:
                note = f"IPv6 address on port {v6_port} (port stripped for threat engine lookup)."
            if is_loop_v6:
                note = "Local loopback IPv6 address (::1). Non-routable on public threat intelligence feeds."
            elif is_priv_v6:
                note += " (Private / Local range)."
            return {
                "raw": raw,
                "normalized": norm_v6,
                "type": "IPV6",
                "type_label": IOC_TYPES["IPV6"],
                "is_defanged": is_defanged,
                "is_private": is_priv_v6,
                "is_loopback": is_loop_v6,
                "valid": True,
                "notes": note
            }

    # 5b. Localhost name or Localhost:port directly
    if refanged.lower() == "localhost":
        return {
            "raw": raw,
            "normalized": "localhost",
            "type": "DOMAIN",
            "type_label": IOC_TYPES["DOMAIN"],
            "is_defanged": is_defanged,
            "is_private": True,
            "is_loopback": True,
            "valid": True,
            "notes": "Localhost loopback domain name (RFC 6761). Non-routable on public threat intelligence feeds."
        }

    m_lh_port = re.match(r"^localhost:(\d{1,5})$", refanged, re.IGNORECASE)
    if m_lh_port:
        p_val = int(m_lh_port.group(1))
        if 0 < p_val <= 65535:
            return {
                "raw": raw,
                "normalized": "localhost",
                "type": "DOMAIN",
                "type_label": IOC_TYPES["DOMAIN"],
                "is_defanged": is_defanged,
                "is_private": True,
                "is_loopback": True,
                "valid": True,
                "port": p_val,
                "notes": f"Localhost loopback domain on port {p_val} (RFC 6761)."
            }

    # 6. Complete URL with Scheme (supports IDN / Punycode hosts and bracketed IPv6 hosts)
    if refanged.lower().startswith(("http://", "https://", "ftp://")):
        import urllib.parse
        try:
            parsed = urllib.parse.urlsplit(refanged)
            h = parsed.hostname
            if h:
                try:
                    puny_h = h.encode("idna").decode("ascii")
                except Exception:
                    puny_h = h
                port_str = f":{parsed.port}" if parsed.port else ""
                netloc = f"[{puny_h}]{port_str}" if ":" in puny_h and not puny_h.startswith("[") else f"{puny_h}{port_str}"
                normalized_url = urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path, parsed.query, parsed.fragment))
                if URL_REGEX.match(normalized_url) or h.lower() == "localhost" or h.lower().endswith(".localhost"):
                    is_priv_url, is_loop_url, host_note = check_host_internal_and_loopback(h)
                    note = "Complete URL with valid scheme and path."
                    if is_loop_url:
                        note = "Local loopback development URL (RFC 1122 / RFC 5735). Non-routable on public threat repositories."
                    elif is_priv_url:
                        note = f"RFC 1918 / Private network URL ({host_note}). Non-routable on public threat feeds."
                    elif puny_h != h:
                        note = f"URL with Internationalized Domain Name (IDN: '{h}') normalized to Punycode."
                    return {
                        "raw": raw,
                        "normalized": normalized_url,
                        "type": "URL",
                        "type_label": IOC_TYPES["URL"],
                        "is_defanged": is_defanged,
                        "is_private": is_priv_url,
                        "is_loopback": is_loop_url,
                        "valid": True,
                        "notes": note
                    }
        except Exception:
            pass

    if URL_REGEX.match(refanged):
        import urllib.parse
        is_priv_url, is_loop_url = False, False
        note = "Complete URL with valid scheme and path."
        try:
            parsed = urllib.parse.urlsplit(refanged)
            if parsed.hostname:
                is_priv_url, is_loop_url, _ = check_host_internal_and_loopback(parsed.hostname)
                if is_loop_url:
                    note = "Local loopback development URL (RFC 1122 / RFC 5735). Non-routable on public threat repositories."
                elif is_priv_url:
                    note = "RFC 1918 / Private network URL. Non-routable on public threat feeds."
        except Exception:
            pass
        return {
            "raw": raw,
            "normalized": refanged,
            "type": "URL",
            "type_label": IOC_TYPES["URL"],
            "is_defanged": is_defanged,
            "is_private": is_priv_url,
            "is_loopback": is_loop_url,
            "valid": True,
            "notes": note
        }

    # 7. URL without Scheme (e.g. 127.0.0.1:5000/app, localhost:8080/api, evil.com:8080/payload, münchen.de/path, or [2001:db8::1]/path)
    if "/" in refanged and not refanged.lower().startswith(("http://", "https://", "ftp://")):
        first_segment = refanged.split("/", 1)[0]
        host = first_segment.split(":", 1)[0]
        if first_segment.startswith("[") and "]" in first_segment:
            cand_url = f"http://{refanged}"
            if URL_REGEX.match(cand_url):
                import urllib.parse
                p_v6 = urllib.parse.urlsplit(cand_url).hostname
                is_priv_u, is_loop_u, _ = check_host_internal_and_loopback(p_v6)
                return {
                    "raw": raw,
                    "normalized": cand_url,
                    "type": "URL",
                    "type_label": IOC_TYPES["URL"],
                    "is_defanged": is_defanged,
                    "is_private": is_priv_u,
                    "is_loopback": is_loop_u,
                    "valid": True,
                    "notes": "URL with IPv6 host missing protocol scheme (auto-prepended http:// for analysis)."
                }
        is_host_ip = bool(normalize_ipv4_candidate(host))
        puny_host = None
        try:
            puny_host = host.encode("idna").decode("ascii")
        except Exception:
            puny_host = None
        is_dom = DOMAIN_REGEX.match(host) or (puny_host and DOMAIN_REGEX.match(puny_host)) or (host.lower() == "localhost")
        if is_host_ip or is_dom:
            actual_host = puny_host if (puny_host and not is_host_ip) else host
            port_suffix = (":" + first_segment.split(":", 1)[1]) if ":" in first_segment else ""
            remainder_path = "/" + refanged.split("/", 1)[1]
            candidate_url = f"http://{actual_host}{port_suffix}{remainder_path}"
            if URL_REGEX.match(candidate_url) or actual_host.lower() == "localhost":
                is_priv_u, is_loop_u, host_diag = check_host_internal_and_loopback(actual_host)
                note = "URL missing protocol scheme (auto-prepended http:// for analysis)."
                if is_loop_u:
                    note = "Local development URL missing protocol scheme (auto-prepended http:// for analysis)."
                elif is_priv_u:
                    note = f"Private network URL missing protocol scheme ({host_diag})."
                elif puny_host and puny_host != host:
                    note = f"URL with IDN ('{host}') missing protocol scheme (normalized to Punycode)."
                return {
                    "raw": raw,
                    "normalized": candidate_url,
                    "type": "URL",
                    "type_label": IOC_TYPES["URL"],
                    "is_defanged": is_defanged,
                    "is_private": is_priv_u,
                    "is_loopback": is_loop_u,
                    "valid": True,
                    "notes": note
                }

    # 8. Domain with Port (e.g. evil.com:8080 or münchen.de:8080 or internal-host.local:8080)
    m_dom_port = re.match(r"^([^:]+):(\d{1,5})$", refanged)
    if m_dom_port:
        dom_c, port_c = m_dom_port.groups()
        p_dom = None
        try:
            p_dom = dom_c.encode("idna").decode("ascii")
        except Exception:
            p_dom = None
        is_valid_dom = (DOMAIN_REGEX.match(dom_c) or (p_dom and DOMAIN_REGEX.match(p_dom)) or dom_c.lower() == "localhost" or dom_c.lower().endswith((".local", ".internal", ".lan")))
        if is_valid_dom and 0 < int(port_c) <= 65535:
            target_dom = (p_dom or dom_c).lower()
            is_priv_dom, is_loop_dom, host_diag = check_host_internal_and_loopback(target_dom)
            note = f"Domain name on port {port_c} (port stripped for reputation lookup)."
            if is_loop_dom:
                note = f"Localhost loopback on port {port_c} (RFC 6761)."
            elif is_priv_dom:
                note = f"Internal domain on port {port_c} ({host_diag})."
            elif p_dom and p_dom != dom_c:
                note = f"Internationalized Domain Name on port {port_c} (normalized to Punycode '{target_dom}')."
            return {
                "raw": raw,
                "normalized": target_dom,
                "type": "DOMAIN",
                "type_label": IOC_TYPES["DOMAIN"],
                "is_defanged": is_defanged,
                "is_private": is_priv_dom,
                "is_loopback": is_loop_dom,
                "valid": True,
                "port": int(port_c),
                "notes": note
            }

    # 9. Standard Domain Name (ASCII FQDN)
    if DOMAIN_REGEX.match(refanged) or refanged.lower().endswith((".local", ".internal", ".lan", ".localhost")):
        is_priv_dom, is_loop_dom, host_diag = check_host_internal_and_loopback(refanged)
        note = "Fully Qualified Domain Name (FQDN)."
        if is_loop_dom:
            note = "Localhost loopback domain name (RFC 6761). Non-routable on public threat feeds."
        elif is_priv_dom:
            note = f"Internal private domain ({host_diag})."
        return {
            "raw": raw,
            "normalized": refanged.lower(),
            "type": "DOMAIN",
            "type_label": IOC_TYPES["DOMAIN"],
            "is_defanged": is_defanged,
            "is_private": is_priv_dom,
            "is_loopback": is_loop_dom,
            "valid": True,
            "notes": note
        }

    # 9b. Internationalized Domain Names (IDN / Punycode)
    try:
        puny_candidate = refanged.encode("idna").decode("ascii")
        if DOMAIN_REGEX.match(puny_candidate) and puny_candidate != refanged:
            return {
                "raw": raw,
                "normalized": puny_candidate.lower(),
                "type": "DOMAIN",
                "type_label": IOC_TYPES["DOMAIN"],
                "is_defanged": is_defanged,
                "is_private": False,
                "is_loopback": False,
                "valid": True,
                "notes": f"Internationalized Domain Name (IDN: '{raw}') normalized to Punycode FQDN for reputation check."
            }
    except Exception:
        pass

    # 10. Fallback / Invalid
    return {
        "raw": raw,
        "normalized": refanged,
        "type": "UNKNOWN",
        "type_label": IOC_TYPES["UNKNOWN"],
        "is_defanged": is_defanged,
        "is_private": False,
        "is_loopback": False,
        "valid": False,
        "notes": "Input does not match recognized IPv4, IPv6, Hash (MD5/SHA1/SHA256), Domain, or URL formats."
    }

