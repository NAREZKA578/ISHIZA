"""netwatch probe library: low-level network checks, stdlib only.

Each function returns (value, error_kind, detail). error_kind is one of the
event kinds understood by the engine (dns_failure, timeout, refused, ...) or
None on success.
"""
import ipaddress
import os
import random
import socket
import ssl
import struct
import time
from typing import List, Optional, Tuple

# ---------------------------------------------------------------- helpers ---

def resolve(host: str, port: int = 0, timeout: float = 5.0) -> Tuple[List[str], Optional[str]]:
    """Resolve a hostname. Returns (sorted_ips, err_kind)."""
    try:
        if ipaddress.ip_address(host):
            return [str(host)], None
    except ValueError:
        pass
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos})
        if not ips:
            return [], "no_data"
        return ips, None
    except socket.gaierror as e:
        code = e.args[0] if e.args else None
        kind = {
            socket.EAI_NONAME: "nxdomain",
            socket.EAI_AGAIN: "servfail",
            getattr(socket, "EAI_NODATA", -5): "no_data",
        }.get(code, "dns_failure")
        return [], kind
    except Exception:
        return [], "dns_failure"
    finally:
        socket.setdefaulttimeout(old)


_DNS_ERR_KINDS = {2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def dns_query(name: str, server: str, qtype: str = "A", timeout: float = 3.0,
              do_tcp_fallback: bool = True) -> Tuple[Optional[float], List[str], Optional[str], str]:
    """Raw UDP DNS query against `server`. Returns (latency_ms, answers, err, rcode)."""
    qid = random.randint(0, 0xFFFF)
    flags = 0x0100  # RD
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    qtype_val = {"A": 1, "AAAA": 28, "TXT": 16, "MX": 15, "NS": 2, "SOA": 6}.get(qtype, 1)
    qname = b"".join(bytes([len(l)]) + l.encode("idna") for l in name.rstrip(".").split(".")) + b"\x00"
    query = header + qname + struct.pack(">HH", qtype_val, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.monotonic()
    rcode, answers, truncated = None, [], False
    try:
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(4096)
        latency = (time.monotonic() - start) * 1000.0
        if len(data) < 12:
            return None, [], "malformed", ""
        rid, rflags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        rcode = rflags & 0xF
        truncated = bool(rflags & 0x0400)
        if rid != qid:
            return None, [], "malformed", ""
        if rcode != 0:
            return latency, [], _DNS_ERR_KINDS.get(rcode, f"rcode{rcode}"), str(rcode)
        if truncated and do_tcp_fallback:
            return dns_tcp_query(name, server, qtype, timeout)
        # skip question
        pos = 12
        for _ in range(qd):
            while pos < len(data):
                ln = data[pos]
                if ln == 0:
                    pos += 1
                    break
                if ln & 0xC0:
                    pos += 2
                    break
                pos += 1 + ln
            pos += 4
        for _ in range(an):
            # name (may be compressed pointer)
            if pos < len(data) and data[pos] & 0xC0:
                pos += 2
            else:
                while pos < len(data) and data[pos] != 0:
                    ln = data[pos]
                    if ln & 0xC0:
                        pos += 1
                        break
                    pos += 1 + ln
                else:
                    pos += 1
            if pos + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlen]
            pos += rdlen
            if rtype == 1 and rdlen == 4:
                answers.append(socket.inet_ntoa(rdata))
            elif rtype == 28 and rdlen == 16:
                answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype in (5, 2):  # CNAME/NS domain
                answers.append(_decode_name(data, pos - rdlen))
            else:
                answers.append(rdata.decode("utf-8", "replace"))
        return latency, answers, None, "0"
    except socket.timeout:
        return None, [], "timeout", ""
    except OSError:
        return None, [], "unreachable", ""
    finally:
        sock.close()


def _decode_name(data: bytes, pos: int) -> str:
    parts, jumps = [], 0
    while pos < len(data) and jumps < 10:
        ln = data[pos]
        if ln == 0:
            break
        if ln & 0xC0:
            pos = struct.unpack(">H", data[pos:pos + 2])[0] & 0x3FFF
            jumps += 1
            continue
        parts.append(data[pos + 1:pos + 1 + ln].decode("utf-8", "replace"))
        pos += 1 + ln
    return ".".join(parts)


def dns_tcp_query(name: str, server: str, qtype: str = "A", timeout: float = 3.0):
    """Same as dns_query but over TCP (for truncated/large answers)."""
    qid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qtype_val = {"A": 1, "AAAA": 28}.get(qtype, 1)
    qname = b"".join(bytes([len(l)]) + l.encode("idna") for l in name.rstrip(".").split(".")) + b"\x00"
    query = header + qname + struct.pack(">HH", qtype_val, 1)
    try:
        with socket.create_connection((server, 53), timeout=timeout) as s:
            start = time.monotonic()
            s.sendall(struct.pack(">H", len(query)) + query)
            raw_len = s.recv(2)
            (rlen,) = struct.unpack(">H", raw_len)
            data = s.recv(rlen)
            latency = (time.monotonic() - start) * 1000.0
            rcode = struct.unpack(">H", data[2:4])[0] & 0xF if len(data) >= 4 else None
            if rcode:
                return latency, [], _DNS_ERR_KINDS.get(rcode, f"rcode{rcode}"), str(rcode)
            return latency, ["<tcp-answer>"], None, "0"
    except socket.timeout:
        return None, [], "timeout", ""
    except OSError:
        return None, [], "unreachable", ""


def tcp_probe(host: str, port: int, timeout: float, tls: bool = False,
              verify: bool = True, sni: Optional[str] = None,
              deadline_check=None) -> Tuple[Optional[float], Optional[str], dict]:
    """TCP connect (+ optional TLS handshake). Returns (rtt_ms, err, extra).

    RTT измеряется честным ICMP echo-запросом (raw socket, если доступен),
    иначе — временем TCP-handshake. TLS-рукопожатие в RTT не входит."""
    extra = {}
    ips, derr = resolve(host, port, timeout)
    if derr:
        return None, derr, extra
    # RTT до хоста не зависит от порта: сырой ICMP точнее TCP-handshake-оценки
    rtt_ms = None
    reps, _perr, got = raw_icmp_ping(ips[0], count=1, timeout=min(timeout, 2.0))
    if got:
        rtt_ms = reps[0][1]
    if derr:
        return None, derr, extra
    ip = ips[0]
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except socket.timeout:
        return None, "timeout", extra
    except ConnectionRefusedError:
        return None, "refused", extra
    except PermissionError:
        return None, "perm", extra
    except socket.gaierror:
        return None, "dns_failure", extra
    except OSError as e:
        en = getattr(e, "errno", None)
        if en in (101, 113):   # ENETUNREACH / EHOSTUNREACH
            return None, "net_unreach", extra
        if en == 115:          # EINPROGRESS-style timeout
            return None, "timeout", extra
        if en == 110:
            return None, "timeout", extra
        if en == 104:          # ECONNRESET mid-connect
            return None, "reset", extra
        return None, "connect_error", extra
    if rtt_ms is None:
        t0 = time.monotonic()
        try:
            s2 = socket.create_connection((ip, port), timeout=0.5)
            s2.close()
        except OSError:
            pass
        rtt_ms = (time.monotonic() - t0) * 1000.0
    try:
        # TLS-рукопожатие (в RTT не входит)
        if tls:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            t1 = time.monotonic()
            try:
                ss = ctx.wrap_socket(sock, server_hostname=sni or host)
                tls_ms = (time.monotonic() - t1) * 1000.0
                cert = ss.getpeercert()
                extra["tls"] = ss.version()
                extra["tls_ms"] = round(tls_ms, 2)
                if cert and verify:
                    not_after = cert.get("notAfter")
                    if not_after:
                        exp = time.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days = (time.mktime(exp) - time.time()) / 86400.0
                        extra["cert_days_left"] = round(days, 1)
                        cipher = ss.cipher()
                        if cipher:
                            extra["cipher"] = cipher[0]
                sock = ss
            except ssl.SSLCertVerificationError as e:
                msg = str(e)
                if "certificate has expired" in msg or "expired" in msg.lower():
                    return rtt_ms, "cert_expired", extra
                if "hostname mismatch" in msg.lower():
                    return rtt_ms, "cert_cn_mismatch", extra
                return rtt_ms, "cert_verify", extra
            except ssl.SSLError as e:
                em = str(e).lower()
                if "handshake" in em or "alert" in em:
                    return rtt_ms, "tls_handshake", extra
                return rtt_ms, "tls_error", extra
            except socket.timeout:
                return rtt_ms, "timeout", extra
        return rtt_ms, None, extra
    finally:
        try:
            sock.close()
        except OSError:
            pass


class NetworkDown(OSError):
    pass


def http_probe(url: str, timeout: float, method: str = "GET",
               expect_status: Optional[int] = None, max_redirects: int = 5,
               headers: Optional[dict] = None, body: Optional[str] = None,
               verify: bool = True) -> Tuple[Optional[float], Optional[int], Optional[str], dict]:
    """HTTP(S) request without external deps. Returns (ttfb_ms, status, err, extra)."""
    import urllib.error
    import urllib.request
    extra = {}
    ctx = None
    if url.startswith("https"):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method, data=body.encode() if body else None,
                                 headers=headers or {"User-Agent": "netwatch/2"})
    t0 = time.monotonic()
    try:
        opener = urllib.request.build_opener()
        if ctx:
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        resp = opener.open(req, timeout=timeout)
        ttfb = (time.monotonic() - t0) * 1000.0
        status = resp.status
        extra["redirects"] = len(resp.url and [u for u in [resp.geturl()] if u != url] or [])
        final_url = resp.geturl()
        if final_url != url:
            extra["redirected_to"] = final_url
        resp.read(2048)
        resp.close()
    except urllib.error.HTTPError as e:
        ttfb = (time.monotonic() - t0) * 1000.0
        status = e.code
    except urllib.error.URLError as e:
        ttfb = (time.monotonic() - t0) * 1000.0
        reason = e.reason
        if isinstance(reason, socket.timeout):
            return ttfb, None, "timeout", extra
        if isinstance(reason, ssl.SSLCertVerificationError):
            msg = str(reason).lower()
            if "expired" in msg:
                return ttfb, None, "cert_expired", extra
            if "hostname mismatch" in msg:
                return ttfb, None, "cert_cn_mismatch", extra
            return ttfb, None, "cert_verify", extra
        if isinstance(reason, ssl.SSLError):
            return ttfb, None, "tls_handshake", extra
        if isinstance(reason, socket.gaierror):
            code = reason.args[0] if reason.args else None
            kind = {getattr(socket, "EAI_NONAME", -2): "nxdomain",
                    getattr(socket, "EAI_AGAIN", -3): "servfail"}.get(code, "dns_failure")
            return ttfb, None, kind, extra
        if isinstance(reason, ConnectionRefusedError):
            return ttfb, None, "refused", extra
        if isinstance(reason, OSError) and getattr(reason, "errno", None) in (101, 113, 100):
            return ttfb, None, "net_unreach", extra
        return ttfb, None, "http_error", extra
    except socket.timeout:
        return (time.monotonic() - t0) * 1000.0, None, "timeout", extra
    except OSError:
        return (time.monotonic() - t0) * 1000.0, None, "net_errors", extra
    if expect_status is not None and status != expect_status:
        return ttfb, status, "unexpected_status", extra
    if status and status >= 500:
        return ttfb, status, "http_5xx", extra
    return ttfb, status, None, extra


def udp_echo_probe(host: str, port: int, timeout: float,
                   payload: bytes = b"netwatch-probe") -> Tuple[Optional[float], Optional[str]]:
    """Send datagram, wait for any reply (best-effort; many hosts drop silently)."""
    ips, derr = resolve(host, port, timeout)
    if derr:
        return None, derr
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t0 = time.monotonic()
        sock.sendto(payload, (ips[0], port))
        try:
            sock.recvfrom(1024)
            return (time.monotonic() - t0) * 1000.0, None
        except socket.timeout:
            return None, "udp_no_reply"
        except ConnectionRefusedError:
            # ICMP port unreachable -> host reachable, port closed (that's fine)
            return (time.monotonic() - t0) * 1000.0, None
    except OSError as e:
        if getattr(e, "errno", None) in (101, 113):
            return None, "net_unreach"
        return None, "send_failed"
    finally:
        sock.close()


def ntp_probe(server: str, timeout: float) -> Tuple[Optional[float], Optional[float], Optional[str]]:
    """SNMP-free NTP mode-3 query. Returns (rtt_ms, clock_offset_s, err)."""
    ips, derr = resolve(server, 123, timeout)
    if derr:
        return None, None, derr
    packet = bytearray(48)
    packet[0] = 0x1B  # LI=0 VN=3 Mode=3
    # transmit timestamp at bytes 40-47 (NTP epoch 1900)
    ntp_t = time.time() + 2208988800
    frac = (ntp_t % 1) * (2 ** 32)
    packet[40:44] = struct.pack(">I", int(ntp_t) & 0xFFFFFFFF)
    packet[44:48] = struct.pack(">I", int(frac) & 0xFFFFFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t0 = time.monotonic()
        sock.sendto(bytes(packet), (ips[0], 123))
        data = sock.recv(48)
        rtt = (time.monotonic() - t0) * 1000.0
        if len(data) < 48:
            return rtt, None, "malformed"
        stratum = data[1]
        if stratum == 0:
            return rtt, None, "koog_stratum0"
        recv_s, recv_f = struct.unpack(">II", data[32:40])
        server_time = recv_s + recv_f / 2 ** 32 - 2208988800
        offset = server_time - (time.time() + rtt / 2000.0)
        return rtt, offset, None
    except socket.timeout:
        return None, None, "timeout"
    except OSError:
        return None, None, "net_unreach"
    finally:
        sock.close()


_RAW_PING_ID = random.randint(0, 0xFFFF)


def raw_icmp_ping(host: str, count: int = 1, timeout: float = 2.0, size: int = 56,
                  df: bool = False, ttl: Optional[int] = None) -> Tuple[List[Tuple[int, float]], Optional[str], int]:
    """ICMP echo via raw socket (needs root). Returns [(seq, rtt_ms)], err, received."""
    ips, derr = resolve(host, 0, timeout)
    if derr:
        return [], derr, 0
    dest = ips[0]
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return [], "raw_not_allowed", 0
    except OSError:
        return [], "raw_not_allowed", 0
    sock.settimeout(timeout)
    if ttl is not None:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        except OSError:
            pass
    if df and hasattr(socket, "IP_MTU_DISCOVER"):
        try:
            PMTU_DISCOVER = 2  # IP_PMTUDISC_DO
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, PMTU_DISCOVER)
        except OSError:
            pass
    replies = []
    sent = 0
    try:
        for seq in range(count):
            pkt = _icmp_packet(_RAW_PING_ID, seq, size)
            try:
                t0 = time.monotonic()
                sock.sendto(pkt, (dest, 0))
                sent += 1
                data = sock.recv(2048)
                rtt = (time.monotonic() - t0) * 1000.0
                icmp = data[20:] if len(data) > 20 else data
                if len(icmp) >= 8 and icmp[0] == 0 and struct.unpack(">H", icmp[4:6])[0] == _RAW_PING_ID:
                    rseq = struct.unpack(">H", icmp[6:8])[0]
                    replies.append((rseq, rtt))
            except socket.timeout:
                continue
            except OSError as e:
                en = getattr(e, "errno", None)
                if en in (101, 113):
                    return replies, "net_unreach", len(replies)
                if en == 90:  # EMSGSIZE from DF probe
                    return replies, "msg_too_big", len(replies)
                continue
        return replies, None, len(replies)
    finally:
        sock.close()


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _icmp_packet(pid: int, seq: int, size: int) -> bytes:
    payload = bytes(((i * 7 + 13) % 251 for i in range(size)))
    header = struct.pack(">BBHHH", 8, 0, 0, pid, seq)
    chk = _icmp_checksum(header + payload)
    return struct.pack(">BBHHH", 8, 0, chk, pid, seq) + payload


def pmtud_probe(host: str, sizes: List[int], timeout: float = 2.0) -> Tuple[Optional[int], Optional[str]]:
    """Binary-ish path MTU discovery via DF-flagged ICMP pings (root). Returns (mtu, err)."""
    last_err = None
    for size in sizes:
        reps, err, got = raw_icmp_ping(host, count=1, timeout=timeout, size=size, df=True)
        if err:
            last_err = err
        if got:
            return size + 28, None  # IP(20)+ICMP(8) headers
        if err == "msg_too_big":
            return None, "frag_needed_at_%d" % size
    return None, last_err or "no_response"


def traceroute(host: str, max_hops: int = 20, timeout: float = 2.0,
               queries_per_hop: int = 3) -> Tuple[List[dict], Optional[str]]:
    """UDP-TTL-expiry traceroute using raw sockets (root). Best effort."""
    ips, derr = resolve(host, 0, timeout)
    if derr:
        return [], derr
    dest = ips[0]
    try:
        send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv.settimeout(timeout)
    except OSError:
        return [], "raw_not_allowed"
    hops, reached = [], False
    base_port = 33434
    try:
        for hop in range(1, max_hops + 1):
            rtts = []
            for q in range(queries_per_hop):
                port = base_port + hop
                addr = (dest, port)
                try:
                    send.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, hop)
                    t0 = time.monotonic()
                    send.sendto(b"\x4e" * 12, addr)
                    data = recv.recvfrom(2048)[0]
                    rtt = (time.monotonic() - t0) * 1000.0
                    icmp = data[20:]
                    itype = icmp[0] if icmp else None
                    if itype == 11:  # TTL exceeded
                        inner_src = socket.inet_ntoa(data[28:32]) if len(data) >= 32 else "?"
                        rtts.append((inner_src, rtt))
                    elif itype == 3:  # dest unreachable -> arrived
                        rtts.append((dest, rtt))
                        reached = True
                except socket.timeout:
                    continue
                except OSError:
                    continue
            addrs = sorted({a for a, _ in rtts})
            avg = round(sum(r for _, r in rtts) / len(rtts), 2) if rtts else None
            hops.append({"hop": hop, "addrs": addrs, "avg_ms": avg, "replies": len(rtts)})
            if reached:
                break
        return hops, None
    finally:
        send.close()
        recv.close()


def mtu_discovery_scan(host: str, timeout: float = 2.0) -> Tuple[Optional[int], Optional[str]]:
    sizes = list(range(1472, 512, -64))
    return pmtud_probe(host, sizes, timeout)


def captive_portal_detect(timeout: float = 3.0) -> Tuple[bool, str]:
    """Query a known-hotspot DNS name; an answer usually means we're behind a portal."""
    lat, answers, err, _ = dns_query("www.msftconnecttest.com", "1.1.1.1", "A", timeout)
    if err == "nxdomain":
        return False, "clean"
    if err:
        return False, "check_failed:" + err
    return True, ",".join(a for a in answers if a[0].isdigit()) or "answered"


def connectivity_check(timeout: float = 3.0) -> Tuple[bool, str]:
    """Is there internet at all? DNS test first, then HTTP fallback."""
    lat, answers, err, _ = dns_query("example.com", "1.1.1.1", "A", timeout)
    if not err and answers:
        return True, "dns_ok"
    ms, status, herr, _ = http_probe("http://example.com", timeout)
    if status:
        return True, "http_ok"
    return False, herr or "no_internet"


def tcp_rtt(host: str, port: int, timeout: float, samples: int = 3) -> Tuple[Optional[float], Optional[str]]:
    """Estimate RTT by timing repeated TCP handshakes (SYN->SYN/ACK->RST)."""
    vals = []
    err = None
    for _ in range(samples):
        ms, e, _ = tcp_probe(host, port, timeout)
        if e:
            err = e
            break
        if ms is not None:
            vals.append(ms)
    if not vals:
        return None, err or "no_samples"
    return sum(vals) / len(vals), None
