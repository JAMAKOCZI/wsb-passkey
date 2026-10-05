"""
WSB Passkey - logowanie do MeritoGo (WSB Merito) "pendrivem".

Jak to działa:
  1. Uruchamiasz WSBPasskey.exe z pendrive'a (jedno kliknięcie).
  2. Program kopiuje się do %TEMP% (żeby wyjęcie pendrive'a go nie zabiło),
     pyta o PIN, odszyfrowuje login/hasło zapisane na pendrivie.
  3. Odpala Edge/Chrome z NOWYM, tymczasowym profilem i loguje Cię na meritogo.pl.
  4. Co pół sekundy sprawdza, czy pendrive nadal jest w porcie.
     Gdy go wyjmiesz: wylogowanie z CAS (login.wsb.pl), zamknięcie przeglądarki,
     skasowanie tymczasowego profilu (ciasteczka, historia, sesje) i koniec.

Dane logowania są szyfrowane AES-256-GCM kluczem wyprowadzonym z PIN-u (scrypt).
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import glob
import json
import logging
import os
import queue
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

import tkinter as tk
from tkinter import messagebox

import websocket  # websocket-client
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Zapewnienie, że lokalna komunikacja z DevTools (127.0.0.1) omija uczelniany serwer proxy
os.environ["NO_PROXY"] = "127.0.0.1,localhost," + os.environ.get("NO_PROXY", "")

# --------------------------------------------------------------------------- #
# Konfiguracja
# --------------------------------------------------------------------------- #
APP_NAME = "WSB Passkey"
START_URL = "https://meritogo.pl/"
LOGOUT_URLS = [
    "https://login.wsb.pl/cas/logout",                 # sesja SSO uczelni (CAS)
    "https://login.microsoftonline.com/logout.srf",    # sesja Microsoft
]
CONFIG_NAME = "wsb_passkey.dat"
PROFILE_PREFIX = "wsbpk_profile_"
TEMP_EXE_PREFIX = "wsbpk_run_"
MIN_PIN_LEN = 6
PIN_ATTEMPTS = 3
LOGIN_TIMEOUT_S = 120
POLL_MS = 500

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**17, 8, 1
AAD = b"wsb-passkey-v1"

CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200

log = logging.getLogger("wsbpk")


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def app_dir() -> str:
    """Folder, w którym leży exe / skrypt (czyli pendrive)."""
    target = sys.executable if is_frozen() else __file__
    return os.path.dirname(os.path.abspath(target))


# --------------------------------------------------------------------------- #
# Szyfrowanie danych logowania
# --------------------------------------------------------------------------- #
def _derive_key(pin: str, salt: bytes, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(pin.encode("utf-8"))


def save_credentials(path: str, username: str, password: str, pin: str) -> None:
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = _derive_key(pin, salt)
    plain = json.dumps({"username": username, "password": password}).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, plain, AAD)
    blob = {
        "v": 1,
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(blob, f)
    os.replace(tmp, path)


def load_credentials(path: str, pin: str) -> dict | None:
    """Zwraca {'username','password'} albo None przy złym PIN-ie."""
    with open(path, "r", encoding="utf-8") as f:
        blob = json.load(f)
    kdf = blob["kdf"]
    key = _derive_key(pin, base64.b64decode(blob["salt"]), kdf["n"], kdf["r"], kdf["p"])
    try:
        plain = AESGCM(key).decrypt(base64.b64decode(blob["nonce"]), base64.b64decode(blob["ct"]), AAD)
    except InvalidTag:
        return None
    return json.loads(plain)


# --------------------------------------------------------------------------- #
# Bezpieczeństwo systemu Windows: Volume Serial & Job Object
# --------------------------------------------------------------------------- #
def get_volume_serial(path: str) -> int | None:
    """Odczytuje unikalny numer seryjny woluminu nośnika USB (wykrywa podmianę pendrive'a)."""
    try:
        drive = os.path.splitdrive(os.path.abspath(path))[0]
        if not drive:
            return None
        root = drive + ("\\" if not drive.endswith("\\") else "")
        serial = ctypes.c_ulong()
        res = ctypes.windll.kernel32.GetVolumeInformationW(
            root, None, 0, ctypes.byref(serial), None, None, None, 0
        )
        return serial.value if res else None
    except Exception:
        return None


def create_kill_on_close_job():
    """Tworzy Windows Job Object, który automatycznie zabija wszystkie procesy potomne przeglądarki."""
    try:
        kernel32 = ctypes.windll.kernel32
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryLimit", ctypes.c_size_t),
                ("PeakJobMemoryLimit", ctypes.c_size_t),
            ]

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            kernel32.CloseHandle(job)
            return None
        return job
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Minimalny klient Chrome DevTools Protocol (działa z Edge i Chrome)
# --------------------------------------------------------------------------- #
class CDPError(Exception):
    pass


class CDP:
    def __init__(self, ws_url: str, timeout: float = 10):
        self.ws = websocket.create_connection(ws_url, timeout=timeout, suppress_origin=True)
        self._lock = threading.Lock()
        self._id = 0

    def call(self, method: str, params: dict | None = None, timeout: float = 10) -> dict:
        with self._lock:
            self._id += 1
            mid = self._id
            self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
            deadline = time.time() + timeout
            while True:
                left = deadline - time.time()
                if left <= 0:
                    raise CDPError(f"timeout: {method}")
                self.ws.settimeout(left)
                msg = json.loads(self.ws.recv())
                if msg.get("id") == mid:
                    if "error" in msg:
                        raise CDPError(str(msg["error"]))
                    return msg.get("result", {})

    def eval(self, expression: str, timeout: float = 5):
        res = self.call(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": True},
            timeout,
        )
        if "exceptionDetails" in res:
            raise CDPError(str(res["exceptionDetails"].get("text")))
        return res.get("result", {}).get("value")

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:
            pass


def http_json(url: str, timeout: float = 2):
    req = urllib.request.Request(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


# --------------------------------------------------------------------------- #
# Przeglądarka
# --------------------------------------------------------------------------- #
def _app_path_from_registry(exe_name: str) -> str | None:
    try:
        import winreg
    except ImportError:
        return None
    sub = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, sub) as k:
                val, _ = winreg.QueryValueEx(k, None)
                if val and os.path.isfile(val):
                    return val
        except OSError:
            pass
    return None


def find_browsers(preferred: str | None = None) -> list[tuple[str, str]]:
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    la = os.environ.get("LOCALAPPDATA", "")
    known = {
        "edge": ("msedge.exe", [
            os.path.join(pf86, r"Microsoft\Edge\Application\msedge.exe"),
            os.path.join(pf, r"Microsoft\Edge\Application\msedge.exe"),
        ]),
        "chrome": ("chrome.exe", [
            os.path.join(pf, r"Google\Chrome\Application\chrome.exe"),
            os.path.join(pf86, r"Google\Chrome\Application\chrome.exe"),
            os.path.join(la, r"Google\Chrome\Application\chrome.exe"),
        ]),
    }
    order = ["edge", "chrome"]
    if preferred in known:
        order.remove(preferred)
        order.insert(0, preferred)
    found = []
    for name in order:
        exe_name, paths = known[name]
        path = _app_path_from_registry(exe_name) or next((p for p in paths if os.path.isfile(p)), None)
        if path:
            found.append((name, path))
    return found


class Browser:
    """Edge/Chrome uruchomiony z tymczasowym profilem i portem DevTools."""

    def __init__(self, name: str, exe: str, headless: bool = False):
        self.name, self.exe = name, exe
        self.profile = tempfile.mkdtemp(prefix=PROFILE_PREFIX)
        self.job = create_kill_on_close_job()
        self._write_prefs()
        args = [
            exe,
            f"--user-data-dir={self.profile}",
            "--remote-debugging-port=0",
            "--remote-debugging-address=127.0.0.1",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-sync",
            "--disable-features=Translate,msEdgeSignInPromo,msImplicitSignin",
            "--password-store=basic",
            "--disable-background-networking",
            "--disable-client-side-phishing-detection",
            "--disable-default-apps",
            "--disable-breakpad",
            "--disable-blink-features=AutomationControlled",
            "--no-pings",
            "--start-maximized",
        ]
        if headless:
            args.append("--headless=new")
        args.append(START_URL)
        log.info("Uruchamiam %s", name)
        self.proc = subprocess.Popen(args, close_fds=True)
        if self.job and hasattr(self.proc, "_handle"):
            try:
                ctypes.windll.kernel32.AssignProcessToJobObject(self.job, int(self.proc._handle))
            except Exception as e:
                log.warning("Job assign: %s", e)
        self.port, self.browser_ws_path = self._wait_devtools()

    def _write_prefs(self) -> None:
        # Bez pytań "zapisać hasło?" i bez powitań - profil i tak zostanie skasowany.
        d = os.path.join(self.profile, "Default")
        os.makedirs(d, exist_ok=True)
        prefs = {
            "credentials_enable_service": False,
            "profile": {"password_manager_enabled": False, "exit_type": "Normal"},
            "autofill": {"profile_enabled": False, "credit_card_enabled": False},
            "browser": {"has_seen_welcome_page": True},
            "translate": {"enabled": False},
        }
        with open(os.path.join(d, "Preferences"), "w", encoding="utf-8") as f:
            json.dump(prefs, f)

    def _wait_devtools(self, timeout: float = 20) -> tuple[int, str]:
        path = os.path.join(self.profile, "DevToolsActivePort")
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = f.read().split()
                if len(lines) >= 2:
                    return int(lines[0]), lines[1]
            except (OSError, ValueError):
                pass
            time.sleep(0.2)
        raise RuntimeError(f"{self.name}: brak portu DevTools (może zablokowany polityką uczelni)")

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def alive(self, timeout: float = 1.5) -> bool:
        try:
            http_json(self.base + "/json/version", timeout=timeout)
            return True
        except Exception:
            return False

    def page_ws(self, timeout: float = 15) -> str:
        """websocket strony z meritogo (albo pierwszej karty)."""
        deadline = time.time() + timeout
        fallback = None
        while time.time() < deadline:
            try:
                pages = [t for t in http_json(self.base + "/json/list") if t.get("type") == "page"]
            except Exception:
                pages = []
            for t in pages:
                if "meritogo" in t.get("url", "") or "wsb.pl" in t.get("url", ""):
                    return t["webSocketDebuggerUrl"]
            if pages:
                fallback = pages[0]["webSocketDebuggerUrl"]
            time.sleep(0.3)
        if fallback:
            return fallback
        raise RuntimeError("Nie znaleziono karty przeglądarki")

    def logout_and_close(self) -> None:
        t0 = time.time()
        bcdp = None
        try:
            bcdp = CDP(f"ws://127.0.0.1:{self.port}{self.browser_ws_path}", timeout=2)
        except Exception as e:
            log.warning("browser ws: %s", e)
        # 1) wylogowanie (CAS + Microsoft) równolegle w nowych kartach -
        #    unieważnia sesje po stronie serwera, nie tylko lokalne ciasteczka
        if bcdp:
            opened = 0
            for url in LOGOUT_URLS:
                try:
                    bcdp.call("Target.createTarget", {"url": url}, timeout=2)
                    opened += 1
                except Exception as e:
                    log.warning("logout %s: %s", url, e)
            if opened:
                time.sleep(1.5)
        # 2) zamknięcie przeglądarki przez CDP
        if bcdp:
            try:
                bcdp.call("Browser.close", timeout=2)
            except Exception:
                pass
            bcdp.close()
        for _ in range(20):
            if not self.alive(timeout=0.2):
                break
            time.sleep(0.1)
        # 3) natychmiastowe ubicie całego drzewa procesów przez Job Object
        if self.job:
            try:
                ctypes.windll.kernel32.TerminateJobObject(self.job, 0)
                ctypes.windll.kernel32.CloseHandle(self.job)
            except Exception:
                pass
            self.job = None
        elif self.proc.poll() is None or self.alive(timeout=0.2):
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(self.proc.pid)],
                           capture_output=True, creationflags=CREATE_NO_WINDOW)
        # 4) skasowanie profilu (ciasteczka, cache, historia)
        for _ in range(25):
            shutil.rmtree(self.profile, ignore_errors=True)
            if not os.path.exists(self.profile):
                break
            time.sleep(0.15)
        log.info("Przeglądarka zamknięta w %.1fs, profil usunięty: %s",
                 time.time() - t0, not os.path.exists(self.profile))


def launch_browser(preferred: str | None, headless: bool) -> Browser:
    errors = []
    for name, exe in find_browsers(preferred):
        try:
            return Browser(name, exe, headless=headless)
        except Exception as e:
            log.warning("%s nie wystartował: %s", name, e)
            errors.append(str(e))
    raise RuntimeError("Nie udało się uruchomić Edge ani Chrome.\n" + "\n".join(errors))


# --------------------------------------------------------------------------- #
# Automatyczne logowanie
# --------------------------------------------------------------------------- #
DETECT_JS = r"""
(() => {
  const vis = el => {
    if (!el || el.disabled) return false;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || +cs.opacity === 0) return false;
    if (el.closest('.moveOffScreen, [aria-hidden=true]')) return false;
    const rc = el.getBoundingClientRect();
    return rc.width > 1 && rc.height > 1 && rc.right > 0 && rc.bottom > 0
           && rc.left < innerWidth && rc.top < innerHeight + 2000;
  };
  const q = s => document.querySelector(s);
  const txt = el => el ? (el.innerText || el.value || '').trim() : '';
  const host = location.hostname;
  const r = {host, state: 'other', error: ''};
  if (document.readyState === 'loading') { r.state = 'loading'; return r; }

  // CAS: login.wsb.pl - stary formularz login/hasło
  const cu = q('input#username'), cp = q('input#password');
  if (vis(cu) && vis(cp)) {
    r.state = 'cas';
    const e = [...document.querySelectorAll(
      '#loginErrorsPanel, .alert-danger, .banner-danger, .mdc-snackbar, [role=alert], .error')]
      .find(el => vis(el) && txt(el));
    r.error = e ? txt(e) : '';
    return r;
  }
  // CAS: login.wsb.pl - przycisk "Przejdź do logowania Microsoft" (SAML2)
  if (/(^|\.)wsb\.pl$/.test(host) && vis(q('a[href*="clientredirect"]'))) {
    r.state = 'cas_ms'; return r;
  }

  // Microsoft (Entra ID) - klasyczny i nowy (Fluent) wygląd
  if (/(^|\.)(login\.microsoftonline\.com|login\.live\.com|login\.microsoft\.com)$/.test(host)) {
    const u = q('input[name=loginfmt]'), p = q('input[name=passwd]');
    const errOf = sel => { const e = [...document.querySelectorAll(sel)].find(el => vis(el) && txt(el)); return e ? txt(e) : ''; };
    if (vis(p)) { r.state = 'ms_pass'; r.error = errOf('#passwordError, [data-testid=passwordError]'); return r; }
    if (vis(u)) { r.state = 'ms_user'; r.error = errOf('#usernameError, [data-testid=usernameError]'); return r; }
    const body = (document.body.innerText || '').slice(0, 3000);
    if (vis(q('#KmsiCheckboxField')) || vis(q('#KmsiDescription'))
        || (vis(q('#idBtn_Back')) && vis(q('#idSIButton9')))
        || (/stay signed in|nie wylogowywa|pozosta. zalogowan/i.test(body)
            && vis(q('button[data-testid=secondaryButton], #idBtn_Back')))) { r.state = 'ms_kmsi'; return r; }
    if (vis(q('#tilesHolder')) || vis(q('[data-test-id=tilesHolder]'))) { r.state = 'ms_picker'; return r; }
    if (/approve sign in|zatwierd. logowanie|verify your identity|zweryfikuj swoj. to.samo|enter code|wprowad. kod/i.test(body)) {
      r.state = 'ms_mfa'; return r;
    }
    r.state = 'ms_other'; return r;
  }

  // MeritoGo
  if (/(^|\.)meritogo\.pl$/.test(host)) {
    r.state = window.__wsbpkFindLogin && window.__wsbpkFindLogin() ? 'merito_login' : 'merito';
    return r;
  }
  return r;
})()
"""

# Szuka na meritogo.pl przycisku/linku "Zaloguj".
MERITO_HELPER_JS = r"""
window.__wsbpkFindLogin = () => {
  const vis = el => !!el && !el.disabled && el.getClientRects().length > 0
                    && getComputedStyle(el).visibility !== 'hidden';
  const re = /^(zaloguj( się)?( przez .*)?|log ?in( with .*)?|sign ?in( with .*)?)$/i;
  return [...document.querySelectorAll('button, a, [role=button], .v-btn')]
    .filter(vis).find(el => re.test((el.innerText || '').trim().replace(/\s+/g, ' ')));
};
"""


class LoginBot(threading.Thread):
    """Wypełnia formularze CAS / Microsoft na karcie MeritoGo."""

    def __init__(self, browser: Browser, creds: dict, status_q: queue.Queue, stop: threading.Event):
        super().__init__(daemon=True)
        self.b, self.creds, self.q, self.stop = browser, creds, status_q, stop
        self.cdp: CDP | None = None

    def status(self, kind: str, text: str) -> None:
        self.q.put((kind, text))

    def _wipe_creds(self) -> None:
        """Bezpieczne czyszczenie haseł z pamięci RAM."""
        if hasattr(self, "creds") and isinstance(self.creds, dict):
            for k in list(self.creds.keys()):
                self.creds[k] = ""
            self.creds.clear()

    # --- akcje na stronie ---
    def _fill(self, selector: str, value: str) -> None:
        ok = self.cdp.eval(
            f"(() => {{ const el = document.querySelector({json.dumps(selector)});"
            f" if (!el) return false; el.focus(); el.select(); return true; }})()"
        )
        if not ok:
            raise CDPError(f"brak pola {selector}")
        self.cdp.call("Input.insertText", {"text": value})
        # na wszelki wypadek (gdyby insertText nie wywołał zdarzeń frameworka)
        self.cdp.eval(
            f"(() => {{ const el = document.querySelector({json.dumps(selector)});"
            f" if (el.value !== {json.dumps(value)}) {{ el.value = {json.dumps(value)}; }}"
            f" el.dispatchEvent(new Event('input', {{bubbles:true}}));"
            f" el.dispatchEvent(new Event('change', {{bubbles:true}})); }})()"
        )

    def _click(self, selector: str) -> None:
        self.cdp.eval(
            f"(() => {{ const el = document.querySelector({json.dumps(selector)}); if (el) el.click(); }})()"
        )

    # --- główna pętla ---
    def run(self) -> None:
        try:
            self.cdp = CDP(self.b.page_ws())
            self._loop()
        except Exception as e:
            log.exception("LoginBot")
            if not self.stop.is_set():
                self.status("error", f"Automatyczne logowanie nie powiodło się: {e}\nZaloguj się ręcznie.")
        finally:
            if self.cdp:
                self.cdp.close()
            self._wipe_creds()

    def _loop(self) -> None:
        user, pwd = self.creds["username"], self.creds["password"]
        deadline = time.time() + LOGIN_TIMEOUT_S
        last_action: dict[str, float] = {}
        submits = {"cas": 0, "ms_pass": 0}
        submitted = False
        merito_since = None
        first_merito = None
        last_state = None

        self.status("info", "Loguję do MeritoGo…")
        while not self.stop.is_set() and time.time() < deadline:
            time.sleep(0.5)
            try:
                self.cdp.eval(MERITO_HELPER_JS)
                st = self.cdp.eval(DETECT_JS) or {}
            except (CDPError, websocket.WebSocketException) as e:
                # nawigacja w toku / zamknięta karta - spróbuj ponownie
                if isinstance(e, websocket.WebSocketException):
                    self.cdp.close()
                    self.cdp = CDP(self.b.page_ws())
                continue

            state = st.get("state")
            if state != last_state:
                log.info("stan: %s (%s)", state, st.get("host"))
                last_state = state
            now = time.time()
            can_act = now - last_action.get(state, 0) > 4  # nie klikaj w kółko tego samego

            if st.get("error") and state in ("cas", "ms_user", "ms_pass") and state in last_action:
                self.status("error", f"Logowanie odrzucone:\n{st['error']}\n\n"
                                     "Popraw dane (opcja 'Zmień dane…' przy PIN-ie).")
                return

            ms_submit = "#idSIButton9, button[data-testid=primaryButton], input[type=submit], button[type=submit]"

            if state == "cas_ms" and can_act:
                self._click('a[href*="clientredirect"]')  # "Przejdź do logowania Microsoft"
                last_action[state] = now

            elif state == "cas" and can_act:
                if submits["cas"] >= 2:
                    self.status("error", "CAS ponownie prosi o hasło - przerwano, żeby nie zablokować konta.")
                    return
                self._fill("#username", user)
                self._fill("#password", pwd)
                self._click("#submitButtonPL, form#wf-form-Logowanie button[type=submit]")
                submits["cas"] += 1
                submitted = True
                last_action[state] = now
                self.status("info", "Wysłano login i hasło…")

            elif state == "ms_user" and can_act:
                self._fill("input[name=loginfmt]", user)
                self._click(ms_submit)
                last_action[state] = now

            elif state == "ms_pass" and can_act:
                if submits["ms_pass"] >= 2:
                    self.status("error", "Microsoft ponownie prosi o hasło - przerwano, żeby nie zablokować konta.")
                    return
                self._fill("input[name=passwd]", pwd)
                self._click(ms_submit)
                submits["ms_pass"] += 1
                submitted = True
                last_action[state] = now
                self.status("info", "Wysłano hasło do Microsoft…")

            elif state == "ms_kmsi" and can_act:
                # "Nie" - nie zapamiętuj logowania na tym komputerze
                self._click("#idBtn_Back, button[data-testid=secondaryButton]")
                last_action[state] = now

            elif state == "ms_mfa" and can_act:
                self.status("info", "Microsoft prosi o dodatkową weryfikację (MFA) - potwierdź ją ręcznie.")
                last_action[state] = now
                deadline = max(deadline, now + 90)

            elif state == "ms_picker" and can_act:
                clicked = self.cdp.eval(
                    "(() => { const u = %s.toLowerCase();"
                    " const t = [...document.querySelectorAll('#tilesHolder [role=button], #tilesHolder .table, [data-test-id]')]"
                    "  .find(el => (el.innerText||'').toLowerCase().includes(u));"
                    " if (t) { t.click(); return true; }"
                    " const o = document.querySelector('#otherTile'); if (o) { o.click(); return true; } return false; })()"
                    % json.dumps(user)
                )
                log.info("picker click: %s", clicked)
                last_action[state] = now

            elif state == "merito_login" and can_act:
                self.cdp.eval("(() => { const el = window.__wsbpkFindLogin(); if (el) el.click(); })()")
                last_action[state] = now

            if state == "merito":
                first_merito = first_merito or now
                merito_since = merito_since or now
                if submitted and now - merito_since > 2:
                    self.status("ok", "Zalogowano. Wyjmij pendrive, aby się wylogować.")
                    return
                if not submitted and now - first_merito > 25:
                    self.status("error", "Nie znalazłem przycisku logowania na MeritoGo - zaloguj się ręcznie.")
                    return
            else:
                merito_since = None

        if not self.stop.is_set():
            self.status("error", "Przekroczono czas logowania - dokończ ręcznie w przeglądarce.")


# --------------------------------------------------------------------------- #
# Okienka
# --------------------------------------------------------------------------- #
def _center(win: tk.Misc) -> None:
    win.update_idletasks()
    w, h = win.winfo_width(), win.winfo_height()
    x = (win.winfo_screenwidth() - w) // 2
    y = (win.winfo_screenheight() - h) // 3
    win.geometry(f"+{x}+{y}")


def form_dialog(root: tk.Tk, title: str, intro: str, fields: list[tuple[str, str, bool]],
                extra_button: tuple[str, str] | None = None) -> dict | None:
    result: dict = {}
    win = tk.Toplevel(root)
    win.title(title)
    win.resizable(False, False)
    win.attributes("-topmost", True)
    frm = tk.Frame(win, padx=18, pady=14)
    frm.pack()
    if intro:
        tk.Label(frm, text=intro, justify="left", wraplength=380).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
    entries = {}
    for i, (key, label, secret) in enumerate(fields, start=1):
        tk.Label(frm, text=label).grid(row=i, column=0, sticky="e", padx=(0, 8), pady=3)
        e = tk.Entry(frm, width=34, show="•" if secret else "")
        e.grid(row=i, column=1, pady=3)
        entries[key] = e

    def ok(_=None):
        result.update({k: e.get() for k, e in entries.items()})
        result["_action"] = "ok"
        for e in entries.values():
            e.delete(0, tk.END)
        win.destroy()

    def cancel(_=None):
        for e in entries.values():
            e.delete(0, tk.END)
        win.destroy()

    btns = tk.Frame(frm)
    btns.grid(row=len(fields) + 1, column=0, columnspan=2, pady=(12, 0), sticky="we")
    if extra_button:
        text, action = extra_button

        def extra():
            result["_action"] = action
            for e in entries.values():
                e.delete(0, tk.END)
            win.destroy()

        tk.Button(btns, text=text, command=extra, relief="flat", fg="#0645ad", cursor="hand2").pack(side="left")
    tk.Button(btns, text="Anuluj", width=10, command=cancel).pack(side="right", padx=(6, 0))
    tk.Button(btns, text="OK", width=10, command=ok, default="active").pack(side="right")
    win.bind("<Return>", ok)
    win.bind("<Escape>", cancel)
    win.protocol("WM_DELETE_WINDOW", cancel)
    _center(win)
    win.lift()
    win.focus_force()
    entries[fields[0][0]].focus_force()
    win.grab_set()
    root.wait_window(win)
    return result or None


def setup_dialog(root: tk.Tk, config_path: str) -> bool:
    intro = ("Pierwsza konfiguracja.\n\nPodaj dane, którymi logujesz się na login.wsb.pl "
             "(konto Microsoft uczelni) oraz wymyśl PIN (min. %d znaków). "
             "Dane zostaną zaszyfrowane i zapisane na pendrivie:\n%s" % (MIN_PIN_LEN, config_path))
    while True:
        r = form_dialog(root, f"{APP_NAME} - konfiguracja", intro, [
            ("username", "Login / e-mail:", False),
            ("password", "Hasło:", True),
            ("pin", "PIN:", True),
            ("pin2", "Powtórz PIN:", True),
        ])
        if not r:
            return False
        if not r["username"].strip() or not r["password"]:
            messagebox.showerror(APP_NAME, "Login i hasło nie mogą być puste.", parent=root)
            continue
        if len(r["pin"]) < MIN_PIN_LEN:
            messagebox.showerror(APP_NAME, f"PIN musi mieć co najmniej {MIN_PIN_LEN} znaków.", parent=root)
            continue
        if r["pin"] != r["pin2"]:
            messagebox.showerror(APP_NAME, "PIN-y się różnią.", parent=root)
            continue
        save_credentials(config_path, r["username"].strip(), r["password"], r["pin"])
        messagebox.showinfo(APP_NAME, "Zapisano. Teraz zaloguję Cię pierwszy raz.", parent=root)
        return True


def unlock_dialog(root: tk.Tk, config_path: str) -> dict | None:
    for attempt in range(PIN_ATTEMPTS):
        intro = "Podaj PIN, aby zalogować się do MeritoGo."
        if attempt:
            intro = f"Zły PIN. Pozostało prób: {PIN_ATTEMPTS - attempt}."
        r = form_dialog(root, APP_NAME, intro, [("pin", "PIN:", True)],
                        extra_button=("Zmień dane…", "setup"))
        if not r:
            return None
        if r["_action"] == "setup":
            if setup_dialog(root, config_path):
                continue
            return None
        root.config(cursor="watch")
        creds = load_credentials(config_path, r["pin"])
        root.config(cursor="")
        if creds:
            return creds
        time.sleep(1.0)  # spowolnienie przeciwko zautomatyzowanym próbom
    messagebox.showerror(APP_NAME, "Zbyt wiele błędnych prób. Aplikacja zostanie zamknięta.", parent=root)
    return None


# --------------------------------------------------------------------------- #
# Aplikacja
# --------------------------------------------------------------------------- #
class App:
    def __init__(self, args):
        self.args = args
        self.usb_dir = os.path.abspath(args.usb_dir or app_dir())
        self.config_path = os.path.join(self.usb_dir, CONFIG_NAME)
        self.usb_serial = get_volume_serial(self.usb_dir)
        self._has_config = os.path.isfile(self.config_path)
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title(APP_NAME)
        self.browser: Browser | None = None
        self.bot: LoginBot | None = None
        self.stop = threading.Event()
        self.status_q: queue.Queue = queue.Queue()
        self.closing = False
        self._dead_checks = 0

    def usb_present(self) -> bool:
        try:
            # 1. Sprawdź czy numer seryjny woluminu USB się nie zmienił (wykrycie odłączenia / zamiany)
            if self.usb_serial is not None:
                curr_serial = get_volume_serial(self.usb_dir)
                if curr_serial != self.usb_serial:
                    return False
            # 2. Sprawdź czy folder nośnika istnieje
            if not os.path.isdir(self.usb_dir):
                return False
            # 3. Jeśli plik klucza istnieje, upewnij się że nadal jest obecny na nośniku
            if self._has_config and not os.path.isfile(self.config_path):
                return False
            return True
        except Exception:
            return False

    def run(self) -> None:
        self.root.after(POLL_MS, self._early_watch)
        if self.args.setup or not os.path.isfile(self.config_path):
            if not setup_dialog(self.root, self.config_path):
                return
            self._has_config = True
            self.usb_serial = get_volume_serial(self.usb_dir)
        creds = unlock_dialog(self.root, self.config_path)
        if not creds:
            return
        if not self.usb_present():
            return
        try:
            self.browser = launch_browser(self.args.browser, self.args.headless)
        except Exception as e:
            messagebox.showerror(APP_NAME, str(e), parent=self.root)
            return
        self.bot = LoginBot(self.browser, creds, self.status_q, self.stop)
        self.bot.start()
        creds = None
        self._build_status_window()
        self.root.after(POLL_MS, self._watch)
        self.root.mainloop()

    def _early_watch(self) -> None:
        # Pendrive wyjęty jeszcze przed startem przeglądarki -> po prostu wyjdź.
        if self.browser is not None:
            return
        if not self.usb_present():
            log.info("Pendrive wyjęty przed logowaniem")
            os._exit(0)
        self.root.after(POLL_MS, self._early_watch)

    def _build_status_window(self) -> None:
        r = self.root
        r.deiconify()
        r.resizable(False, False)
        r.attributes("-toolwindow", False)
        frm = tk.Frame(r, padx=16, pady=12)
        frm.pack()
        self.status_lbl = tk.Label(frm, text="Uruchamiam przeglądarkę…", justify="left", wraplength=320, width=46,
                                   anchor="w")
        self.status_lbl.pack(anchor="w")
        tk.Label(frm, text=f"Pendrive: {self.usb_dir}", fg="#666").pack(anchor="w", pady=(6, 0))
        tk.Button(frm, text="Wyloguj i zamknij teraz", command=lambda: self.shutdown("przycisk")).pack(
            anchor="e", pady=(10, 0))
        r.protocol("WM_DELETE_WINDOW", lambda: self.shutdown("okno zamknięte"))
        r.update_idletasks()
        r.geometry(f"+{r.winfo_screenwidth() - r.winfo_width() - 30}+{r.winfo_screenheight() - r.winfo_height() - 90}")
        r.iconify()

    def _watch(self) -> None:
        if self.closing:
            return
        while not self.status_q.empty():
            kind, text = self.status_q.get_nowait()
            color = {"ok": "#1a7f37", "error": "#b42318"}.get(kind, "#000")
            self.status_lbl.config(text=text, fg=color)
            if kind == "error":
                self.root.deiconify()
                self.root.lift()
        if not self.usb_present():
            self.shutdown("pendrive wyjęty")
            return
        if self.browser and not self.browser.alive():
            self._dead_checks += 1
            if self._dead_checks >= 2:
                self.shutdown("przeglądarka zamknięta")
                return
        else:
            self._dead_checks = 0
        self.root.after(POLL_MS, self._watch)

    def shutdown(self, reason: str) -> None:
        if self.closing:
            return
        self.closing = True
        log.info("Zamykanie: %s", reason)
        self.stop.set()
        try:
            self.status_lbl.config(text="Wylogowuję i zamykam…", fg="#000")
            self.root.update()
        except Exception:
            pass
        if self.browser:
            self.browser.logout_and_close()
        self.root.destroy()
        cleanup_logs()


# --------------------------------------------------------------------------- #
# Uruchamianie z pendrive'a: kopia do %TEMP%, sprzątanie, jedna instancja
# --------------------------------------------------------------------------- #
def cleanup_logs() -> None:
    try:
        for handler in logging.root.handlers[:]:
            handler.close()
            logging.root.removeHandler(handler)
        log_file = os.path.join(tempfile.gettempdir(), "wsb_passkey.log")
        if os.path.isfile(log_file):
            os.remove(log_file)
    except Exception:
        pass


def relaunch_from_temp() -> bool:
    """Kopiuje program do %TEMP%, aby wyjęcie pendrive'a nie zablokowało procesu.
    W przypadku gdy zasady grupy uczelni (AppLocker / SRP) blokują uruchamianie z Temp,
    funkcja zwraca False, a program automatycznie kontynuuje działanie wprost z pendrive'a.
    """
    try:
        tmp_dir = tempfile.gettempdir()
        dst = os.path.join(tmp_dir, "WSBPasskey_runner.exe")
        try:
            shutil.copy2(sys.executable, dst)
        except OSError:
            dst = os.path.join(tmp_dir, f"{TEMP_EXE_PREFIX}{secrets.token_hex(2)}.exe")
            shutil.copy2(sys.executable, dst)

        args = [dst, "--usb-dir", app_dir(), "--temp-exe"] + sys.argv[1:]
        proc = subprocess.Popen(args, close_fds=True, cwd=tmp_dir,
                                creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        # Szybka weryfikacja czy proces nie został zablokowany przez zasady grupy (AppLocker błąd 1260)
        time.sleep(0.3)
        if proc.poll() is not None and proc.returncode != 0:
            log.warning("Uruchomienie z Temp zablokowane przez politykę systemu (kod %s)", proc.returncode)
            try:
                os.remove(dst)
            except OSError:
                pass
            return False
        return True
    except OSError as e:
        log.warning("Nie można uruchomić kopii z Temp (%s), uruchamiam bezpośrednio", e)
        return False


def cleanup_leftovers() -> None:
    """Sprzątanie po ewentualnym wcześniejszym crashu (profil z ciasteczkami i pliki tymczasowe)."""
    tmp = tempfile.gettempdir()
    for d in glob.glob(os.path.join(tmp, PROFILE_PREFIX + "*")):
        shutil.rmtree(d, ignore_errors=True)
    me = os.path.abspath(sys.executable).lower()
    for f in glob.glob(os.path.join(tmp, "WSBPasskey_runner*.exe")) + glob.glob(os.path.join(tmp, TEMP_EXE_PREFIX + "*.exe")):
        if os.path.abspath(f).lower() != me:
            try:
                os.remove(f)
            except OSError:
                pass
    log_file = os.path.join(tmp, "wsb_passkey.log")
    try:
        if os.path.isfile(log_file):
            os.remove(log_file)
    except OSError:
        pass


_mutex = None


def single_instance() -> bool:
    global _mutex
    _mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\WSBPasskeyMutex")
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def main() -> None:
    p = argparse.ArgumentParser(description=APP_NAME)
    p.add_argument("--usb-dir", help="folder pendrive'a z plikiem danych (domyślnie folder programu)")
    p.add_argument("--setup", action="store_true", help="skonfiguruj login/hasło/PIN od nowa")
    p.add_argument("--browser", choices=["edge", "chrome"], help="preferowana przeglądarka")
    p.add_argument("--headless", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--temp-exe", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--no-relocate", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args()

    if is_frozen() and not args.temp_exe and not args.no_relocate:
        if relaunch_from_temp():
            return
        # Jeśli uruchomienie z Temp zostało zablokowane przez politykę uczelni,
        # kontynuujemy działanie bezpośrednio z nośnika USB (fallback).

    logging.basicConfig(
        filename=os.path.join(tempfile.gettempdir(), "wsb_passkey.log"),
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", encoding="utf-8",
    )
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    try:
        if not single_instance():
            return
        cleanup_leftovers()
        App(args).run()
    except Exception as e:
        log.exception("fatal")
        try:
            messagebox.showerror(APP_NAME, f"Błąd: {e}")
        except Exception:
            pass
    finally:
        cleanup_logs()


if __name__ == "__main__":
    main()
