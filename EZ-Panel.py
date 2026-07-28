#!/usr/bin/env python3
# Created by: EOAMIR
# ver: v1.4.1 EZ-Panel
# Tel: @IMEOAMIR
import sqlite3
import hashlib
import secrets
import time
import os
import sys
import requests
import json
import subprocess
import re
import copy

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


C_RESET   = "\033[0m"
C_BOLD    = "\033[1m"
C_RED     = "\033[91m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN    = "\033[96m"
C_WHITE   = "\033[97m"


DB_PATH         = '/etc/x-ui/x-ui.db'
TOKEN_SAVE_PATH = '/etc/x-ui/ez_token.json'


PG_CREDS_FILE = os.path.expanduser("~/.pg_relay_creds")


TSIN_INSTANCES_DIR = "/etc/tor/tsin_instances"
TSIN_OLD_DIR       = "/etc/tor/instances"          # also used by EoTor (plain <code> folders, no "tsin_" prefix)

NODE_TYPE_TAGS = {
    "tsin":  "T.Sin",
    "eotor": "EoTor",
}


COUNTRIES = [
    {"index":  1, "code": "de", "name": "Germany",       "flag": "🇩🇪", "out_port": 9080, "in_port": 3031},
    {"index":  2, "code": "tr", "name": "Turkey",         "flag": "🇹🇷", "out_port": 9081, "in_port": 3032},
    {"index":  3, "code": "us", "name": "United States",  "flag": "🇺🇸", "out_port": 9082, "in_port": 3033},
    {"index":  4, "code": "fr", "name": "France",         "flag": "🇫🇷", "out_port": 9083, "in_port": 3034},
    {"index":  5, "code": "at", "name": "Austria",        "flag": "🇦🇹", "out_port": 9084, "in_port": 3035},
    {"index":  6, "code": "be", "name": "Belgium",        "flag": "🇧🇪", "out_port": 9085, "in_port": 3036},
    {"index":  7, "code": "ro", "name": "Romania",        "flag": "🇷🇴", "out_port": 9086, "in_port": 3037},
    {"index":  8, "code": "ca", "name": "Canada",         "flag": "🇨🇦", "out_port": 9087, "in_port": 3038},
    {"index":  9, "code": "sg", "name": "Singapore",      "flag": "🇸🇬", "out_port": 9088, "in_port": 3039},
    {"index": 10, "code": "jp", "name": "Japan",          "flag": "🇯🇵", "out_port": 9089, "in_port": 3040},
    {"index": 11, "code": "ie", "name": "Ireland",        "flag": "🇮🇪", "out_port": 9090, "in_port": 3041},
    {"index": 12, "code": "fi", "name": "Finland",        "flag": "🇫🇮", "out_port": 9091, "in_port": 3042},
    {"index": 13, "code": "es", "name": "Spain",          "flag": "🇪🇸", "out_port": 9092, "in_port": 3043},
    {"index": 14, "code": "pl", "name": "Poland",         "flag": "🇵🇱", "out_port": 9093, "in_port": 3044},
    {"index": 15, "code": "nl", "name": "Netherlands",    "flag": "🇳🇱", "out_port": 9094, "in_port": 3045},
    {"index": 16, "code": "it", "name": "Italy",          "flag": "🇮🇹", "out_port": 9095, "in_port": 3046},
    {"index": 17, "code": "ch", "name": "Switzerland",    "flag": "🇨🇭", "out_port": 9096, "in_port": 3047},
    {"index": 18, "code": "se", "name": "Sweden",         "flag": "🇸🇪", "out_port": 9097, "in_port": 3048},
    {"index": 19, "code": "no", "name": "Norway",         "flag": "🇳🇴", "out_port": 9098, "in_port": 3049},
    {"index": 20, "code": "dk", "name": "Denmark",        "flag": "🇩🇰", "out_port": 9099, "in_port": 3050},
    {"index": 21, "code": "is", "name": "Iceland",        "flag": "🇮🇸", "out_port": 9100, "in_port": 3051},
    {"index": 22, "code": "au", "name": "Australia",      "flag": "🇦🇺", "out_port": 9101, "in_port": 3052},
    {"index": 23, "code": "in", "name": "India",          "flag": "🇮🇳", "out_port": 9102, "in_port": 3053},
    {"index": 24, "code": "hk", "name": "Hong Kong",      "flag": "🇭🇰", "out_port": 9103, "in_port": 3054},
    {"index": 25, "code": "ua", "name": "Ukraine",        "flag": "🇺🇦", "out_port": 9104, "in_port": 3055},
    {"index": 26, "code": "cz", "name": "Czech Republic", "flag": "🇨🇿", "out_port": 9105, "in_port": 3056},
    {"index": 27, "code": "kr", "name": "South Korea",    "flag": "🇰🇷", "out_port": 9106, "in_port": 3057},
    {"index": 28, "code": "za", "name": "South Africa",   "flag": "🇿🇦", "out_port": 9107, "in_port": 3058},
    {"index": 29, "code": "mx", "name": "Mexico",         "flag": "🇲🇽", "out_port": 9108, "in_port": 3059},
    {"index": 30, "code": "my", "name": "Malaysia",       "flag": "🇲🇾", "out_port": 9109, "in_port": 3060},
    {"index": 31, "code": "az", "name": "Azerbaijan",     "flag": "🇦🇿", "out_port": 9110, "in_port": 3061},
    {"index": 32, "code": "cy", "name": "Cyprus",         "flag": "🇨🇾", "out_port": 9111, "in_port": 3062},
    {"index": 33, "code": "gr", "name": "Greece",         "flag": "🇬🇷", "out_port": 9112, "in_port": 3063},
    {"index": 34, "code": "pt", "name": "Portugal",       "flag": "🇵🇹", "out_port": 9113, "in_port": 3064},
    {"index": 35, "code": "hu", "name": "Hungary",        "flag": "🇭🇺", "out_port": 9114, "in_port": 3065},
    {"index": 36, "code": "lu", "name": "Luxembourg",     "flag": "🇱🇺", "out_port": 9115, "in_port": 3066},
    {"index": 37, "code": "gb", "name": "United Kingdom", "flag": "🇬🇧", "out_port": 9116, "in_port": 3067},
    {"index": 38, "code": "ar", "name": "Argentina",      "flag": "🇦🇷", "out_port": 9117, "in_port": 3068},
    {"index": 39, "code": "tw", "name": "Taiwan",         "flag": "🇹🇼", "out_port": 9118, "in_port": 3069},
    {"index": 40, "code": "bg", "name": "Bulgaria",       "flag": "🇧🇬", "out_port": 9119, "in_port": 3070},
    {"index": 41, "code": "il", "name": "Israel",         "flag": "🇮🇱", "out_port": 9120, "in_port": 3071},
    {"index": 42, "code": "md", "name": "Moldova",        "flag": "🇲🇩", "out_port": 9121, "in_port": 3072},
    {"index": 43, "code": "ru", "name": "Russia",         "flag": "🇷🇺", "out_port": 9122, "in_port": 3073},
    {"index": 44, "code": "ir", "name": "Chile",          "flag": "🇨🇱", "out_port": 9123, "in_port": 3074},
    {"index": 45, "code": "cr", "name": "Costa Rica",     "flag": "🇨🇷", "out_port": 9124, "in_port": 3075},
    {"index": 46, "code": "vn", "name": "Vietnam",        "flag": "🇻🇳", "out_port": 9125, "in_port": 3076},
    {"index": 47, "code": "id", "name": "Indonesia",      "flag": "🇮🇩", "out_port": 9126, "in_port": 3077},
    {"index": 48, "code": "sc", "name": "Seychelles",     "flag": "🇸🇨", "out_port": 9127, "in_port": 3078},
    {"index": 49, "code": "hr", "name": "Croatia",        "flag": "🇭🇷", "out_port": 9128, "in_port": 3079},
    {"index": 50, "code": "tn", "name": "Tunisia",        "flag": "🇹🇳", "out_port": 9129, "in_port": 3080},
]

LICENSE_PLAN = "g"

PLAN_COUNTRIES = {
    'b': ['de', 'us', 'tr', 'at', 'fr'],
    's': ['de', 'tr', 'us', 'fr', 'at', 'be', 'ro', 'ca', 'sg', 'jp', 'ie', 'fi', 'es', 'pl', 'nl'],
    'g': [c['code'] for c in COUNTRIES]
}



def detect_installed_panels():

    installed = []

    if os.path.exists(DB_PATH) or os.path.exists('/usr/local/x-ui/x-ui'):
        installed.append(("3X-UI", C_GREEN + "🟢 Installed" + C_RESET))
    else:
        installed.append(("3X-UI", C_WHITE + "⚪ Not Found" + C_RESET))

    pg_paths = ["/opt/pasarguard", "/opt/PasarGuard", "/etc/pasarguard", "/etc/PasarGuard"]
    if any(os.path.exists(p) for p in pg_paths):
        installed.append(("Pasargad", C_GREEN + "🟢 Installed" + C_RESET))
    else:
        installed.append(("Pasargad", C_WHITE + "⚪ Not Found" + C_RESET))

    marzban_paths = ["/opt/marzban", "/etc/marzban", "/usr/local/bin/marzban"]
    if any(os.path.exists(p) for p in marzban_paths):
        installed.append(("Marzban", C_GREEN + "🟢 Installed" + C_RESET))
    else:
        installed.append(("Marzban", C_WHITE + "⚪ Not Found" + C_RESET))
    return installed


def show_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"{C_RED}=" * 66)
    print(f"""{C_RED}
 ███████╗███████╗   ██████╗  █████╗ ███╗   ██╗███████╗██╗     
 ██╔════╝╚══███╔╝   ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║     
 █████╗    ███╔╝    ██████╔╝███████║██╔██╗ ██║█████╗  ██║     
 ██╔══╝   ███╔╝     ██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║     
 ███████╗███████╗██╗██║     ██║  ██║██║ ╚████║███████╗███████╗
 ╚══════╝╚══════╝╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝{C_RESET}""")
    print(f"{C_BOLD}{C_RED}                      EZ-PANEL AUTOMATOR                     {C_RESET}")
    print(f"{C_YELLOW}             Version: V1.4  {C_WHITE}|  {C_RED}Dev : t.me/IMEOAMIR{C_RESET}")
    print(f"{C_RED}=" * 66 + C_RESET)
    print()


def show_banner_with_panels():

    show_banner()
    panels = detect_installed_panels()
    print(f"{C_BLUE}{'─' * 66}{C_RESET}")
    print(f"  {C_BOLD}{C_WHITE}🖥️  Detected Panels on this Server:{C_RESET}")
    for name, status in panels:
        print(f"     {C_YELLOW}❖{C_RESET}  {C_WHITE}{name:<12}{C_RESET}  {status}")
    print(f"{C_BLUE}{'─' * 66}{C_RESET}")
    print()


def parse_selection(input_str, max_limit):
    selected = set()
    parts = input_str.replace(" ", "").split(",")
    for part in parts:
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                s, e = int(start), int(end)
                if 1 <= s <= max_limit and 1 <= e <= max_limit:
                    selected.update(range(min(s, e), max(s, e) + 1))
            except ValueError:
                continue
        else:
            try:
                v = int(part)
                if 1 <= v <= max_limit:
                    selected.add(v)
            except ValueError:
                continue
    return sorted(list(selected))


def confirm_proceed(prompt="Are you sure you want to proceed?"):

    ans = input(f"\n{C_BOLD}{C_YELLOW}❓ {prompt} ({C_GREEN}y{C_YELLOW}/{C_RED}n{C_YELLOW}){C_RESET}: ").strip().lower()
    return ans == "y"


def fetch_ez_license():

    global LICENSE_PLAN
    LICENSE_PLAN = "g"

def ez_get_allowed_codes():
    return set(PLAN_COUNTRIES.get(LICENSE_PLAN, [c['code'] for c in COUNTRIES]))

def ez_get_required_plan_label(code):
    if code in ez_get_allowed_codes():
        return None
    if code in PLAN_COUNTRIES['s']:
        return "Silver/Gold"
    return "Gold"

def ez_format_plan_label(req):
    b = C_BLUE
    s = C_WHITE
    g = C_YELLOW
    r = C_RESET
    if req == "Silver/Gold":
        return f"{b}[{r}{s}Silver{r}{b}/{r}{g}Gold{r}{b}]{r}"
    elif req == "Gold":
        return f"{b}[{r}{g}Gold{r}{b}]{r}       "
    return ""


class ThreeXUIClient:
    def __init__(self, base_url, api_token=None):
        self.base_url = base_url.rstrip('/')
        self.api_base_url = self.base_url[:-6] if self.base_url.endswith('/panel') else self.base_url
        self.api_token = api_token
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = False
        if self.api_token:
            self.session.headers.update({
                "Authorization": f"Bearer {self.api_token}",
                "Accept": "application/json"
            })

    def test_connection(self):
        url = f"{self.api_base_url}/panel/api/inbounds/list"
        last_error = ""
        for method in ["POST", "GET"]:
            try:
                r = self.session.post(url, timeout=10) if method == "POST" else self.session.get(url, timeout=10)
                if r.status_code == 200:
                    try:
                        result = r.json()
                        if result.get("success") or "obj" in result:
                            return True, None
                        last_error = f"Status 200 but success=False. Msg: {result.get('msg')}"
                    except Exception:
                        return True, None
                else:
                    last_error = f"HTTP {r.status_code}: {r.text[:100]}"
            except Exception as e:
                last_error = str(e)
        return False, last_error

    def get_inbounds(self):
        url = f"{self.api_base_url}/panel/api/inbounds/list"
        try:
            r = self.session.post(url, timeout=10)
            if r.status_code != 200:
                r = self.session.get(url, timeout=10)
            result = r.json()
            if r.status_code == 200 and result.get("success"):
                return True, result.get("obj", [])
            return False, []
        except Exception:
            return False, []

    def create_inbound(self, inbound_data):
        url = f"{self.api_base_url}/panel/api/inbounds/add"
        try:
            r = self.session.post(url, json=inbound_data, timeout=10)
            result = r.json()
            if r.status_code == 200 and result.get("success"):
                return True, result
            return False, result
        except Exception:
            return False, None

    def delete_inbound(self, inbound_id):
        url = f"{self.api_base_url}/panel/api/inbounds/del/{inbound_id}"
        try:
            r = self.session.post(url, timeout=10)
            result = r.json()
            return r.status_code == 200 and result.get("success")
        except Exception:
            return False

    def get_xray_setting(self):
        url = f"{self.api_base_url}/panel/api/xray/"
        try:
            r = self.session.post(url, timeout=10)
            result = r.json()
            if r.status_code == 200 and result.get("success"):
                return True, result.get("obj", {})
            return False, None
        except Exception:
            return False, None

    def update_xray_setting(self, xray_setting_str, outbound_test_url="https://www.google.com/generate_204"):
        url = f"{self.api_base_url}/panel/api/xray/update"
        try:
            r = self.session.post(url, data={"xraySetting": xray_setting_str, "outboundTestUrl": outbound_test_url}, timeout=10)
            result = r.json()
            return r.status_code == 200 and result.get("success")
        except Exception:
            return False

    def add_permanent_outbound(self, outbound_data):
        success, settings = self.get_xray_setting()
        if not success or not settings:
            return False
        try:
            if isinstance(settings, str):
                settings = json.loads(settings)
            xray_setting = settings.get("xraySetting", "{}")
            xray_config  = json.loads(xray_setting) if isinstance(xray_setting, str) else xray_setting
            xray_config.setdefault("outbounds", [])
            new_tag = outbound_data.get("tag")
            if new_tag:
                xray_config["outbounds"] = [ob for ob in xray_config["outbounds"] if ob.get("tag") != new_tag]
            xray_config["outbounds"].append(outbound_data)
            outbound_test_url = settings.get("outboundTestUrl", "https://www.google.com/generate_204")
            return self.update_xray_setting(json.dumps(xray_config, indent=2), outbound_test_url)
        except Exception:
            return False

    def add_routing_rule(self, rule_data):
        success, settings = self.get_xray_setting()
        if not success or not settings:
            return False
        try:
            if isinstance(settings, str):
                settings = json.loads(settings)
            xray_setting = settings.get("xraySetting", "{}")
            xray_config  = json.loads(xray_setting) if isinstance(xray_setting, str) else xray_setting
            xray_config.setdefault("routing", {}).setdefault("rules", [])
            new_inbound_tags = rule_data.get("inboundTag", [])
            xray_config["routing"]["rules"] = [
                r for r in xray_config["routing"]["rules"]
                if not any(tag in r.get("inboundTag", []) for tag in new_inbound_tags)
            ]
            xray_config["routing"]["rules"].append(rule_data)
            outbound_test_url = settings.get("outboundTestUrl", "https://www.google.com/generate_204")
            return self.update_xray_setting(json.dumps(xray_config, indent=2), outbound_test_url)
        except Exception:
            return False

    def delete_outbound_and_routing(self, outbound_tag, inbound_tag):
        success, settings = self.get_xray_setting()
        if not success or not settings:
            return False
        try:
            if isinstance(settings, str):
                settings = json.loads(settings)
            xray_setting = settings.get("xraySetting", "{}")
            xray_config  = json.loads(xray_setting) if isinstance(xray_setting, str) else xray_setting
            if "outbounds" in xray_config:
                xray_config["outbounds"] = [ob for ob in xray_config["outbounds"] if ob.get("tag") != outbound_tag]
            if "routing" in xray_config and "rules" in xray_config["routing"]:
                xray_config["routing"]["rules"] = [
                    r for r in xray_config["routing"]["rules"]
                    if inbound_tag not in r.get("inboundTag", []) and r.get("outboundTag") != outbound_tag
                ]
            outbound_test_url = settings.get("outboundTestUrl", "https://www.google.com/generate_204")
            return self.update_xray_setting(json.dumps(xray_config, indent=2), outbound_test_url)
        except Exception:
            return False

    def restart_xray_service(self):
        url = f"{self.api_base_url}/panel/api/server/restartXrayService"
        try:
            r = self.session.post(url, timeout=10)
            return r.status_code == 200 and r.json().get("success")
        except Exception:
            return False



def generate_api_token():
    if not os.path.exists(DB_PATH):
        print(f"{C_RED}[Error] Database not found at {DB_PATH}. Is 3X-UI installed?{C_RESET}")
        sys.exit(1)
    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM settings WHERE key IN ('webPort', 'webBasePath')")
        port = "54321"
        path = ""
        for key, value in cursor.fetchall():
            if key == 'webPort':       port = value
            elif key == 'webBasePath': path = value.strip('/')
        base_url_http  = f"http://127.0.0.1:{port}/{path}"  if path else f"http://127.0.0.1:{port}/"
        base_url_https = f"https://127.0.0.1:{port}/{path}" if path else f"https://127.0.0.1:{port}/"
        base_url = base_url_http
        _probe = requests.Session()
        _probe.trust_env = False
        _probe.verify    = False
        for candidate in [base_url_http, base_url_https]:
            try:
                _probe.get(f"{candidate.rstrip('/')}/panel/api/inbounds/list", timeout=5)
                base_url = candidate
                break
            except Exception:
                continue
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('api_tokens', 'api_token')")
        table_row = cursor.fetchone()
        if not table_row:
            print(f"{C_RED}[Error] API tokens table not found.{C_RESET}")
            conn.close()
            sys.exit(1)
        table_name = table_row[0]
        existing_plaintext = existing_hash = None
        if os.path.exists(TOKEN_SAVE_PATH):
            try:
                saved = json.load(open(TOKEN_SAVE_PATH))
                existing_plaintext = saved.get("plaintext_token")
                existing_hash      = saved.get("hashed_token")
            except Exception:
                pass
        if existing_plaintext and existing_hash:
            cursor.execute(f"SELECT token FROM {table_name} WHERE name = ? AND enabled = 1", ('EZ-Panel-Auto',))
            db_row = cursor.fetchone()
            if db_row and db_row[0] == existing_hash:
                conn.close()
                return base_url, existing_plaintext
        plaintext_token = "3xui_" + secrets.token_hex(20)
        hashed_token    = hashlib.sha256(plaintext_token.encode()).hexdigest()
        cursor.execute(f"DELETE FROM {table_name} WHERE name = ?", ('EZ-Panel-Auto',))
        cursor.execute(f"INSERT INTO {table_name} (name, token, enabled, created_at) VALUES (?, ?, ?, ?)",
                       ('EZ-Panel-Auto', hashed_token, 1, int(time.time() * 1000)))
        conn.commit()
        conn.close()
        try:
            json.dump({"plaintext_token": plaintext_token, "hashed_token": hashed_token}, open(TOKEN_SAVE_PATH, 'w'))
        except Exception:
            pass
        return base_url, plaintext_token
    except Exception as e:
        print(f"{C_RED}[Error generating token]: {e}{C_RESET}")
        sys.exit(1)


def parse_json_field(val):
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return val
    return val


def get_installed_tsin_nodes():
    """
    Scans both known Tor-instance layouts and returns a dict of country_code -> node.
    Each node carries 'node_type' ('tsin' / 'eotor') and 'tag_prefix' ('T.Sin' / 'EoTor')
    so the rest of the code can build correctly-labeled outbound tags.

    Layouts:
      - T.Sin : /etc/tor/tsin_instances/tsin_<code>
      - EoTor : /etc/tor/instances/<code>            (no "tsin_" prefix)
      - Legacy: /etc/tor/instances/tsin_<code>        (old T.Sin nodes, kept for back-compat)
    """
    installed = {}

    def _register(code, node_type):
        if code in installed:
            return
        for c in COUNTRIES:
            if c['code'] == code:
                node = c.copy()
                node['node_type']  = node_type
                node['tag_prefix'] = NODE_TYPE_TAGS[node_type]
                installed[code] = node
                break

    if os.path.exists(TSIN_INSTANCES_DIR):
        try:
            for item in os.listdir(TSIN_INSTANCES_DIR):
                if item.startswith("tsin_"):
                    _register(item.replace("tsin_", ""), "tsin")
        except Exception:
            pass

    if os.path.exists(TSIN_OLD_DIR):
        try:
            for item in os.listdir(TSIN_OLD_DIR):
                if item.startswith("tsin_"):
                    _register(item.replace("tsin_", ""), "tsin")
                else:
                    _register(item, "eotor")
        except Exception:
            pass

    return installed


def check_node_configured_in_panel(client, country_code, tag_prefix="T.Sin"):
    try:
        success, settings = client.get_xray_setting()
        if not success or not settings:
            return False
        if isinstance(settings, str):
            settings = json.loads(settings)
        xray_setting = settings.get("xraySetting", "{}")
        xray_config  = json.loads(xray_setting) if isinstance(xray_setting, str) else xray_setting
        outbound_tag = f"{tag_prefix}-{country_code.upper()}"
        if not any(ob.get("tag") == outbound_tag for ob in xray_config.get("outbounds", [])):
            return False
        return any(r.get("outboundTag") == outbound_tag for r in xray_config.get("routing", {}).get("rules", []))
    except Exception:
        return False


def clone_inbound_for_country(client, source_inbound, country):

    settings        = parse_json_field(source_inbound.get("settings"))
    stream_settings = parse_json_field(source_inbound.get("streamSettings"))
    sniffing        = parse_json_field(source_inbound.get("sniffing"))

    flag         = country.get('flag', '🌐')
    tag_prefix   = country.get('tag_prefix', 'T.Sin')
    inbound_tag  = f"{flag} {country['name']}"      
    outbound_tag = f"{tag_prefix}-{country['code'].upper()}"  

    success, current_inbounds = client.get_inbounds()
    if success and current_inbounds:
        for ib in current_inbounds:
            if ib.get("port") == country['in_port'] or ib.get("tag") == inbound_tag:
                client.delete_inbound(ib.get("id"))

    inbound_payload = {
        "enable": True,
        "remark": f"{flag} {country['name']}",
        "listen": source_inbound.get("listen", ""),
        "port": country['in_port'],
        "protocol": source_inbound.get("protocol"),
        "expiryTime": 0,
        "total": 0,
        "tag": inbound_tag,
        "settings": settings,
        "streamSettings": stream_settings,
        "sniffing": sniffing
    }
    inbound_ok, _ = client.create_inbound(inbound_payload)
    if not inbound_ok:
        print(f" {C_RED}❌ Failed to create inbound for {flag} {country['name']} (Port {country['in_port']}).{C_RESET}")
        return False

    outbound_ok = client.add_permanent_outbound({
        "protocol": "socks",
        "settings": {"servers": [{"address": "127.0.0.1", "port": country['out_port']}]},
        "tag": outbound_tag
    })
    if not outbound_ok:
        print(f" {C_RED}❌ Failed to create SOCKS outbound for {flag} {country['name']}.{C_RESET}")
        return False

    routing_ok = client.add_routing_rule({
        "type": "field",
        "inboundTag": [inbound_tag],
        "outboundTag": outbound_tag
    })
    if not routing_ok:
        print(f" {C_RED}❌ Failed to create routing rule for {flag} {country['name']}.{C_RESET}")
        return False

    print(f" {C_GREEN}✅ {flag} {country['name']}{C_RESET} | In:{C_CYAN}{country['in_port']}{C_RESET} ➔ Out:{C_YELLOW}{country['out_port']}{C_RESET}")
    return True


def execute_deletion_for_countries(client, selected_countries, current_inbounds):
    success_count = 0
    for country in selected_countries:
        flag         = country.get('flag', '🌐')
        tag_prefix   = country.get('tag_prefix', 'T.Sin')
        inbound_tag  = f"{flag} {country['name']}"
        outbound_tag = f"{tag_prefix}-{country['code'].upper()}"
        inbound_deleted = False
        for ib in current_inbounds:
            if ib.get("port") == country['in_port'] or ib.get("tag") == inbound_tag:
                if client.delete_inbound(ib.get("id")):
                    inbound_deleted = True
        outbound_routing_deleted = client.delete_outbound_and_routing(outbound_tag, inbound_tag)
        if inbound_deleted or outbound_routing_deleted:
            print(f" {C_RED}🗑️  Removed:{C_RESET} {flag} {country['name']}")
            success_count += 1
        else:
            print(f" {C_YELLOW}⏭️  Nothing to delete for:{C_RESET} {flag} {country['name']}")
    return success_count



def xui_show_inbounds(inbounds):
    print(f"{C_BLUE}{'─' * 62}{C_RESET}")
    print(f"  {C_BOLD}{'#':<4} {'Port':<8} {'Protocol':<12} {'Remark'}{C_RESET}")
    print(f"{C_BLUE}{'─' * 62}{C_RESET}")
    for i, ib in enumerate(inbounds, 1):
        port     = str(ib.get('port', '?'))
        protocol = ib.get('protocol', '?')
        remark   = ib.get('remark', 'No Remark')
        print(f"  {C_YELLOW}[{i}]{C_RESET}  {C_WHITE}{port:<8}{C_RESET} {C_CYAN}{protocol:<12}{C_RESET} {C_GREEN}{remark}{C_RESET}")
    print(f"{C_BLUE}{'─' * 62}{C_RESET}")



def handle_tsin_nodes_setup(client):
    installed = get_installed_tsin_nodes()
    if not installed:
        show_banner()
        print(f"{C_YELLOW}📦 No T.Sin/EoTor nodes installed on your system.{C_RESET}")
        input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to return...")
        return

    unconfigured = sorted(
        [info for code, info in installed.items()
         if not check_node_configured_in_panel(client, code, info.get('tag_prefix', 'T.Sin'))],
        key=lambda x: x['out_port']
    )

    if not unconfigured:
        show_banner()
        print(f"{C_GREEN}🎉 All installed T.Sin/EoTor nodes are already configured!{C_RESET}")
        input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to return...")
        return

    success, inbounds = client.get_inbounds()
    if not success or not inbounds:
        print(f"{C_RED}❌ No active inbounds found to clone from.{C_RESET}")
        input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to return...")
        return

    while True:

        show_banner()
        print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ T.SIN / EOTOR — SELECT NODES TO SETUP ]{C_RESET}")
        print(f"{C_BLUE}{'─' * 66}{C_RESET}")
        for i, node in enumerate(unconfigured, 1):
            tag_label = f"{C_BOLD}{C_RED}[{node.get('tag_prefix', 'T.Sin')}]{C_RESET}"
            print(f"  {C_YELLOW}[{i:02}]{C_RESET} {tag_label} {node.get('flag', '🌐')} {C_WHITE}{node['name']:<20}{C_RESET}  SOCKS Port: {C_CYAN}{node['out_port']}{C_RESET}")
        print(f"{C_BLUE}{'─' * 66}{C_RESET}")
        print(f"  {C_RED}[0]{C_RESET} Go Back")
        print(f"{C_BLUE}{'─' * 66}{C_RESET}")

        node_input = input(f"\n{C_BOLD}Select node(s) (e.g. 1 or 1-3,5):{C_RESET} ").strip()
        if node_input in ("0", ""):
            return

        selected_indices = parse_selection(node_input, len(unconfigured))
        if not selected_indices:
            print(f"{C_RED}❌ Invalid selection. Try again.{C_RESET}")
            time.sleep(1.5)
            continue

        selected_nodes = [unconfigured[i - 1] for i in selected_indices]


        show_banner()
        print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ T.SIN — SELECT INBOUND SOURCE ]{C_RESET}")
        xui_show_inbounds(inbounds)
        print(f"  {C_RED}[0]{C_RESET} Go Back")
        print(f"{C_BLUE}{'─' * 62}{C_RESET}")

        while True:
            port_input = input(f"\n{C_BOLD}Enter the inbound port to clone from:{C_RESET} ").strip()
            if port_input == "0":
                break
            try:
                target_port = int(port_input)
            except ValueError:
                print(f"{C_RED}❌ Invalid input.{C_RESET}")
                time.sleep(1)
                continue
            matched = next((ib for ib in inbounds if ib.get('port') == target_port), None)
            if not matched:
                print(f"{C_RED}❌ Port {target_port} not found.{C_RESET}")
                time.sleep(1)
                continue


            show_banner()
            print(f"{C_YELLOW}📋 Summary:{C_RESET}")
            print(f"   Clone from port  : {C_CYAN}{target_port}{C_RESET}")
            print(f"   Nodes to setup   : {C_WHITE}{', '.join(n['name'] for n in selected_nodes)}{C_RESET}")
            if not confirm_proceed("Start setup?"):
                print(f"{C_YELLOW}Cancelled.{C_RESET}")
                time.sleep(1)
                break


            show_banner()
            print(f"{C_YELLOW}⚡ Setting up T.Sin nodes...{C_RESET}")
            print(f"{C_BLUE}{'─' * 60}{C_RESET}")
            success_count = sum(1 for node in selected_nodes if clone_inbound_for_country(client, matched, node))
            print(f"{C_BLUE}{'─' * 60}{C_RESET}")
            if success_count > 0:
                print(f"{C_YELLOW}⏳ Restarting Xray Core...{C_RESET}")
                if client.restart_xray_service():
                    print(f"\n{C_GREEN}🎉 Setup completed for {success_count} node(s)!{C_RESET}")
                else:
                    print(f"\n{C_RED}⚠️ Saved but auto-restart failed.{C_RESET}")
            else:
                print(f"{C_RED}❌ Setup failed for all nodes.{C_RESET}")
            input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
            return



def handle_3xui_flow():
    print(f"{C_YELLOW}⏳ Authenticating with local 3X-UI database...{C_RESET}")
    base_url, api_token = generate_api_token()
    client = ThreeXUIClient(base_url=base_url, api_token=api_token)
    connected, err_msg = client.test_connection()
    if not connected:
        try:
            subprocess.run(["systemctl", "restart", "x-ui"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)
            connected, err_msg = client.test_connection()
        except Exception:
            pass
    if not connected:
        print(f"{C_RED}❌ Cannot connect to panel: {err_msg}{C_RESET}")
        print("Please run: systemctl restart x-ui")
        input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to return...")
        return
    print(f"{C_GREEN}🟢 Login successful!{C_RESET}\n")
    time.sleep(1)

    while True:
        show_banner()
        print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ 3X-UI CONTROL PANEL ]{C_RESET}")
        print(f"{C_RED}{'=' * 45}{C_RESET}")
        print(f"  {C_YELLOW}[1]{C_RESET} Batch Create  (all 50 countries)")
        print(f"  {C_YELLOW}[2]{C_RESET} Custom Create (select countries)")
        print(f"  {C_YELLOW}[3]{C_RESET} T.Sin/EoTor Installed Nodes")
        print(f"  {C_YELLOW}[4]{C_RESET} Delete Configurations")
        print(f"  {C_RED}[0]{C_RESET} Exit")
        print(f"{C_RED}{'=' * 45}{C_RESET}")

        choice = input(f"\n{C_BOLD}Selected option:{C_RESET} ").strip()
        if choice == "0":
            break
        if choice not in ["1", "2", "3", "4"]:
            print(f"{C_RED}❌ Invalid option.{C_RESET}")
            time.sleep(1.5)
            continue


        if choice == "3":
            handle_tsin_nodes_setup(client)
            continue


        if choice == "4":
            while True:
                show_banner()
                print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ DELETE CONFIGS MENU ]{C_RESET}")
                print(f"{C_RED}{'=' * 45}{C_RESET}")
                print(f"  {C_YELLOW}[1]{C_RESET} Batch Delete  (all 50 countries)")
                print(f"  {C_YELLOW}[2]{C_RESET} Custom Delete (select countries)")
                print(f"  {C_RED}[0]{C_RESET} Go Back")
                print(f"{C_RED}{'=' * 45}{C_RESET}")
                del_choice = input(f"\n{C_BOLD}Selected Option:{C_RESET} ").strip()
                if del_choice == "0":
                    break
                if del_choice not in ["1", "2"]:
                    print(f"{C_RED}❌ Invalid option.{C_RESET}")
                    time.sleep(1.5)
                    continue
                success, inbounds = client.get_inbounds()
                if not success:
                    print(f"{C_RED}❌ Failed to fetch inbounds.{C_RESET}")
                    input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to return...")
                    continue

                if del_choice == "1":
                    show_banner()
                    print(f"{C_RED}⚠️  WARNING: Deletes ALL 50 country configs (inbound + SOCKS + routing).{C_RESET}")
                    if not confirm_proceed("Delete ALL?"):
                        print(f"{C_YELLOW}Cancelled.{C_RESET}")
                        time.sleep(1.5)
                        continue
                    show_banner()
                    print(f"{C_YELLOW}⚡ Batch deletion in progress...{C_RESET}")
                    print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                    removed = execute_deletion_for_countries(client, COUNTRIES, inbounds)
                    print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                    print(f"🗑️  Done. ({C_RED}{removed}{C_RESET} configs cleared)")
                    print(f"{C_YELLOW}⏳ Restarting Xray...{C_RESET}")
                    if client.restart_xray_service():
                        print(f"{C_GREEN}🎉 Restarted!{C_RESET}")
                    else:
                        print(f"{C_RED}⚠️ Auto-restart failed.{C_RESET}")
                    input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
                    break

                elif del_choice == "2":
                    while True:
                        existing_ports = {ib.get('port') for ib in inbounds}
                        show_banner()
                        print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ SELECT COUNTRIES TO DELETE ]{C_RESET}")
                        print(f"{C_BLUE}{'─' * 66}{C_RESET}")
                        for i in range(0, len(COUNTRIES), 2):
                            c1 = COUNTRIES[i]
                            s1 = f"{C_GREEN}🟢{C_RESET}" if c1['in_port'] in existing_ports else f"{C_WHITE}⚪{C_RESET}"
                            col1 = f"  {C_YELLOW}[{c1['index']:02}]{C_RESET} {c1['flag']} {C_WHITE}{c1['name']:<15}{C_RESET} {s1}"
                            if i + 1 < len(COUNTRIES):
                                c2 = COUNTRIES[i+1]
                                s2 = f"{C_GREEN}🟢{C_RESET}" if c2['in_port'] in existing_ports else f"{C_WHITE}⚪{C_RESET}"
                                col2 = f"  {C_YELLOW}[{c2['index']:02}]{C_RESET} {c2['flag']} {C_WHITE}{c2['name']:<15}{C_RESET} {s2}"
                                print(f"{col1:<45}{col2}")
                            else:
                                print(col1)
                        print(f"{C_BLUE}{'─' * 66}{C_RESET}")
                        print(f"  {C_RED}[0]{C_RESET} Go Back")
                        print(f"{C_BLUE}{'─' * 66}{C_RESET}")
                        inp = input(f"\nIndices to delete (e.g. 1-3,5): ").strip()
                        if inp in ("0", ""):
                            break
                        sel = parse_selection(inp, len(COUNTRIES))
                        if not sel:
                            print(f"{C_RED}❌ Invalid selection.{C_RESET}")
                            time.sleep(1.5)
                            continue
                        sel_countries = [COUNTRIES[i - 1] for i in sel]
                        if not confirm_proceed(f"Delete {len(sel_countries)} country config(s)?"):
                            time.sleep(1)
                            continue
                        show_banner()
                        print(f"{C_RED}⚡ Deleting selected countries...{C_RESET}")
                        print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                        removed = execute_deletion_for_countries(client, sel_countries, inbounds)
                        print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                        if removed > 0:
                            print(f"{C_YELLOW}⏳ Restarting Xray...{C_RESET}")
                            if client.restart_xray_service():
                                print(f"{C_GREEN}🎉 Done! {removed} config(s) removed.{C_RESET}")
                            else:
                                print(f"{C_RED}⚠️ Removed but auto-restart failed.{C_RESET}")
                        else:
                            print(f"{C_YELLOW}Nothing to remove.{C_RESET}")
                        input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
                        break
                    break
            continue


        success, inbounds = client.get_inbounds()
        if not success or not inbounds:
            print(f"{C_RED}❌ No active inbounds found to clone from.{C_RESET}")
            input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to return...")
            continue

        if choice == "1":
            existing_ports      = {ib.get('port') for ib in inbounds}
            allowed_codes       = ez_get_allowed_codes()
            available_countries = [c for c in COUNTRIES if c['in_port'] not in existing_ports and c['code'] in allowed_codes]
            restricted_count    = len([c for c in COUNTRIES if c['in_port'] not in existing_ports and c['code'] not in allowed_codes])
            if not available_countries:
                show_banner()
                print(f"{C_GREEN}🎉 All countries in your subscription are already configured!{C_RESET}")
                input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
                continue


            show_banner()
            print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ BATCH CREATE — SELECT INBOUND SOURCE ]{C_RESET}")
            xui_show_inbounds(inbounds)
            print(f"  {C_RED}[0]{C_RESET} Go Back")
            print(f"{C_BLUE}{'─' * 62}{C_RESET}")
            while True:
                port_input = input(f"\n{C_BOLD}Enter inbound port to clone from:{C_RESET} ").strip()
                if port_input == "0":
                    break
                try:
                    target_port = int(port_input)
                except ValueError:
                    print(f"{C_RED}❌ Invalid input.{C_RESET}")
                    time.sleep(1)
                    continue
                matched = next((ib for ib in inbounds if ib.get('port') == target_port), None)
                if not matched:
                    print(f"{C_RED}❌ Port {target_port} not found.{C_RESET}")
                    time.sleep(1)
                    continue


                show_banner()
                print(f"{C_YELLOW}📋 Summary:{C_RESET}")
                print(f"   Clone from port  : {C_CYAN}{target_port}{C_RESET}")
                print(f"   Countries to add : {C_WHITE}{len(available_countries)} (skipping already configured){C_RESET}")
                if restricted_count:
                    print(f"   {C_YELLOW}Restricted       : {restricted_count} location(s) not in your subscription.{C_RESET}")
                if not confirm_proceed("Start batch creation?"):
                    print(f"{C_YELLOW}Cancelled.{C_RESET}")
                    time.sleep(1)
                    break

                show_banner()
                print(f"{C_YELLOW}⚡ Batch creation in progress...{C_RESET}")
                print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                success_count = skip_count = 0
                for country in COUNTRIES:
                    if country['in_port'] in existing_ports:
                        print(f"  {C_YELLOW}⏭️  Skipped: {country['flag']} {country['name']} (port {country['in_port']} exists){C_RESET}")
                        skip_count += 1
                        continue
                    if country['code'] not in allowed_codes:
                        continue
                    if clone_inbound_for_country(client, matched, country):
                        success_count += 1
                print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                print(f"🔄 Done. {C_GREEN}{success_count}{C_RESET} created, {C_YELLOW}{skip_count}{C_RESET} skipped.")
                print(f"{C_YELLOW}⏳ Restarting Xray...{C_RESET}")
                if client.restart_xray_service():
                    print(f"{C_GREEN}🎉 All changes applied!{C_RESET}")
                else:
                    print(f"{C_RED}⚠️ Saved but auto-restart failed.{C_RESET}")
                input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
                break

        elif choice == "2":

            while True:
                existing_ports      = {ib.get('port') for ib in inbounds}
                allowed_codes       = ez_get_allowed_codes()
                all_available       = [c for c in COUNTRIES if c['in_port'] not in existing_ports]
                available_list      = sorted(all_available, key=lambda c: (ez_get_required_plan_label(c['code']) is not None))
                show_banner()
                print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ CUSTOM CREATE — SELECT COUNTRIES ]{C_RESET}")
                print(f"{C_BLUE}{'─' * 66}{C_RESET}")
                if not all_available:
                    print(f"  {C_GREEN}🎉 All 50 countries already configured!{C_RESET}")
                    print(f"{C_BLUE}{'─' * 66}{C_RESET}")
                    input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
                    break
                for idx, c in enumerate(available_list, 1):
                    req = ez_get_required_plan_label(c['code'])
                    if req:
                        print(f"  {idx:02d} - {c['flag']} {c['name']:<16}  {ez_format_plan_label(req)}")
                    else:
                        print(f"  {C_YELLOW}[{idx:02d}]{C_RESET} {c['flag']} {C_WHITE}{c['name']:<16}{C_RESET} {C_CYAN}In:{c['in_port']}{C_RESET}")
                print(f"{C_BLUE}{'─' * 66}{C_RESET}")
                print(f"  {C_RED}[0]{C_RESET} Go Back")
                print(f"{C_BLUE}{'─' * 66}{C_RESET}")
                country_input = input(f"\n{C_BOLD}Select country index(es) (e.g. 1 or 1-3,5):{C_RESET} ").strip()
                if country_input in ("0", ""):
                    break
                sel_indices = parse_selection(country_input, len(available_list))
                if not sel_indices:
                    print(f"{C_RED}❌ Invalid selection.{C_RESET}")
                    time.sleep(1.5)
                    continue
                selected_countries = [available_list[i - 1] for i in sel_indices]
                deployable   = [c for c in selected_countries if not ez_get_required_plan_label(c['code'])]
                restricted   = [c for c in selected_countries if ez_get_required_plan_label(c['code'])]
                if restricted:
                    for rc in restricted:
                        req = ez_get_required_plan_label(rc['code'])
                        print(f"{C_RED}[-] {rc['name']} requires a {ez_format_plan_label(req)} subscription.{C_RESET}")
                    time.sleep(2)
                if not deployable:
                    continue


                show_banner()
                print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ CUSTOM CREATE — SELECT INBOUND SOURCE ]{C_RESET}")
                xui_show_inbounds(inbounds)
                print(f"  {C_RED}[0]{C_RESET} Go Back")
                print(f"{C_BLUE}{'─' * 62}{C_RESET}")
                while True:
                    port_input = input(f"\n{C_BOLD}Enter inbound port to clone from:{C_RESET} ").strip()
                    if port_input == "0":
                        break
                    try:
                        target_port = int(port_input)
                    except ValueError:
                        print(f"{C_RED}❌ Invalid input.{C_RESET}")
                        time.sleep(1)
                        continue
                    matched = next((ib for ib in inbounds if ib.get('port') == target_port), None)
                    if not matched:
                        print(f"{C_RED}❌ Port {target_port} not found.{C_RESET}")
                        time.sleep(1)
                        continue


                    show_banner()
                    print(f"{C_YELLOW}📋 Summary:{C_RESET}")
                    print(f"   Clone from port  : {C_CYAN}{target_port}{C_RESET}")
                    print(f"   Countries        : {C_WHITE}{', '.join(c['name'] for c in deployable)}{C_RESET}")
                    if not confirm_proceed("Start creation?"):
                        print(f"{C_YELLOW}Cancelled.{C_RESET}")
                        time.sleep(1)
                        break

                    show_banner()
                    print(f"{C_YELLOW}⚡ Creating configs for selected countries...{C_RESET}")
                    print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                    count = sum(1 for sc in deployable if clone_inbound_for_country(client, matched, sc))
                    print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                    if count > 0:
                        print(f"{C_YELLOW}⏳ Restarting Xray...{C_RESET}")
                        if client.restart_xray_service():
                            print(f"{C_GREEN}🎉 Completed for {count} country(s)!{C_RESET}")
                        else:
                            print(f"{C_RED}⚠️ Saved but auto-restart failed.{C_RESET}")
                    else:
                        print(f"{C_RED}❌ All failed.{C_RESET}")
                    input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
                    break
                break



class PasarGuardAPI:
    def __init__(self, base_url, username, password, core_id=1):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.core_id  = core_id
        self.token    = None
        self.headers  = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    def login(self):
        url = f"{self.base_url}/api/admin/token"
        print(f"{C_YELLOW}[~] Logging in...{C_RESET}")
        try:
            r = requests.post(url, data={"username": self.username, "password": self.password},
                              headers=self.headers, timeout=15)
            if r.status_code == 200:
                data  = r.json()
                self.token = data.get("access_token")
                ttype = data.get("token_type", "Bearer")
                self.headers.update({
                    "Authorization": f"{ttype} {self.token}",
                    "Content-Type": "application/json"
                })
                print(f"{C_GREEN}[+] Login successful!{C_RESET}")
                return True
            elif r.status_code == 401:
                print(f"{C_RED}[-] Invalid username or password.{C_RESET}")
            else:
                print(f"{C_RED}[-] Login failed ({r.status_code}): {r.text}{C_RESET}")
            return False
        except requests.exceptions.ConnectionError:
            print(f"{C_RED}[-] Cannot connect to server.{C_RESET}")
            return False
        except Exception as e:
            print(f"{C_RED}[-] Error: {e}{C_RESET}")
            return False

    def get_core_config(self):
        url = f"{self.base_url}/api/core/{self.core_id}"
        try:
            r = requests.get(url, headers=self.headers, timeout=15)
            if r.status_code == 200:
                data = r.json()
                return data.get("config", data)
            print(f"{C_RED}[-] Error ({r.status_code}): {r.text}{C_RESET}")
            return None
        except Exception as e:
            print(f"{C_RED}[-] Exception: {e}{C_RESET}")
            return None

    def save_core_config(self, config: dict, restart_nodes: bool = True):
        url    = f"{self.base_url}/api/core/{self.core_id}"
        params = {"restart_nodes": str(restart_nodes).lower()}
        try:
            r = requests.put(url, json={"config": config}, params=params,
                             headers=self.headers, timeout=15)
            if r.status_code in [200, 201]:
                print(f"{C_GREEN}[+] Core config saved!{C_RESET}")
                return True
            print(f"{C_RED}[-] Save failed ({r.status_code}): {r.text}{C_RESET}")
            return False
        except Exception as e:
            print(f"{C_RED}[-] Exception: {e}{C_RESET}")
            return False

    def list_inbounds_raw(self):
        config = self.get_core_config()
        return config.get("inbounds", []) if config else []

    @staticmethod
    def _extract_outbound_endpoint(ob):
        settings = ob.get("settings", {}) or {}
        protocol = (ob.get("protocol") or "").lower()
        if "address" in settings and "port" in settings:
            return settings.get("address", "—"), str(settings.get("port", "?"))
        servers = settings.get("servers")
        if servers:
            return servers[0].get("address", "—"), str(servers[0].get("port", "?"))
        vnext = settings.get("vnext")
        if vnext:
            return vnext[0].get("address", "—"), str(vnext[0].get("port", "?"))
        peers = settings.get("peers")
        if peers:
            ep = peers[0].get("endpoint", "")
            if ":" in ep:
                addr, _, port = ep.rpartition(":")
                return addr, port
        if protocol in ("freedom", "blackhole", "dns", "loopback"):
            return "(direct)", "-"
        return "—", "?"

    def quick_remove_relay(self, inbound_tag: str):

        print(f"\n{C_YELLOW}[~] Removing relay '{inbound_tag}'...{C_RESET}")
        config = self.get_core_config()
        if config is None:
            print(f"{C_RED}[-] Could not fetch config.{C_RESET}")
            return False

        before = len(config.get("inbounds", []))
        config["inbounds"] = [ib for ib in config.get("inbounds", []) if ib.get("tag") != inbound_tag]
        print(f"{C_CYAN}[~] Inbound(s) removed: {before - len(config['inbounds'])}{C_RESET}")

        before = len(config.get("outbounds", []))
        config["outbounds"] = [ob for ob in config.get("outbounds", []) if ob.get("tag") != inbound_tag]
        print(f"{C_CYAN}[~] Outbound(s) removed: {before - len(config['outbounds'])}{C_RESET}")

        routing = config.get("routing", {})
        rules   = routing.get("rules", [])
        before  = len(rules)
        routing["rules"] = [r for r in rules
                            if not (inbound_tag in r.get("inboundTag", []) or r.get("outboundTag") == inbound_tag)]
        print(f"{C_CYAN}[~] Routing rule(s) removed: {before - len(routing['rules'])}{C_RESET}")

        if not self.save_core_config(config):
            print(f"{C_RED}[-] Failed to save core config.{C_RESET}")
            return False


        raw_hosts = self.get_hosts()
        if raw_hosts is None:
            print(f"{C_YELLOW}[!] Could not fetch hosts — skipping host removal.{C_RESET}")
            return True

        flat_hosts = self._flatten_hosts(raw_hosts)
        removed_h = 0
        
        for group_tag, h in flat_hosts:
            if h.get("inbound_tag") == inbound_tag or group_tag == inbound_tag:
                host_id = h.get("id")
                if host_id is not None:
                    if self.delete_host(host_id):
                        removed_h += 1
                else:
                    print(f"{C_YELLOW}[!] Host matched but has no 'id' field.{C_RESET}")
                    
        print(f"{C_CYAN}[~] Host(s) removed: {removed_h}{C_RESET}")

        if removed_h == 0:
            print(f"{C_YELLOW}[!] No host found with inbound_tag='{inbound_tag}' — nothing to remove.{C_RESET}")

        print(f"{C_GREEN}[+] Relay '{inbound_tag}' fully removed.{C_RESET}")
        return True

    def get_hosts(self):
        url = f"{self.base_url}/api/hosts"
        try:
            r = requests.get(url, headers=self.headers, timeout=15)
            if r.status_code == 200:
                return r.json()
            print(f"{C_RED}[-] Error fetching hosts ({r.status_code}): {r.text}{C_RESET}")
            return None
        except Exception as e:
            print(f"{C_RED}[-] Exception: {e}{C_RESET}")
            return None

    def save_hosts(self, hosts_data):
        url = f"{self.base_url}/api/hosts"
        try:
            r = requests.put(url, json=hosts_data, headers=self.headers, timeout=15)
            if r.status_code in [200, 201]:
                print(f"{C_GREEN}[+] Hosts saved!{C_RESET}")
                return True
            print(f"{C_RED}[-] Save hosts failed ({r.status_code}): {r.text}{C_RESET}")
            return False
        except Exception as e:
            print(f"{C_RED}[-] Exception: {e}{C_RESET}")
            return False
            
    def delete_host(self, host_id):
        url = f"{self.base_url}/api/host/{host_id}"
        try:
            r = requests.delete(url, headers=self.headers, timeout=15)
            if r.status_code in [200, 204]:
                return True
            print(f"{C_RED}[-] Delete host failed ({r.status_code}): {r.text}{C_RESET}")
            return False
        except Exception as e:
            print(f"{C_RED}[-] Exception: {e}{C_RESET}")
            return False

    def _flatten_hosts(self, data):
        flat = []
        if isinstance(data, dict):
            for group_tag, hosts in data.items():
                if isinstance(hosts, list):
                    for h in hosts:
                        flat.append((group_tag, h))
                elif isinstance(hosts, dict):
                    flat.append((group_tag, hosts))
        elif isinstance(data, list):
            for h in data:
                group_tag = h.get("inbound_tag") or h.get("tag") or h.get("inboundTag") or "—"
                flat.append((group_tag, h))
        return flat

    def clone_host(self, source_index: int, target_inbound_tag: str, new_remark: str):
        raw = self.get_hosts()
        if raw is None:
            print(f"{C_RED}[-] Could not fetch hosts.{C_RESET}")
            return False
        data = copy.deepcopy(raw)
        flat = self._flatten_hosts(data)
        if source_index < 1 or source_index > len(flat):
            print(f"{C_RED}[-] Invalid host index.{C_RESET}")
            return False
        _, source_host = flat[source_index - 1]
        new_host = copy.deepcopy(source_host)
        new_host.pop("id", None)
        new_host["remark"]      = new_remark
        new_host["inbound_tag"] = target_inbound_tag
        if "name" in new_host:
            new_host["name"] = new_remark
        if isinstance(data, list):
            data[:] = [h for h in data if not (
                h.get("inbound_tag") == target_inbound_tag and h.get("remark") == new_remark
            )]
            data.append(new_host)
        elif isinstance(data, dict):
            group = data.setdefault(target_inbound_tag, [])
            if not isinstance(group, list):
                group = [group]
                data[target_inbound_tag] = group
            data[target_inbound_tag] = [h for h in group if h.get("remark") != new_remark]
            data[target_inbound_tag].append(new_host)
        else:
            print(f"{C_RED}[-] Unexpected /api/hosts format.{C_RESET}")
            return False
        print(f"{C_GREEN}[+] Cloned host -> '{target_inbound_tag}' remark='{new_remark}'.{C_RESET}")
        return self.save_hosts(data)



def _parse_env_file(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _detect_url_from_pg_env():
    for path in ["/opt/pasarguard/.env", "/opt/PasarGuard/.env",
                 "/etc/pasarguard/.env", "/etc/PasarGuard/.env"]:
        if not os.path.isfile(path):
            continue
        try:
            env      = _parse_env_file(path)
            host     = env.get("UVICORN_HOST", "127.0.0.1").strip()
            port     = env.get("UVICORN_PORT", "8000").strip()
            certfile = env.get("UVICORN_SSL_CERTFILE", "").strip()
            connect_host = "127.0.0.1" if host in ("0.0.0.0", "") else host
            scheme       = "https" if certfile else "http"
            domain = ""
            if certfile:
                for part in certfile.replace("\\", "/").split("/"):
                    if "." in part and not part.endswith(".pem"):
                        domain = part
                        break
            url = f"{scheme}://{domain}:{port}" if domain else f"{scheme}://{connect_host}:{port}"
            print(f"{C_GREEN}[+] Detected panel URL: {url}{C_RESET}")
            return url
        except Exception as e:
            print(f"{C_YELLOW}[!] Could not parse {path}: {e}{C_RESET}")
    return ""


def pg_load_cached_creds():
    if not os.path.isfile(PG_CREDS_FILE):
        return None
    try:
        env = _parse_env_file(PG_CREDS_FILE)
        url, user, pw = env.get("URL",""), env.get("USER",""), env.get("PASS","")
        if url and user and pw:
            return url, user, pw
    except Exception:
        pass
    return None


def pg_save_creds(url, user, pw):
    try:
        import stat
        with open(PG_CREDS_FILE, "w") as f:
            f.write(f"URL={url}\nUSER={user}\nPASS={pw}\n")
        os.chmod(PG_CREDS_FILE, stat.S_IRUSR | stat.S_IWUSR)
        print(f"{C_GREEN}[+] Credentials saved.{C_RESET}")
    except Exception as e:
        print(f"{C_YELLOW}[!] Could not save credentials: {e}{C_RESET}")


def pg_resolve_credentials():
    import getpass
    cached = pg_load_cached_creds()
    if cached:
        url, user, pw = cached
        print(f"{C_GREEN}[+] Using saved credentials  URL={url}  user={user}{C_RESET}")
        return url, user, pw
    print(f"{C_YELLOW}[~] Detecting panel URL...{C_RESET}")
    detected_url = _detect_url_from_pg_env()
    if detected_url:
        print(f"  Panel URL : {detected_url}  (auto-detected)")
        if confirm_proceed(f"Is this the correct panel address? ({detected_url})"):
            url = detected_url
        else:
            url = input("  Panel URL (e.g. https://panel.example.com:8000): ").strip()
    else:
        url = input("  Panel URL (e.g. https://panel.example.com:8000): ").strip()
    user = input("  Admin username: ").strip()
    pw   = getpass.getpass("  Admin password: ")
    pg_save_creds(url, user, pw)
    return url, user, pw



def pg_show_inbounds(inbounds):

    print(f"{C_BLUE}{'─' * 72}{C_RESET}")
    print(f"  {C_BOLD}{'#':<4} {'Port':<8} {'Protocol':<12} {'Network':<10} {'Security':<10} Tag{C_RESET}")
    print(f"{C_BLUE}{'─' * 72}{C_RESET}")
    for i, ib in enumerate(inbounds, 1):
        tag      = ib.get("tag", "—")
        protocol = ib.get("protocol", "?")
        port     = str(ib.get("port", "?"))
        ss       = ib.get("streamSettings", {}) or {}
        network  = ss.get("network", "tcp")
        security = ss.get("security", "none")
        print(f"  {C_YELLOW}[{i}]{C_RESET}  {C_WHITE}{port:<8}{C_RESET}{C_CYAN}{protocol:<12}{C_RESET}"
              f"{C_RED}{network:<10}{C_RESET}{C_GREEN}{security:<10}{C_RESET}{tag}")
    print(f"{C_BLUE}{'─' * 72}{C_RESET}")


def pg_show_hosts(api: PasarGuardAPI):

    raw  = api.get_hosts()
    if raw is None:
        return None, []
    flat = api._flatten_hosts(raw)
    if not flat:
        print(f"{C_YELLOW}[i] No hosts found.{C_RESET}")
        return raw, []
    print(f"{C_BLUE}{'─' * 80}{C_RESET}")
    print(f"  {C_BOLD}{'#':<4} {'Inbound Tag':<25} {'Remark':<22} {'Address':<22} Port{C_RESET}")
    print(f"{C_BLUE}{'─' * 80}{C_RESET}")
    for i, (group_tag, h) in enumerate(flat, 1):
        remark  = str(h.get("remark") or h.get("name") or "—")
        address = str(h.get("address", "—"))
        port    = str(h.get("port", "?"))
        tag_str = str(group_tag)
        print(f"  {C_YELLOW}[{i}]{C_RESET}  {C_CYAN}{tag_str:<25}{C_RESET}"
              f"{C_WHITE}{remark:<22}{C_RESET}{C_GREEN}{address:<22}{C_RESET}{port}")
    print(f"{C_BLUE}{'─' * 80}{C_RESET}")
    return raw, flat


def pg_pick_inbound(api: PasarGuardAPI):

    inbounds = api.list_inbounds_raw()
    if not inbounds:
        print(f"{C_RED}[-] No inbounds available.{C_RESET}")
        return None
    print(f"\n{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ SELECT INBOUND TO CLONE FROM ]{C_RESET}")
    pg_show_inbounds(inbounds)
    print(f"  {C_RED}[0]{C_RESET} Go Back")
    print(f"{C_BLUE}{'─' * 72}{C_RESET}")
    while True:
        val = input(f"\n{C_BOLD}Enter inbound # :{C_RESET} ").strip()
        if val == "0":
            return None
        try:
            idx = int(val)
            if 1 <= idx <= len(inbounds):
                return inbounds[idx - 1]
            print(f"{C_RED}❌ Must be 1 – {len(inbounds)}.{C_RESET}")
        except ValueError:
            print(f"{C_RED}❌ Invalid number.{C_RESET}")


def pg_pick_host(api: PasarGuardAPI):

    print(f"\n{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ SELECT HOST TO CLONE FROM ]{C_RESET}")
    _, flat = pg_show_hosts(api)
    if not flat:
        return None
    print(f"  {C_RED}[0]{C_RESET} Go Back")
    print(f"{C_BLUE}{'─' * 80}{C_RESET}")
    while True:
        val = input(f"\n{C_BOLD}Enter host # :{C_RESET} ").strip()
        if val == "0":
            return None
        try:
            idx = int(val)
            if 1 <= idx <= len(flat):
                return idx
            print(f"{C_RED}❌ Must be 1 – {len(flat)}.{C_RESET}")
        except ValueError:
            print(f"{C_RED}❌ Invalid number.{C_RESET}")



def pg_clone_inbound_for_country(api: PasarGuardAPI, source_inbound: dict,
                                  country: dict, host_index: int):

    flag        = country.get('flag', '🌐')
    remark      = f"{flag} {country['name']}"
    inbound_tag = remark  

    config = api.get_core_config()
    if config is None:
        print(f"{C_RED}[-] Could not fetch core config.{C_RESET}")
        return False

    inbounds  = config.setdefault("inbounds", [])
    outbounds = config.setdefault("outbounds", [])


    inbounds[:]  = [ib for ib in inbounds
                    if ib.get("port") != country['in_port'] and ib.get("tag") != inbound_tag]
    outbounds[:] = [ob for ob in outbounds if ob.get("tag") != inbound_tag]


    new_inbound         = copy.deepcopy(source_inbound)
    new_inbound["port"] = country['in_port']
    new_inbound["tag"]  = inbound_tag
    inbounds.append(new_inbound)


    outbounds.append({
        "tag":      inbound_tag,
        "protocol": "socks",
        "settings": {"address": "127.0.0.1", "port": country['out_port']}
    })


    routing = config.setdefault("routing", {})
    rules   = routing.setdefault("rules", [])
    rules[:] = [r for r in rules
                if not (inbound_tag in r.get("inboundTag", []) or r.get("outboundTag") == inbound_tag)]
    rules.append({"type": "field", "inboundTag": [inbound_tag], "outboundTag": inbound_tag})

    if not api.save_core_config(config):
        print(f"{C_RED} ❌ Failed to save config for {remark}.{C_RESET}")
        return False


    clone_ok = api.clone_host(
        source_index=host_index,
        target_inbound_tag=inbound_tag,
        new_remark=remark
    )
    if clone_ok:
        print(f" {C_GREEN}✅ {remark}{C_RESET} | In:{C_CYAN}{country['in_port']}{C_RESET} ➔ Out:{C_YELLOW}{country['out_port']}{C_RESET}")
    else:
        print(f" {C_YELLOW}⚠️  {remark}{C_RESET} — inbound/outbound/routing OK but host clone failed.")
    return True


def pg_execute_deletion(api: PasarGuardAPI, selected_countries: list):

    removed = 0
    for country in selected_countries:
        flag        = country.get('flag', '🌐')
        inbound_tag = f"{flag} {country['name']}"
        ok = api.quick_remove_relay(inbound_tag)
        if ok:
            print(f" {C_RED}🗑️  Removed:{C_RESET} {inbound_tag}")
            removed += 1
        else:
            print(f" {C_YELLOW}⏭️  Nothing deleted for:{C_RESET} {inbound_tag}")
    return removed


def pg_get_configured_ports(api: PasarGuardAPI):
    return {ib.get("port") for ib in api.list_inbounds_raw() if ib.get("port") is not None}



def pg_check_node_configured(api: PasarGuardAPI, country_code: str):
    country     = next((c for c in COUNTRIES if c['code'] == country_code), None)
    if not country:
        return False
    flag        = country.get('flag', '🌐')
    inbound_tag = f"{flag} {country['name']}"
    config      = api.get_core_config()
    if not config:
        return False
    ib_exists = any(ib.get("tag") == inbound_tag for ib in config.get("inbounds", []))
    ob_exists = any(ob.get("tag") == inbound_tag for ob in config.get("outbounds", []))
    return ib_exists and ob_exists


def handle_pg_tsin_nodes(api: PasarGuardAPI):
    installed = get_installed_tsin_nodes()
    if not installed:
        show_banner()
        print(f"{C_YELLOW}📦 No T.Sin/EoTor nodes installed on this system.{C_RESET}")
        input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to return...")
        return

    unconfigured = sorted(
        [info for code, info in installed.items() if not pg_check_node_configured(api, code)],
        key=lambda x: x['out_port']
    )

    if not unconfigured:
        show_banner()
        print(f"{C_GREEN}🎉 All installed T.Sin/EoTor nodes are already configured!{C_RESET}")
        input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to return...")
        return

    while True:

        show_banner()
        print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ T.SIN / EOTOR — SELECT NODES TO SETUP ]{C_RESET}")
        print(f"{C_BLUE}{'─' * 66}{C_RESET}")
        for i, node in enumerate(unconfigured, 1):
            tag_label = f"{C_BOLD}{C_RED}[{node.get('tag_prefix', 'T.Sin')}]{C_RESET}"
            print(f"  {C_YELLOW}[{i:02}]{C_RESET} {tag_label} {node.get('flag','🌐')} {C_WHITE}{node['name']:<20}{C_RESET}  SOCKS Port: {C_CYAN}{node['out_port']}{C_RESET}")
        print(f"{C_BLUE}{'─' * 66}{C_RESET}")
        print(f"  {C_RED}[0]{C_RESET} Go Back")
        print(f"{C_BLUE}{'─' * 66}{C_RESET}")

        node_input = input(f"\n{C_BOLD}Select node(s) (e.g. 1 or 1-3,5):{C_RESET} ").strip()
        if node_input in ("0", ""):
            return
        selected_indices = parse_selection(node_input, len(unconfigured))
        if not selected_indices:
            print(f"{C_RED}❌ Invalid selection.{C_RESET}")
            time.sleep(1.5)
            continue
        selected_nodes = [unconfigured[i - 1] for i in selected_indices]


        show_banner()
        src_inbound = pg_pick_inbound(api)
        if src_inbound is None:
            continue


        show_banner()
        host_idx = pg_pick_host(api)
        if host_idx is None:
            continue


        show_banner()
        print(f"{C_YELLOW}📋 Summary:{C_RESET}")
        print(f"   Inbound to clone : {C_CYAN}{src_inbound.get('tag','?')} (port {src_inbound.get('port','?')}){C_RESET}")
        print(f"   Nodes to setup   : {C_WHITE}{', '.join(n['name'] for n in selected_nodes)}{C_RESET}")
        if not confirm_proceed("Start T.Sin setup?"):
            print(f"{C_YELLOW}Cancelled.{C_RESET}")
            time.sleep(1)
            continue


        show_banner()
        print(f"{C_YELLOW}⚡ Setting up T.Sin nodes on Pasargad...{C_RESET}")
        print(f"{C_BLUE}{'─' * 60}{C_RESET}")
        count = sum(1 for n in selected_nodes if pg_clone_inbound_for_country(api, src_inbound, n, host_idx))
        print(f"{C_BLUE}{'─' * 60}{C_RESET}")
        if count > 0:
            print(f"{C_GREEN}🎉 Setup completed for {count} node(s)!{C_RESET}")
        else:
            print(f"{C_RED}❌ Setup failed for all nodes.{C_RESET}")
        input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
        return



def handle_pg_flow():
    show_banner()
    print(f"{C_YELLOW}⏳ Connecting to Pasargad panel...{C_RESET}")
    PANEL_URL, USER, PASS = pg_resolve_credentials()
    api = PasarGuardAPI(base_url=PANEL_URL, username=USER, password=PASS, core_id=1)

    if not api.login():
        print(f"{C_RED}[!] Login failed.{C_RESET}")
        ans = input("  Delete saved credentials and retry? (yes/no): ").strip().lower()
        if ans == "yes":
            try:
                os.remove(PG_CREDS_FILE)
                print(f"{C_GREEN}[+] Credentials removed — please re-run.{C_RESET}")
            except Exception:
                pass
        return

    print(f"{C_GREEN}🟢 Login successful!{C_RESET}\n")
    time.sleep(1)

    while True:
        show_banner()
        print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ PASARGAD CONTROL PANEL ]{C_RESET}")
        print(f"{C_RED}{'=' * 45}{C_RESET}")
        print(f"  {C_YELLOW}[1]{C_RESET} Batch Create  (all 50 countries)")
        print(f"  {C_YELLOW}[2]{C_RESET} Custom Create (select countries)")
        print(f"  {C_YELLOW}[3]{C_RESET} T.Sin/EoTor Installed Nodes")
        print(f"  {C_YELLOW}[4]{C_RESET} Delete Configurations")
        print(f"  {C_RED}[0]{C_RESET} Exit")
        print(f"{C_RED}{'=' * 45}{C_RESET}")

        choice = input(f"\n{C_BOLD}Selected option:{C_RESET} ").strip()
        if choice == "0":
            break
        if choice not in ["1", "2", "3", "4"]:
            print(f"{C_RED}❌ Invalid option.{C_RESET}")
            time.sleep(1.5)
            continue


        if choice == "3":
            handle_pg_tsin_nodes(api)
            continue


        if choice == "4":
            while True:
                show_banner()
                print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ DELETE CONFIGS MENU ]{C_RESET}")
                print(f"{C_RED}{'=' * 45}{C_RESET}")
                print(f"  {C_YELLOW}[1]{C_RESET} Batch Delete  (all 50 countries)")
                print(f"  {C_YELLOW}[2]{C_RESET} Custom Delete (select countries)")
                print(f"  {C_RED}[0]{C_RESET} Go Back")
                print(f"{C_RED}{'=' * 45}{C_RESET}")
                del_choice = input(f"\n{C_BOLD}Selected Option:{C_RESET} ").strip()
                if del_choice == "0":
                    break
                if del_choice not in ["1", "2"]:
                    print(f"{C_RED}❌ Invalid option.{C_RESET}")
                    time.sleep(1.5)
                    continue

                if del_choice == "1":
                    show_banner()
                    print(f"{C_RED}⚠️  WARNING: Deletes ALL 50 country configs (inbound + SOCKS + routing + host).{C_RESET}")
                    if not confirm_proceed("Delete ALL 50 countries?"):
                        print(f"{C_YELLOW}Cancelled.{C_RESET}")
                        time.sleep(1.5)
                        continue
                    show_banner()
                    print(f"{C_YELLOW}⚡ Batch deletion in progress...{C_RESET}")
                    print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                    removed = pg_execute_deletion(api, COUNTRIES)
                    print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                    print(f"🗑️  Done. ({C_RED}{removed}{C_RESET} configs cleared)")
                    input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
                    break

                elif del_choice == "2":
                    while True:
                        existing_ports = pg_get_configured_ports(api)
                        show_banner()
                        print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ SELECT COUNTRIES TO DELETE ]{C_RESET}")
                        print(f"{C_BLUE}{'─' * 70}{C_RESET}")
                        for i in range(0, len(COUNTRIES), 2):
                            c1 = COUNTRIES[i]
                            s1 = f"{C_GREEN}🟢{C_RESET}" if c1['in_port'] in existing_ports else f"{C_WHITE}⚪{C_RESET}"
                            col1 = f"  {C_YELLOW}[{c1['index']:02}]{C_RESET} {c1['flag']} {C_WHITE}{c1['name']:<16}{C_RESET} {s1}"
                            if i + 1 < len(COUNTRIES):
                                c2 = COUNTRIES[i+1]
                                s2 = f"{C_GREEN}🟢{C_RESET}" if c2['in_port'] in existing_ports else f"{C_WHITE}⚪{C_RESET}"
                                col2 = f"  {C_YELLOW}[{c2['index']:02}]{C_RESET} {c2['flag']} {C_WHITE}{c2['name']:<16}{C_RESET} {s2}"
                                print(f"{col1:<48}{col2}")
                            else:
                                print(col1)
                        print(f"{C_BLUE}{'─' * 70}{C_RESET}")
                        print(f"  {C_RED}[0]{C_RESET} Go Back")
                        print(f"{C_BLUE}{'─' * 70}{C_RESET}")
                        inp = input(f"\nIndices to delete (e.g. 1-3,5): ").strip()
                        if inp in ("0", ""):
                            break
                        sel = parse_selection(inp, len(COUNTRIES))
                        if not sel:
                            print(f"{C_RED}❌ Invalid selection.{C_RESET}")
                            time.sleep(1.5)
                            continue
                        sel_countries = [COUNTRIES[i - 1] for i in sel]
                        if not confirm_proceed(f"Delete {len(sel_countries)} country config(s)?"):
                            time.sleep(1)
                            continue
                        show_banner()
                        print(f"{C_RED}⚡ Deleting...{C_RESET}")
                        print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                        removed = pg_execute_deletion(api, sel_countries)
                        print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                        if removed > 0:
                            print(f"{C_GREEN}🎉 {removed} config(s) removed!{C_RESET}")
                        else:
                            print(f"{C_YELLOW}Nothing to remove.{C_RESET}")
                        input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
                        break
                    break
            continue


        if choice == "1":
            existing_ports      = pg_get_configured_ports(api)
            allowed_codes       = ez_get_allowed_codes()
            available_countries = [c for c in COUNTRIES if c['in_port'] not in existing_ports and c['code'] in allowed_codes]
            restricted_count    = len([c for c in COUNTRIES if c['in_port'] not in existing_ports and c['code'] not in allowed_codes])
            if not available_countries:
                show_banner()
                print(f"{C_GREEN}🎉 All countries in your subscription are already configured!{C_RESET}")
                input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
                continue


            show_banner()
            src_inbound = pg_pick_inbound(api)
            if src_inbound is None:
                continue


            show_banner()
            host_idx = pg_pick_host(api)
            if host_idx is None:
                continue


            show_banner()
            print(f"{C_YELLOW}📋 Summary:{C_RESET}")
            print(f"   Inbound to clone : {C_CYAN}{src_inbound.get('tag','?')} (port {src_inbound.get('port','?')}){C_RESET}")
            print(f"   Countries to add : {C_WHITE}{len(available_countries)} (already configured will be skipped){C_RESET}")
            if restricted_count:
                print(f"   {C_YELLOW}Restricted       : {restricted_count} location(s) not in your subscription.{C_RESET}")
            if not confirm_proceed("Start batch creation?"):
                print(f"{C_YELLOW}Cancelled.{C_RESET}")
                time.sleep(1)
                continue


            show_banner()
            print(f"{C_YELLOW}⚡ Batch creation in progress...{C_RESET}")
            print(f"{C_BLUE}{'─' * 60}{C_RESET}")
            success_count = skip_count = 0
            for country in COUNTRIES:
                if country['in_port'] in existing_ports:
                    print(f"  {C_YELLOW}⏭️  Skipped:{C_RESET} {country['flag']} {country['name']} (port {country['in_port']} exists)")
                    skip_count += 1
                    continue
                if country['code'] not in allowed_codes:
                    continue
                if pg_clone_inbound_for_country(api, src_inbound, country, host_idx):
                    success_count += 1
            print(f"{C_BLUE}{'─' * 60}{C_RESET}")
            print(f"🔄 Done. {C_GREEN}{success_count}{C_RESET} created, {C_YELLOW}{skip_count}{C_RESET} skipped.")
            print(f"{C_GREEN}🎉 Batch complete!{C_RESET}")
            input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")


        elif choice == "2":
            while True:

                existing_ports      = pg_get_configured_ports(api)
                allowed_codes       = ez_get_allowed_codes()
                all_available       = [c for c in COUNTRIES if c['in_port'] not in existing_ports]
                available_list      = sorted(all_available, key=lambda c: (ez_get_required_plan_label(c['code']) is not None))
                show_banner()
                print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ CUSTOM CREATE — SELECT COUNTRIES ]{C_RESET}")
                print(f"{C_BLUE}{'─' * 66}{C_RESET}")
                if not all_available:
                    print(f"  {C_GREEN}🎉 All 50 countries already configured!{C_RESET}")
                    print(f"{C_BLUE}{'─' * 66}{C_RESET}")
                    input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
                    break
                for idx, c in enumerate(available_list, 1):
                    req = ez_get_required_plan_label(c['code'])
                    if req:
                        print(f"  {idx:02d} - {c['flag']} {c['name']:<16}  {ez_format_plan_label(req)}")
                    else:
                        print(f"  {C_YELLOW}[{idx:02d}]{C_RESET} {c['flag']} {C_WHITE}{c['name']:<16}{C_RESET} {C_CYAN}In:{c['in_port']}{C_RESET}")
                print(f"{C_BLUE}{'─' * 66}{C_RESET}")
                print(f"  {C_RED}[0]{C_RESET} Go Back")
                print(f"{C_BLUE}{'─' * 66}{C_RESET}")
                country_input = input(f"\n{C_BOLD}Select country index(es) (e.g. 1 or 1-3,5):{C_RESET} ").strip()
                if country_input in ("0", ""):
                    break
                sel_indices = parse_selection(country_input, len(available_list))
                if not sel_indices:
                    print(f"{C_RED}❌ Invalid selection.{C_RESET}")
                    time.sleep(1.5)
                    continue
                selected_countries = [available_list[i - 1] for i in sel_indices]
                deployable = [c for c in selected_countries if not ez_get_required_plan_label(c['code'])]
                restricted = [c for c in selected_countries if ez_get_required_plan_label(c['code'])]
                if restricted:
                    for rc in restricted:
                        req = ez_get_required_plan_label(rc['code'])
                        print(f"{C_RED}[-] {rc['name']} requires a {ez_format_plan_label(req)} subscription.{C_RESET}")
                    time.sleep(2)
                if not deployable:
                    continue


                show_banner()
                src_inbound = pg_pick_inbound(api)
                if src_inbound is None:
                    continue


                show_banner()
                host_idx = pg_pick_host(api)
                if host_idx is None:
                    continue


                show_banner()
                print(f"{C_YELLOW}📋 Summary:{C_RESET}")
                print(f"   Inbound to clone : {C_CYAN}{src_inbound.get('tag','?')} (port {src_inbound.get('port','?')}){C_RESET}")
                print(f"   Countries        : {C_WHITE}{', '.join(c['name'] for c in deployable)}{C_RESET}")
                if not confirm_proceed("Start creation?"):
                    print(f"{C_YELLOW}Cancelled.{C_RESET}")
                    time.sleep(1)
                    continue


                show_banner()
                print(f"{C_YELLOW}⚡ Creating configs...{C_RESET}")
                print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                count = sum(1 for sc in deployable
                            if pg_clone_inbound_for_country(api, src_inbound, sc, host_idx))
                print(f"{C_BLUE}{'─' * 60}{C_RESET}")
                if count > 0:
                    print(f"{C_GREEN}🎉 Completed for {count} country(s)!{C_RESET}")
                else:
                    print(f"{C_RED}❌ All failed.{C_RESET}")
                input(f"\nPress {C_BOLD}{C_WHITE}[Enter]{C_RESET} to continue...")
                break



def main():
    fetch_ez_license()

    installed_list = []
    

    if os.path.exists(DB_PATH) or os.path.exists('/usr/local/x-ui/x-ui'):
        installed_list.append("3X-UI")
        

    pg_paths = ["/opt/pasarguard", "/opt/PasarGuard", "/etc/pasarguard", "/etc/PasarGuard"]
    if any(os.path.exists(p) for p in pg_paths):
        installed_list.append("Pasargad")
        

    marzban_paths = ["/opt/marzban", "/etc/marzban", "/usr/local/bin/marzban"]
    if any(os.path.exists(p) for p in marzban_paths):
        installed_list.append("Marzban")


    if len(installed_list) == 1:
        detected_panel = installed_list[0]
        show_banner()
        print(f"{C_GREEN}🟢 Panel {detected_panel} detected! login...{C_RESET}")
        time.sleep(2)
        
        if detected_panel == "3X-UI":
            handle_3xui_flow()
        elif detected_panel == "Pasargad":
            handle_pg_flow()
        elif detected_panel == "Marzban":
            print(f"\n{C_YELLOW}⚠️ This module is under development.{C_RESET}")
            time.sleep(2)
            

        show_banner()
        print(f"{C_RED}Thank you for using EZ-Panel. Goodbye!{C_RESET}\n")
        sys.exit(0)


    while True:
        show_banner_with_panels()
        print(f"{C_RED}📌{C_RESET} {C_BOLD}{C_RED}[ SELECT SYSTEM PANEL MODULE ]{C_RESET}")
        print(f"{C_RED}{'=' * 55}{C_RESET}")
        print(f"  {C_YELLOW}[1]{C_RESET} 3X-UI Panel")
        print(f"  {C_YELLOW}[2]{C_RESET} Pasargad Panel")
        print(f"  {C_YELLOW}[3]{C_RESET} Marzban Panel          ({C_YELLOW}⏳ COMING SOON{C_RESET})")
        print(f"  {C_RED}[0]{C_RESET} Exit Program")
        print(f"{C_RED}{'=' * 55}{C_RESET}")

        panel_choice = input(f"\n{C_BOLD}Selected Option:{C_RESET} ").strip()

        if panel_choice == "0":
            show_banner()
            print(f"{C_RED}Thank you for using EZ-Panel. Goodbye!{C_RESET}\n")
            break
        elif panel_choice == "1":
            handle_3xui_flow()
        elif panel_choice == "2":
            handle_pg_flow()
        elif panel_choice == "3":
            print(f"\n{C_YELLOW}⚠️ This module is under development.{C_RESET}")
            time.sleep(2)
        else:
            print(f"\n{C_RED}❌ Invalid choice.{C_RESET}")
            time.sleep(1.5)


if __name__ == "__main__":
    main()
