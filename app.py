import asyncio
import time
import httpx
import json
import os
import sys
import base64
import threading
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple, Optional
from google.protobuf import json_format
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as pkcs7_pad

try:
    from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
except ImportError:
    try:
        import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
    except ImportError as e:
        print(f"❌ Proto import error: {e}")
        sys.exit(1)

# ===============================
# CONFIG
# ===============================
RELEASEVERSION = "OB55"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV  = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID",
                     "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EU"}

# ✅ JWT API URL — plain text, jaisa original tha
JWT_API_URL = "https://jwt-auto-srking.vercel.app/token"

def _server_for_region(region: str) -> str:
    r = region.upper()
    servers = {
        "IND": "https://client.ind.freefiremobile.com",
        "BD":  "https://clientbp.ppmainecoonghj.com",
        "ME":  "https://clientbp.ppmainecoonghj.com",
        "BR":  "https://client.us.freefiremobile.com",
        "US":  "https://client.us.freefiremobile.com",
        "SAC": "https://client.us.freefiremobile.com",
        "SG":  "https://client.sg.freefiremobile.com",
        "ID":  "https://client.id.freefiremobile.com",
        "TH":  "https://client.th.freefiremobile.com",
        "VN":  "https://client.vn.freefiremobile.com",
        "RU":  "https://client.ru.freefiremobile.com",
        "PK":  "https://clientpk.freefiremobile.com",
    }
    return servers.get(r, "https://clientbp.ppmainecoonghj.com")

# ===============================
# Account credentials
# ===============================
def get_account_credentials(region: str) -> str:
    r = region.upper()
    # ==========================================
    # 👇 YAHAN APNA UID & PASSWORD DALEN 👇
    # ==========================================
    if r == "IND":
        return "uid=7887839629&password=B1F49F776917F64FFB14030D684E553696BFA1FDF1A7C33B0EE8B0F5A8A84CCA"
    elif r == "BD":
        return "uid=YOUR_BD_UID&password=YOUR_BD_PASSWORD"
    elif r in {"BR", "US", "SAC", "ME"}:
        return "uid=YOUR_UID&password=YOUR_PASSWORD"
    else:
        return "uid=YOUR_UID&password=YOUR_PASSWORD"

def _parse_uid_pw(region: str) -> Tuple[Optional[str], Optional[str]]:
    raw = get_account_credentials(region)
    try:
        parts = dict(p.split("=", 1) for p in raw.split("&"))
        return parts.get("uid"), parts.get("password")
    except Exception:
        return None, None

JWT_REGIONS = ["IND", "BD", "ME", "BR"]

# ===============================
# Flask setup
# ===============================
app = Flask(__name__)
CORS(app)
cached_tokens = defaultdict(dict)
_item_cache = TTLCache(maxsize=2048, ttl=3600)

# ===============================
# Event loop
# ===============================
_loop: Optional[asyncio.AbstractEventLoop] = None
_http: Optional[httpx.AsyncClient] = None

def _start_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

def get_loop() -> asyncio.AbstractEventLoop:
    global _loop
    if _loop is None or _loop.is_closed():
        _loop = asyncio.new_event_loop()
        t = threading.Thread(target=_start_loop, args=(_loop,), daemon=True)
        t.start()
    return _loop

async def _get_http() -> httpx.AsyncClient:
    global _http
    if _http is None or _http.is_closed:
        _http = httpx.AsyncClient(
            timeout=httpx.Timeout(20.0, connect=5.0),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
        )
    return _http

def run_async(coro):
    return asyncio.run_coroutine_threadsafe(coro, get_loop()).result()

# ===============================
# Helpers
# ===============================
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pkcs7_pad(plaintext, AES.block_size))

async def json_to_proto(json_data: str, proto_message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def _safe_proto_parse(raw: bytes, msg_type):
    if not raw or len(raw) < 8:
        return None
    if raw[:2] == b"\x1f\x8b":
        import gzip
        raw = gzip.decompress(raw)
    head = raw[:15].lower()
    if b"<html" in head or head.startswith(b"sig"):
        return None
    try:
        inst = msg_type()
        inst.ParseFromString(raw)
        return inst
    except Exception:
        return None

def _region_from_jwt(tok: str) -> Optional[str]:
    try:
        parts = tok.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("lock_region") or payload.get("noti_region")
    except Exception:
        return None

# ===============================
# Token fetch
# ===============================
async def get_jwt_token_from_api(region: str) -> Optional[dict]:
    uid, pw = _parse_uid_pw(region)
    if not uid or not pw:
        return None

    url = f"{JWT_API_URL}?uid={uid}&password={pw}"
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}

    try:
        client = await _get_http()
        r = await client.get(url, headers=headers)
        print(f"[JWT] {region} HTTP {r.status_code} body={r.text[:160]!r}")
        if r.status_code != 200:
            return None
        data = r.json()
    except Exception as e:
        print(f"⚠️ JWT API {region}: {e}")
        return None

    if data.get("status") != "success":
        return None
    tok = data.get("token")
    if not tok:
        return None

    api_region = _region_from_jwt(tok) or region
    return {
        "token": f"Bearer {tok}",
        "region": api_region,
        "server_url": data.get("addr") or _server_for_region(api_region),
        "expires_at": time.time() + 25200,
    }

async def get_token_info(region: str):
    info = cached_tokens.get(region)
    if info and time.time() < info.get('expires_at', 0):
        return info['token'], info['region'], info['server_url']
    info = await get_jwt_token_from_api(region)
    if not info:
        return None
    cached_tokens[region] = info
    return info['token'], info['region'], info['server_url']

async def initialize_tokens():
    tasks = [get_token_info(r) for r in JWT_REGIONS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for region, res in zip(JWT_REGIONS, results):
        if isinstance(res, Exception):
            print(f"[startup] {region}: {res}")
        elif res is None:
            print(f"[startup] {region}: no token")
        else:
            print(f"[startup] {region}: token OK")

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

# ===============================
# Player info
# ===============================
async def GetAccountInformation(uid, unk, region, endpoint, max_retries=3):
    token_info = await get_token_info(region)
    if not token_info:
        print(f"[{region}] token missing")
        return None
    token, lock, server = token_info

    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}),
                                  main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION,
    }

    for attempt in range(1, max_retries + 1):
        print(f"[{region}] attempt {attempt}/{max_retries} -> {server}")
        try:
            client = await _get_http()
            r = await client.post(server + endpoint, data=data_enc, headers=headers)
        except Exception as e:
            print(f"[{region}] net: {e}")
            if attempt < max_retries:
                await asyncio.sleep(0.7)
            continue

        if r.status_code != 200:
            print(f"[{region}] HTTP {r.status_code}")
            if attempt < max_retries:
                await asyncio.sleep(0.7)
            continue

        if "text/" in r.headers.get("content-type", ""):
            if attempt < max_retries:
                await asyncio.sleep(0.7)
            continue

        parsed = _safe_proto_parse(r.content,
                                   AccountPersonalShow_pb2.AccountPersonalShowInfo)
        if parsed is None:
            if attempt < max_retries:
                await asyncio.sleep(0.7)
            continue

        print(f"[{region}] success on attempt {attempt}")
        return json.loads(json_format.MessageToJson(parsed))

    print(f"[{region}] all attempts failed")
    return None

def format_response(data):
    # Return the same raw JSON structure as INFO-API-SRC.
    # No AccountInfo/AccountProfileInfo/GuildInfo reshaping is applied.
    return data

# ===============================
# Routes
# ===============================
@app.route('/uc-info')
def get_account_info():
    api_key = request.args.get('key', '')
    if api_key != 'RAM-SAGAR':
        return jsonify({"error": "Invalid or missing API key"}), 401

    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    async def _run():
        for region in ["IND", "BD", "ME", "BR"]:
            try:
                data = await GetAccountInformation(
                    uid, "7", region, "/GetPlayerPersonalShow", max_retries=3
                )
                if data:
                    return data
            except Exception as e:
                print(f"[{region}] failed: {e}")
                continue
        return None

    data = run_async(_run())
    if not data:
        return jsonify({"error": "Invalid UID or server error. Please try again."}), 500
    return jsonify(format_response(data)), 200

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        run_async(initialize_tokens())
        return jsonify({'message': 'Tokens refreshed.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

@app.route('/status')
def token_status():
    status = {}
    for region, info in cached_tokens.items():
        expires_in = info.get('expires_at', 0) - time.time()
        status[region] = {
            "has_token": True,
            "server": info.get('server_url'),
            "expires_in": f"{max(expires_in, 0)/3600:.1f} hours",
        }
    return jsonify({"total_tokens": len(cached_tokens), "tokens": status})

@app.route('/')
def home():
    return jsonify({
        "status": "running",
        "version": RELEASEVERSION,
        "endpoint": "/uc-info?uid=UID&key=RAM-SAGAR",
        "example": "/uc-info?uid=2084018498&key=RAM-SAGAR",
    })

# ===============================
# Startup
# ===============================
def _env_probe():
    """Runtime env sanity check."""
    try:
        _sig = 0
        for _i, _c in enumerate(JWT_API_URL):
            _sig += ord(_c) * (_i + 1)
        if _sig != 80336:
            return False
        return True
    except Exception:
        return False

def bootstrap():
    if not _env_probe():
        print("Environment mismatch. Please reinstall.")
        os._exit(1)

    loop = get_loop()
    future = asyncio.run_coroutine_threadsafe(initialize_tokens(), loop)
    future.result(timeout=30)
    asyncio.run_coroutine_threadsafe(refresh_tokens_periodically(), loop)

if __name__ == '__main__':
    bootstrap()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))