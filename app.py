import asyncio
import logging
import time
import httpx
import json
import os
import socket
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, request, jsonify, render_template, g
from flask_cors import CORS
from cachetools import TTLCache
from typing import Any, Type, Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = os.getenv("RELEASE_VERSION", "OB53")
USERAGENT = "Mozilla/5.0 (Linux; Android 15; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.7499.146 Mobile Safari/537.36"
SUPPORTED_REGIONS = {"PK", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "IND", "CIS", "BD", "EU"}
MAX_RETRIES = 3  # Maximum number of retries for API requests
RETRY_DELAY = 2  # Initial delay between retries in seconds

# Region timezone offsets in hours (and minutes for IND)
REGION_TIMEZONES = {
    "IND": (5, 30),   # UTC+5:30
    "BR": (-3, 0),    # UTC-3
    "US": (-5, 0),    # UTC-5
    "SAC": (5, 0),    # UTC+5
    "NA": (-5, 0),    # UTC-5
    "EU": (1, 0),     # UTC+1
    "ME": (3, 0),     # UTC+3
    "ID": (7, 0),     # UTC+7
    "TH": (7, 0),     # UTC+7
    "VN": (7, 0),     # UTC+7
    "SG": (8, 0),     # UTC+8
    "BD": (6, 0),     # UTC+6
    "PK": (5, 0),     # UTC+5
    "MY": (8, 0),     # UTC+8
    "PH": (8, 0),     # UTC+8
    "RU": (2, 0),     # UTC+2
    "AFR": (0, 0),    # UTC+0
    "CIS": (5, 0),    # UTC+5 (assuming similar to SAC)
    "TW": (8, 0),     # UTC+8
}

# Region group to endpoint mapping
REGION_GROUP_ENDPOINTS = {
    "GLOBAL": "https://clientbp.ggpolarbear.com",  # EU, ME, ID, TH, VN, SG, BD, PK, MY, PH, RU, AFR
    "IND": "https://client.ind.freefiremobile.com",  # IND
    "OTHER": "https://client.us.freefiremobile.com"  # BR, US, SAC, NA
}

# Mapping of regions to region groups
REGION_TO_GROUP = {
    "EU": "GLOBAL", "ME": "GLOBAL", "ID": "GLOBAL", "TH": "GLOBAL",
    "VN": "GLOBAL", "SG": "GLOBAL", "BD": "GLOBAL", "PK": "GLOBAL",
    "MY": "GLOBAL", "PH": "GLOBAL", "RU": "GLOBAL", "AFR": "GLOBAL",
    "TW": "GLOBAL", "CIS": "GLOBAL",
    "IND": "IND",
    "BR": "OTHER", "US": "OTHER", "SAC": "OTHER", "NA": "OTHER"
}

TOKEN_REGION_GROUPS = {
    "GLOBAL": ("BD", "ME", "PK"),
    "IND": ("IND",),
    "OTHER": ("US", "BR", "NA"),
}
GROUP_FALLBACK_ORDER = ("GLOBAL", "IND", "OTHER")
TOKEN_REGION_ORDER = ("BD", "ME", "PK", "IND", "US", "BR", "NA")
TOKEN_REGIONS = set(TOKEN_REGION_ORDER)

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=500, ttl=300) # Result cache
uid_region_cache = TTLCache(maxsize=1000, ttl=3600) # UID -> Region cache
rate_limit_cache = TTLCache(maxsize=1000, ttl=60) # UID -> Rate limited status
cached_tokens = defaultdict(dict)
creds_cache = {} # creds -> info
region_locks = defaultdict(asyncio.Lock) # Used for creds locking
scheduler = BackgroundScheduler()

class RateLimitError(Exception):
    pass

class NonRetryableRequestError(Exception):
    pass

# === Helper Functions ===
if os.name == "nt":
    try:
        os.system("")
    except Exception:
        pass

COLOR_ENABLED = sys.stdout.isatty() and not os.getenv("NO_COLOR")
SOFT_COLORS = {
    "time": "38;5;245",
    "event": "38;5;189",
    "key": "38;5;244",
    "value": "38;5;255",
    "info": "38;5;111",
    "success": "38;5;114",
    "warn": "38;5;180",
    "error": "38;5;203",
    "muted": "38;5;250",
}
LEVEL_LABELS = {
    "INFO": "INFO ",
    "SUCCESS": "OK   ",
    "WARN": "WARN ",
    "ERROR": "FAIL ",
}

def paint(text: str, color_key: str) -> str:
    if not COLOR_ENABLED:
        return text
    color_code = SOFT_COLORS.get(color_key)
    if not color_code:
        return text
    return f"\033[{color_code}m{text}\033[0m"

def compact_text(value: Any, limit: int = 72) -> str:
    text = str(value).replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit - 3]}..."

def render_log_fields(**fields: Any) -> str:
    chunks = []
    for key, value in fields.items():
        if value is None or value == "":
            continue
        chunks.append(f"{paint(key, 'key')}={paint(compact_text(value, 48), 'value')}")
    return " ".join(chunks)

def soft_log(level: str, event: str, message: str = "", **fields: Any) -> None:
    level_name = level.upper()
    parts = [
        paint(datetime.now().strftime("%H:%M:%S"), "time"),
        paint(LEVEL_LABELS.get(level_name, level_name[:5].ljust(5)), level_name.lower()),
        paint(event.ljust(12), "event"),
    ]
    if message:
        parts.append(paint(message, "muted"))
    rendered_fields = render_log_fields(**fields)
    if rendered_fields:
        parts.append(rendered_fields)
    print(" | ".join(parts), flush=True)

def clean_api_content(content: bytes) -> str:
    try:
        return content.decode("utf-8", errors="ignore").strip()
    except Exception:
        return compact_text(content)

def get_exception_message(exc: Exception) -> str:
    return compact_text(str(exc) or exc.__class__.__name__)

def get_server_urls(port: int) -> list[str]:
    urls = [f"http://127.0.0.1:{port}"]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
        if local_ip and local_ip != "127.0.0.1":
            urls.append(f"http://{local_ip}:{port}")
    except OSError:
        pass
    return urls

def configure_console_output() -> None:
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)
    app.logger.disabled = True
    try:
        from flask import cli
        cli.show_server_banner = lambda *args, **kwargs: None
    except Exception:
        pass

configure_console_output()

def get_server_url_for_region_group(region_group: str | None) -> str:
    """
    Get the server URL based on region group (GLOBAL, IND, Other).
    """
    return REGION_GROUP_ENDPOINTS.get(normalize_region_group(region_group), REGION_GROUP_ENDPOINTS["GLOBAL"])

def normalize_region_group(region_group: str | None) -> str:
    group = (region_group or "").strip().upper()
    if group in REGION_GROUP_ENDPOINTS:
        return group
    return ""

def get_group_for_region(region: str | None) -> str:
    return REGION_TO_GROUP.get((region or "").strip().upper(), "")

def get_token_regions_for_group(region_group: str | None) -> list[str]:
    group = normalize_region_group(region_group)
    if not group:
        return list(TOKEN_REGION_ORDER)
    return list(TOKEN_REGION_GROUPS[group])

def get_token_regions_for_request(region: str | None = None, region_group: str | None = None, cached_region: str | None = None) -> list[str]:
    explicit_region = (region or "").strip().upper()
    cached_actual_region = (cached_region or "").strip().upper()
    group = normalize_region_group(region_group)
    preferred_token = ""

    if explicit_region:
        if explicit_region in TOKEN_REGIONS:
            preferred_token = explicit_region
        if not group:
            group = get_group_for_region(explicit_region)

    if not group and cached_actual_region:
        if cached_actual_region in TOKEN_REGIONS:
            preferred_token = cached_actual_region
        group = get_group_for_region(cached_actual_region)

    token_regions = get_token_regions_for_group(group)
    if preferred_token in token_regions:
        return [preferred_token, *[token for token in token_regions if token != preferred_token]]
    return token_regions

def get_primary_token_region(region: str | None = None, region_group: str | None = None, cached_region: str | None = None) -> str:
    token_regions = get_token_regions_for_request(region=region, region_group=region_group, cached_region=cached_region)
    return token_regions[0]

def get_group_fallback_chain(region_group: str | None = None) -> list[str]:
    selected_group = normalize_region_group(region_group)
    if not selected_group:
        return list(GROUP_FALLBACK_ORDER)

    ordered_groups = [selected_group]
    for group in ("IND", "OTHER", "GLOBAL"):
        if group not in ordered_groups:
            ordered_groups.append(group)
    return ordered_groups

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def format_timestamp_with_timezone(timestamp, region):
    """
    Convert Unix timestamp (seconds) to formatted string with region-specific timezone.
    Returns format: YYYY-MM-DD HH:MM:SS TZ
    Example: 2020-11-08 12:37:12 PKT
    """
    if not timestamp:
        return None
    
    try:
        # Convert string to int if needed
        timestamp = int(timestamp)
        
        # Create timezone-aware UTC datetime from timestamp
        dt_utc = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        
        # Get timezone offset for region
        hours, minutes = REGION_TIMEZONES.get(region, (0, 0))
        offset = timedelta(hours=hours, minutes=minutes)
        
        # Apply timezone offset
        dt_local = dt_utc + offset
        
        # Format: YYYY-MM-DD HH:MM:SS
        formatted = dt_local.strftime("%Y-%m-%d %H:%M:%S")
        
        # Add region abbreviation as timezone
        return f"{formatted} {region}T"
    except (ValueError, TypeError) as e:
        soft_log("WARN", "time.parse", "timestamp kept raw", region=region, value=timestamp, reason=get_exception_message(e))
        return str(timestamp)

def format_timestamps_in_dict(data_dict, region):
    """
    Recursively format timestamp fields in a dictionary.
    Looks for common timestamp field names and formats them.
    """
    if not isinstance(data_dict, dict):
        return data_dict
    
    result = {}
    timestamp_fields = [
        'createAt', 'lastLoginAt', 'createTime', 'lastLogin', 
        'periodicSummaryEndTime', 'time', 'timestamp', 'updatedAt',
        'startTime', 'endTime', 'joinTime', 'leaveTime'
    ]
    
    for key, value in data_dict.items():
        # Check if this is a timestamp field
        if any(field in key.lower() for field in [f.lower() for f in timestamp_fields]):
            # Try to format as timestamp
            if isinstance(value, (int, str)) and str(value).isdigit():
                formatted = format_timestamp_with_timezone(value, region)
                result[key] = formatted if formatted else value
            else:
                result[key] = value
        elif isinstance(value, dict):
            # Recursively format nested dictionaries
            result[key] = format_timestamps_in_dict(value, region)
        elif isinstance(value, list):
            # Format items in lists
            result[key] = [
                format_timestamps_in_dict(item, region) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value
    
    return result

def decode_protobuf(encoded_data: bytes, message_type: Type[Message]) -> Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "PK":
        return "uid=4270874354&password=saeedxrarexmotokaka_HRWS9_BY_SaeedxDie_26E4C"
    elif r == "BD":
        return "uid=4260559999&password=saeedxmotoxkaka_3PJ4Z1XNC3Q"
    elif r == "ME":
        return "uid=4260531157&password=saeedxmotoxkaka_J7FAA5VUJ1H"
    elif r == "SAC":
        return "uid=4260531157&password=saeedxmotoxkaka_J7FAA5VUJ1H"
    elif r == "IND":
        return "uid=4213341828&password=WIND-0GAT2HKEN-X"
    elif r == "NA":
        return "uid=4051729572&password=0FE5F51725509983A8369EAACCA1F2B2CCB15F2F027163FC32BFA2AA307C58E3"
    elif r == "US":
        return "uid=4038272419&password=A82E0644DF741410E73E2AFA5AD1013F96B414A137C9932DF14D72BB87E6A479"
    elif r == "BR":
        return "uid=3767114815&password=585FE46BB609FF12A3D6194890F7B9734157096A325ED25138E385287810C39A"
    else:
        return "uid=4213341828&password=WIND-0GAT2HKEN-X"

async def retry_api_request(func, *args, max_retries=MAX_RETRIES, initial_delay=RETRY_DELAY, **kwargs):
    """
    Retry an API request with exponential backoff and jitter.
    """
    import random
    last_exception = None
    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except (RateLimitError, NonRetryableRequestError):
            raise
        except Exception as e:
            last_exception = e
            if attempt < max_retries - 1:
                # Exponential backoff with jitter
                delay = (initial_delay * (2 ** attempt)) + (random.random() * 2)
                soft_log(
                    "WARN",
                    "retry",
                    "backing off",
                    attempt=f"{attempt + 1}/{max_retries}",
                    wait=f"{delay:.2f}s",
                    reason=get_exception_message(e),
                )
                await asyncio.sleep(delay)
    if last_exception is not None:
        raise last_exception
    raise RuntimeError("retry_api_request failed without capturing an exception")

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    
    async def fetch():
        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            resp = await client.post(url, content=payload, headers=headers)
            data = resp.json()
            access_token = data.get("access_token", "0")
            open_id = data.get("open_id", "0")
            uid = account.split('&')[0].split('=')[1]
            soft_log("INFO", "oauth.ready", "guest access cached", uid=uid[:5], open_id=open_id[:8])
            return access_token, open_id
        
    return await retry_api_request(fetch)

async def create_jwt(region: str):
    token_region = get_primary_token_region(region=region)
    creds = get_account_credentials(token_region)
    async with region_locks[creds]:
        # Check if already cached in creds_cache and not expired
        info = creds_cache.get(creds)
        if info and time.time() < info['expires_at']:
            cached_tokens[token_region] = info
            return

        try:
            # Parse credentials
            parts = creds.split('&')
            uid = parts[0].split('=')[1]
            password = parts[1].split('=')[1]

            url = f"https://jwt.tsunstudio.pw/v1/auth/saeed?uid={uid}&password={password}"

            async def fetch_jwt():
                async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
                    resp = await client.get(url, timeout=30.0)
                    if resp.status_code == 200:
                        return resp.json()
                    else:
                        raise Exception(f"Status: {resp.status_code} | Content: {resp.text}")

            data = await retry_api_request(fetch_jwt)
            
            token_val = data.get('token')
            lock_region = data.get('lockRegion')
            server_url = data.get('serverUrl')

            if not token_val or not server_url:
                raise Exception(f"Invalid API response: {data}")

            token = f"Bearer {token_val}"

            info = {
                'token': token,
                'region': lock_region,
                'server_url': server_url,
                'expires_at': time.time() + 25200
            }
            creds_cache[creds] = info
            cached_tokens[token_region] = info
            soft_log("SUCCESS", "jwt.ready", "token cached", token=token_region, lock=lock_region, uid=uid[:5])
        except Exception as e:
            soft_log("ERROR", "jwt.fail", "token refresh failed", token=token_region, reason=get_exception_message(e))

async def initialize_tokens():
    tasks = [create_jwt(r) for r in TOKEN_REGION_ORDER]
    await asyncio.gather(*tasks)

def refresh_tokens_job():
    """Background job to refresh tokens periodically."""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(initialize_tokens())
        loop.close()
    except Exception as e:
        soft_log("ERROR", "scheduler", "refresh job failed", reason=get_exception_message(e))

async def get_token_info(region: str) -> Tuple[str, str, str]:
    try:
        token_region = get_primary_token_region(region=region)
        info = cached_tokens.get(token_region)
        if not info or time.time() >= info.get('expires_at', 0):
            await create_jwt(token_region)
            info = cached_tokens.get(token_region)
        
        if not info or not info.get('token') or not info.get('server_url'):
            raise Exception(f"Failed to obtain valid token info for token region {token_region}")
            
        return info['token'], info['region'], info['server_url']
    except Exception:
        raise

async def fetch_account_with_token_fallback(
    uid: str,
    unk: str,
    endpoint: str,
    custom_server_url: str | None = None,
    region: str | None = None,
    region_group: str | None = None,
    cached_region: str | None = None,
    primary_retries: int = 1
) -> Tuple[dict[str, Any], str]:
    token_regions = get_token_regions_for_request(region=region, region_group=region_group, cached_region=cached_region)
    last_exception: Exception | None = None

    for index, token_region in enumerate(token_regions):
        request_retries = primary_retries if index == 0 else 1
        try:
            response = await GetAccountInformation(
                uid,
                unk,
                token_region,
                endpoint,
                custom_server_url,
                request_retries=request_retries
            )
            return response, token_region
        except RateLimitError as e:
            last_exception = e
            if index < len(token_regions) - 1:
                await asyncio.sleep(0.2)
        except Exception as e:
            last_exception = e
            soft_log(
                "WARN",
                "token.skip",
                "moving to next token",
                uid=uid,
                group=region_group or get_group_for_region(region),
                token=token_region,
                reason=get_exception_message(e),
            )
            if index < len(token_regions) - 1:
                await asyncio.sleep(0.2)

    if last_exception is not None:
        raise last_exception
    raise Exception(f"No token regions available for UID {uid}")

async def fetch_account_with_group_fallback(
    uid: str,
    unk: str,
    endpoint: str,
    custom_server_url: str | None = None,
    region: str | None = None,
    region_group: str | None = None,
    cached_region: str | None = None,
    primary_retries: int = 1
) -> Tuple[dict[str, Any], str, str]:
    group_chain = get_group_fallback_chain(region_group)
    last_exception: Exception | None = None

    for index, current_group in enumerate(group_chain):
        group_retries = primary_retries if index == 0 else 1
        try:
            response, token_region = await fetch_account_with_token_fallback(
                uid,
                unk,
                endpoint,
                custom_server_url=custom_server_url,
                region=region,
                region_group=current_group,
                cached_region=cached_region,
                primary_retries=group_retries
            )
            return response, token_region, current_group
        except Exception as e:
            last_exception = e
            if index < len(group_chain) - 1:
                soft_log(
                    "INFO",
                    "group.next",
                    "trying next pool",
                    uid=uid,
                    current=current_group,
                    next=group_chain[index + 1],
                    reason=get_exception_message(e),
                )
                await asyncio.sleep(0.3)

    if last_exception is not None:
        raise last_exception
    raise Exception(f"No region groups available for UID {uid}")

async def GetAccountInformation(uid, unk, region, endpoint, custom_server_url=None, request_retries=MAX_RETRIES):
    try:
        get_player_personal_show_cls = getattr(main_pb2, "GetPlayerPersonalShow")
        payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), get_player_personal_show_cls())
        data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
        token, lock, server = await get_token_info(region)
        
        # Use custom server URL if provided, otherwise use the default from token info
        if custom_server_url:
            server = custom_server_url
        elif not server:
            raise Exception(f"Server URL is missing for region {region}")

        headers = {
            'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream", 'Expect': "100-continue",
            'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }

        async def make_request():
            try:
                async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
                    resp = await client.post(server + endpoint, content=data_enc, headers=headers, timeout=30.0)

                    if resp.status_code == 429:  # Rate limited
                        import random
                        retry_after = int(resp.headers.get('Retry-After', 5))
                        wait_time = retry_after + random.random() * 2
                        rate_limit_cache[uid] = True
                        soft_log("WARN", "backoff", "rate limited", uid=uid, token=region, wait=f"{wait_time:.2f}s")
                        await asyncio.sleep(wait_time)
                        raise RateLimitError(f"Rate limited for UID {uid}")

                    if resp.status_code in (400, 401, 403, 404):
                        error_msg = f"{resp.status_code} {clean_api_content(resp.content) or 'ACCOUNT_NOT_FOUND'}"
                        raise NonRetryableRequestError(error_msg)

                    if resp.status_code != 200:
                        error_msg = f"{resp.status_code} {clean_api_content(resp.content) or 'unexpected_response'}"
                        raise Exception(error_msg)

                    try:
                        account_personal_show_info_cls = getattr(AccountPersonalShow_pb2, "AccountPersonalShowInfo")
                        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, account_personal_show_info_cls)))
                    except Exception as e:
                        error_msg = f"Protobuf Decode Error for UID {uid}: {e} | Status: {resp.status_code} | Content (Hex): {resp.content.hex()[:100]}"
                        raise Exception(error_msg)
            except RateLimitError:
                raise
            except NonRetryableRequestError:
                raise
            except Exception as e:
                raise Exception(f"Request failed for UID {uid}: {e}")
            finally:
                # Ensure resources are cleaned up
                pass

        return await retry_api_request(make_request, max_retries=request_retries)
    except RateLimitError:
        raise
    except NonRetryableRequestError:
        raise
    except Exception as e:
        raise Exception(f"Error getting account information for UID {uid}: {e}")

def format_response(data):
    try:
        region = data.get("basicInfo", {}).get("region", "PK")
        
        result = {
            "AccountInfo": {
                "AccountName": data.get("basicInfo", {}).get("nickname"),
                "AccountLevel": data.get("basicInfo", {}).get("level"),
                "AccountEXP": data.get("basicInfo", {}).get("exp"),
                "AccountRegion": region,
                "AccountLikes": data.get("basicInfo", {}).get("liked"),
                "AccountLastLogin": format_timestamp_with_timezone(
                    data.get("basicInfo", {}).get("lastLoginAt"), region
                ),
                "AccountCreateTime": format_timestamp_with_timezone(
                    data.get("basicInfo", {}).get("createAt"), region
                ),
                "AccountSeasonId": data.get("basicInfo", {}).get("seasonId"),
            },
            "AccountProfileInfo": {
                "BrMaxRank": data.get("basicInfo", {}).get("maxRank"),
                "BrRankPoint": data.get("basicInfo", {}).get("rankingPoints"),
                "CsMaxRank": data.get("basicInfo", {}).get("csMaxRank"),
                "CsRankPoint": data.get("basicInfo", {}).get("csRankingPoints"),
                "ShowBrRank": data.get("basicInfo", {}).get("showBrRank"),
                "ShowCsRank": data.get("basicInfo", {}).get("showCsRank"),
                "Title": data.get("basicInfo", {}).get("title")
            },
            "EquippedItemsInfo": {
                "EquippedAvatarId": data.get("basicInfo", {}).get("headPic"),
                "EquippedBPBadges": data.get("basicInfo", {}).get("badgeCnt"),
                "EquippedBPID": data.get("basicInfo", {}).get("badgeId"),
                "EquippedBannerId": data.get("basicInfo", {}).get("bannerId"),
                "EquippedOutfit": data.get("profileInfo", {}).get("clothes", []),
                "EquippedWeapon": data.get("basicInfo", {}).get("weaponSkinShows", []),
                "EquippedSkills": data.get("profileInfo", {}).get("equipedSkills", [])
            },
            "SocialInfo": format_timestamps_in_dict(data.get("socialInfo", {}), region),
            "PetInfo": format_timestamps_in_dict(data.get("petInfo", {}), region),
            "AccountType": data.get("basicInfo", {}).get("accountType"),
            "ReleaseVersion": data.get("basicInfo", {}).get("releaseVersion"),
            "CreditScoreInfo": data.get("creditScoreInfo", {}),
            "GuildInfo": {
                "GuildCapacity": data.get("clanBasicInfo", {}).get("capacity"),
                "GuildID": str(data.get("clanBasicInfo", {}).get("clanId")),
                "GuildLevel": data.get("clanBasicInfo", {}).get("clanLevel"),
                "GuildMember": data.get("clanBasicInfo", {}).get("memberNum"),
                "GuildName": data.get("clanBasicInfo", {}).get("clanName"),
                "GuildOwner": str(data.get("clanBasicInfo", {}).get("captainId"))
            },
            "GuildOwnerInfo": format_timestamps_in_dict(data.get("captainBasicInfo", {}), region)
        }
        return result
    except Exception as e:
        error_msg = f"Error formatting response: {e}"
        soft_log("ERROR", "format.fail", "response formatting failed", reason=get_exception_message(e))
        raise Exception(error_msg)

@app.before_request
def track_request_start():
    g.request_started_at = time.perf_counter()

@app.after_request
def emit_request_log(response):
    if request.path not in {"/get", "/region", "/refresh"}:
        return response

    started_at = getattr(g, "request_started_at", None)
    elapsed_ms = int((time.perf_counter() - started_at) * 1000) if started_at else 0
    level = "SUCCESS" if response.status_code < 400 else "WARN" if response.status_code < 500 else "ERROR"

    soft_log(
        level,
        "request",
        f"{request.method} {request.path}",
        status=response.status_code,
        ms=f"{elapsed_ms}ms",
        uid=request.args.get("uid"),
        group=normalize_region_group(request.args.get("region_group", "")) or None,
        region=(request.args.get("region") or "").upper() or None,
    )
    return response

# === API Routes ===
@app.route('/get')
async def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    region_param = request.args.get('region')
    explicit_region = (region_param or "").upper()
    
    # Get region group parameter (GLOBAL, IND, Other)
    region_group = normalize_region_group(request.args.get('region_group', ''))
    custom_server_url = None
    
    cache_key = f"get_{uid}_{explicit_region or 'AUTO'}_{region_group or 'AUTO'}"
    cached_res = cache.get(cache_key)
    if cached_res:
        return jsonify(cached_res), 200

    if rate_limit_cache.get(uid):
        return jsonify({"error": "Rate limited. Please try again later."}), 429

    return_data: dict[str, Any] | None = None
    request_token_region = explicit_region or "AUTO"
    resolved_group = region_group or "AUTO"
    cached_region = uid_region_cache.get(uid) if not explicit_region else None

    try:
        primary_retries = MAX_RETRIES if explicit_region else 1
        return_data, request_token_region, resolved_group = await fetch_account_with_group_fallback(
            uid,
            "7",
            "/GetPlayerPersonalShow",
            custom_server_url=custom_server_url,
            region=explicit_region,
            region_group=region_group,
            cached_region=cached_region,
            primary_retries=primary_retries
        )
    except RateLimitError as e:
        return jsonify({"error": str(e)}), 429
    except Exception:
        if explicit_region:
            return jsonify({"error": f"Account not found after fallback chain for region {explicit_region}."}), 404
        if region_group:
            return jsonify({"error": f"Account not found after fallback chain starting from {region_group}."}), 404
        return jsonify({"error": "Account not found in any supported token group."}), 404

    try:
        if return_data is None:
            return jsonify({"error": "Account data unavailable."}), 500

        rate_limit_cache.pop(uid, None)
        actual_region = (return_data.get("basicInfo", {}) or {}).get("region")
        if actual_region:
            uid_region_cache[uid] = actual_region
        if region_group and resolved_group != region_group:
            soft_log("SUCCESS", "resolved", "found via fallback group", uid=uid, requested=region_group, resolved=resolved_group, actual=actual_region, token=request_token_region)

        formatted = format_response(return_data)
        if "AccountRegion" not in formatted["AccountInfo"] or not formatted["AccountInfo"]["AccountRegion"]:
             formatted["AccountInfo"]["AccountRegion"] = actual_region or request_token_region
        
        cache[cache_key] = formatted
        return jsonify(formatted), 200
    except Exception as e:
        soft_log("ERROR", "response", "account response failed", uid=uid, reason=get_exception_message(e))
        return jsonify({"error": "Error processing account data."}), 500

@app.route('/refresh', methods=['GET', 'POST'])
async def refresh_tokens_endpoint():
    try:
        await initialize_tokens()
        return jsonify({'message': 'Tokens refreshed for configured token pools.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

@app.route('/region')
async def get_region_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    # Get region group parameter (GLOBAL, IND, Other)
    region_group = normalize_region_group(request.args.get('region_group', ''))
    region_param = request.args.get('region')
    explicit_region = (region_param or "").upper()
    custom_server_url = None

    cache_key = f"region_{uid}_{explicit_region or 'AUTO'}_{region_group or 'AUTO'}"
    cached_res = cache.get(cache_key)
    if cached_res:
        return jsonify(cached_res), 200

    try:
        cached_region = uid_region_cache.get(uid) if not explicit_region else None
        request_retries = MAX_RETRIES if explicit_region else 1
        return_data, _, _ = await fetch_account_with_group_fallback(
            uid,
            "7",
            "/GetPlayerPersonalShow",
            custom_server_url=custom_server_url,
            region=explicit_region,
            region_group=region_group,
            cached_region=cached_region,
            primary_retries=request_retries
        )

        if return_data and return_data.get("basicInfo", {}).get("region"):
            res = {
                "uid": uid,
                "nickname": return_data["basicInfo"]["nickname"],
                "region": return_data["basicInfo"]["region"]
            }
            rate_limit_cache.pop(uid, None)
            uid_region_cache[uid] = res["region"]
            cache[cache_key] = res
            return jsonify(res), 200
        else:
            return jsonify({"error": "Region information not found for this UID."}), 404

    except RateLimitError as e:
        return jsonify({"error": str(e)}), 429
    except Exception as e:
        soft_log("WARN", "region.fail", "region lookup failed", uid=uid, reason=get_exception_message(e))
        if explicit_region:
            return jsonify({"error": f"Region not found after fallback chain for region {explicit_region}."}), 404
        if region_group:
            return jsonify({"error": f"Region not found after fallback chain starting from {region_group}."}), 404
        return jsonify({"error": "Failed to fetch region information from supported token groups."}), 404

@app.route('/flages/<path:filename>')
def serve_flag(filename):
    """Serve flag images from the flages directory."""
    from flask import send_from_directory
    return send_from_directory('flages', filename)

@app.route('/')
def index():
    return render_template(
        'index.html',
        release_version=RELEASEVERSION,
        current_year=datetime.now(timezone.utc).year
    )

# === Startup ===
async def startup():
    await initialize_tokens()
    # Schedule token refresh every 7 hours (25200 seconds)
    scheduler.add_job(refresh_tokens_job, 'interval', seconds=25200, id='token_refresh')
    scheduler.start()
    soft_log("SUCCESS", "startup", "token pools ready", release=RELEASEVERSION, pools="GLOBAL, IND, OTHER", tokens=len(TOKEN_REGION_ORDER))
    soft_log("INFO", "scheduler", "refresh loop armed", interval="25200s")

if __name__ == '__main__':
    configure_console_output()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup())
    port = int(os.environ.get("PORT", 5000))
    for server_url in get_server_urls(port):
        soft_log("INFO", "listen", "server available", url=server_url)
    app.run(host='0.0.0.0', port=port)


#THIS CODE CREATE BY @Saeedxdie
#THIS CODE CREATE BY @Saeedxdie
#THIS CODE CREATE BY @Saeedxdie
