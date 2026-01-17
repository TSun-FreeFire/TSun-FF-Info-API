import asyncio
import time
import httpx
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB52"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)"
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

# === Helper Functions ===
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
        
        # Create datetime from UTC timestamp
        dt_utc = datetime.utcfromtimestamp(timestamp)
        
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
        print(f"Error formatting timestamp {timestamp} for region {region}: {e}", flush=True)
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

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
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
        except Exception as e:
            last_exception = e
            if attempt < max_retries - 1:
                # Exponential backoff with jitter
                delay = (initial_delay * (2 ** attempt)) + (random.random() * 2)
                print(f"API request failed (attempt {attempt + 1}/{max_retries}). Retrying in {delay:.2f} seconds... Error: {repr(e)}", flush=True)
                await asyncio.sleep(delay)
    raise last_exception

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    
    async def fetch():
        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            data = resp.json()
            access_token = data.get("access_token", "0")
            open_id = data.get("open_id", "0")
            uid = account.split('&')[0].split('=')[1]
            print(f"Uid: {uid[:5]} Access Token: {access_token[:8]}...", flush=True)
            return access_token, open_id
        
    return await retry_api_request(fetch)

async def create_jwt(region: str):
    creds = get_account_credentials(region)
    async with region_locks[creds]:
        # Check if already cached in creds_cache and not expired
        info = creds_cache.get(creds)
        if info and time.time() < info['expires_at']:
            cached_tokens[region] = info
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
            print(f"uid: {uid[:5]}, region= {lock_region}, token= {token[:30]}...", flush=True)

            info = {
                'token': token,
                'region': lock_region,
                'server_url': server_url,
                'expires_at': time.time() + 25200
            }
            creds_cache[creds] = info
            cached_tokens[region] = info
        except Exception as e:
            print(f"Error in create_jwt for {region}: {repr(e)}", flush=True)

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

def refresh_tokens_job():
    """Background job to refresh tokens periodically."""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(initialize_tokens())
        loop.close()
    except Exception as e:
        print(f"Error in refresh_tokens_job: {e}", flush=True)

async def get_token_info(region: str) -> Tuple[str, str, str]:
    try:
        info = cached_tokens.get(region)
        if not info or time.time() >= info.get('expires_at', 0):
            await create_jwt(region)
            info = cached_tokens.get(region)
        
        if not info or not info.get('token') or not info.get('server_url'):
            raise Exception(f"Failed to obtain valid token info for region {region}")
            
        return info['token'], info['region'], info['server_url']
    except Exception as e:
        print(f"Error getting token info for region {region}: {repr(e)}", flush=True)
        raise

async def GetAccountInformation(uid, unk, region, endpoint):
    try:
        payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
        data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
        token, lock, server = await get_token_info(region)
        if not server:
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
                    resp = await client.post(server + endpoint, data=data_enc, headers=headers, timeout=30.0)

                    if resp.status_code == 429:  # Rate limited
                        import random
                        retry_after = int(resp.headers.get('Retry-After', 5))
                        wait_time = retry_after + random.random() * 2
                        print(f"Rate limited for UID {uid}. Waiting {wait_time:.2f}s...", flush=True)
                        rate_limit_cache[uid] = True
                        await asyncio.sleep(wait_time)
                        raise RateLimitError(f"Rate limited for UID {uid}")

                    if resp.status_code != 200:
                        error_msg = f"API Error: {resp.status_code} | Content: {resp.content[:200]}"
                        print(error_msg, flush=True)
                        raise Exception(error_msg)

                    try:
                        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))
                    except Exception as e:
                        error_msg = f"Protobuf Decode Error for UID {uid}: {e} | Status: {resp.status_code} | Content (Hex): {resp.content.hex()[:100]}"
                        print(error_msg, flush=True)
                        raise Exception(error_msg)
            except Exception as e:
                error_msg = f"Request failed for UID {uid}: {e}"
                print(error_msg, flush=True)
                raise Exception(error_msg)
            finally:
                # Ensure resources are cleaned up
                pass

        return await retry_api_request(make_request)
    except Exception as e:
        error_msg = f"Error getting account information for UID {uid}: {e}"
        print(error_msg, flush=True)
        raise Exception(error_msg)

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
        print(error_msg, flush=True)
        raise Exception(error_msg)

# === API Routes ===
@app.route('/get')
async def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    region_param = request.args.get('region')
    region = (region_param or "PK").upper()
    
    cache_key = f"get_{uid}_{region}"
    cached_res = cache.get(cache_key)
    if cached_res:
        return jsonify(cached_res), 200

    if rate_limit_cache.get(uid):
        return jsonify({"error": "Rate limited. Please try again later."}), 429

    try:
        # Check UID region cache
        if not region_param:
            cached_region = uid_region_cache.get(uid)
            if cached_region:
                region = cached_region

        # Try primary region
        return_data = await GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
    except RateLimitError as e:
        return jsonify({"error": str(e)}), 429
    except Exception:
        # If failed and no region specified, try auto-detection
        if not region_param:
            found = False
            # Prioritize common regions
            for r in ["IND", "BR", "US", "SAC", "NA", "SG", "ID", "VN", "TH", "ME", "RU", "EU", "BD"]:
                if r == region: continue
                try:
                    # Use fewer retries for auto-detection to avoid triggering more rate limits
                    return_data = await retry_api_request(
                        GetAccountInformation, uid, "7", r, "/GetPlayerPersonalShow",
                        max_retries=1 
                    )
                    found = True
                    region = r # Update region for response
                    uid_region_cache[uid] = r # Cache detected region
                    break
                except RateLimitError:
                    # If we hit a rate limit during auto-detection, stop immediately
                    return jsonify({"error": f"Rate limited during auto-detection for UID {uid}."}), 429
                except Exception:
                    await asyncio.sleep(0.5) # Small delay between region checks
                    continue

            if not found:
                return jsonify({"error": "Account not found in any region."}), 404
        else:
            return jsonify({"error": f"Account not found in region {region}."}), 404

    try:
        formatted = format_response(return_data)
        if "AccountRegion" not in formatted["AccountInfo"] or not formatted["AccountInfo"]["AccountRegion"]:
             formatted["AccountInfo"]["AccountRegion"] = region
        
        cache[cache_key] = formatted
        return jsonify(formatted), 200
    except Exception as e:
        print(f"Error formatting response: {e}", flush=True)
        return jsonify({"error": "Error processing account data."}), 500

@app.route('/refresh', methods=['GET', 'POST'])
async def refresh_tokens_endpoint():
    try:
        await initialize_tokens()
        return jsonify({'message': 'Tokens refreshed for all regions.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

@app.route('/region')
async def get_region_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    cache_key = f"region_{uid}"
    cached_res = cache.get(cache_key)
    if cached_res:
        return jsonify(cached_res), 200

    try:
        # Check UID region cache
        cached_region = uid_region_cache.get(uid)
        region = cached_region or request.args.get('region', 'PK').upper()

        return_data = await GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")

        if return_data and return_data.get("basicInfo", {}).get("region"):
            res = {
                "uid": uid,
                "nickname": return_data["basicInfo"]["nickname"],
                "region": return_data["basicInfo"]["region"]
            }
            uid_region_cache[uid] = res["region"]
            cache[cache_key] = res
            return jsonify(res), 200
        else:
            return jsonify({"error": "Region information not found for this UID."}), 404

    except Exception as e:
        print(f"Error fetching region for UID {uid}: {e}", flush=True)
        return jsonify({"error": f"Failed to fetch region information: {e}"}), 500

@app.route('/flages/<path:filename>')
def serve_flag(filename):
    """Serve flag images from the flages directory."""
    from flask import send_from_directory
    return send_from_directory('flages', filename)

@app.route('/')
def index():
    return render_template('index.html')

# === Startup ===
async def startup():
    await initialize_tokens()
    # Schedule token refresh every 7 hours (25200 seconds)
    scheduler.add_job(refresh_tokens_job, 'interval', seconds=25200, id='token_refresh')
    scheduler.start()
    print("Token refresh scheduler started.", flush=True)

if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup())
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))


#THIS CODE CREATE BY @Saeedxdie
#THIS CODE CREATE BY @Saeedxdie
#THIS CODE CREATE BY @Saeedxdie
