from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import time
import json
import base64
import aiohttp
import asyncio
import ssl

app = Flask(__name__)

# --- Protobuf setup ---
from google.protobuf import message_factory
from google.protobuf import descriptor_pool

pool = descriptor_pool.Default()
fd = pool.AddSerializedFile(b'\n\ndata.proto"7\n\x12InnerNestedMessage\x12\x0f\n\x07\x66ield_6\x18\x06 \x01(\x03\x12\x10\n\x08\x66ield_14\x18\x0e \x01(\x03"\x87\x01\n\nNestedItem\x12\x0f\n\x07\x66ield_1\x18\x01 \x01(\x05\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05\x12\x0f\n\x07\x66ield_3\x18\x03 \x01(\x05\x12\x0f\n\x07\x66ield_4\x18\x04 \x01(\x05\x12\x0f\n\x07\x66ield_5\x18\x05 \x01(\x05\x12$\n\x07\x66ield_6\x18\x06 \x01(\x0b\x32\x13.InnerNestedMessage"@\n\x0fNestedContainer\x12\x0f\n\x07\x66ield_1\x18\x01 \x01(\x05\x12\x1c\n\x07\x66ield_2\x18\x02 \x03(\x0b\x32\x0b.NestedItem"A\n\x0bMainMessage\x12\x0f\n\x07\x66ield_1\x18\x01 \x01(\x05\x12!\n\x07\x66ield_2\x18\x02 \x03(\x0b\x32\x10.NestedContainerb\x06proto3')

MainMessage = message_factory.GetMessageClass(pool.FindMessageTypeByName('MainMessage'))
NestedContainer = message_factory.GetMessageClass(pool.FindMessageTypeByName('NestedContainer'))
NestedItem = message_factory.GetMessageClass(pool.FindMessageTypeByName('NestedItem'))
InnerNestedMessage = message_factory.GetMessageClass(pool.FindMessageTypeByName('InnerNestedMessage'))

# --- Encryption setup ---
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
freefire_version = "OB53"

# -----------------------------
# NEW: Access Token to JWT Converter (v2)
# -----------------------------
def get_jwt_from_access_token_v2(access_token):
    """Access token se JWT nikalne ke liye new external API call"""
    try:
        url = f"https://rizerxaccessjwt.vercel.app/rizer?access_token={access_token}"
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get('success') and 'jwt' in data:
            return data['jwt'], None
        else:
            return None, "Failed to get JWT from access token (v2)"
            
    except requests.RequestException as e:
        return None, f"API request failed: {str(e)}"
    except ValueError:
        return None, "Invalid JSON response"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"

def decode_jwt_noverify(token: str):
    """JWT ko bina verify kiye payload decode karta hai"""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)  # padding fix
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        return payload
    except Exception:
        return None

def get_server_url(lock_region: str):
    """Region ke hisaab se Free Fire endpoint select kare"""
    region = lock_region.upper()
    if region == "IND":
        return "https://client.ind.freefiremobile.com/SetPlayerGalleryShowInfo"
    elif region in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/SetPlayerGalleryShowInfo"
    elif region == "BD":
        return "https://clientbp.ggblueshark.com/SetPlayerGalleryShowInfo"
    elif region == "SG":
        return "https://client.sg.freefiremobile.com/SetPlayerGalleryShowInfo"
    else:
        return "https://clientbp.ggblueshark.com/SetPlayerGalleryShowInfo"

def build_protobuf_message(item_ids):
    """Protobuf message build karta hai"""
    data = MainMessage()
    data.field_1 = 1
    
    container1 = data.field_2.add()
    container1.field_1 = 1
    
    combinations = [
        {"field_1": 2, "field_4": 1},
        {"field_1": 2, "field_4": 1, "field_5": 4},
        {"field_1": 2, "field_4": 1, "field_5": 2},
        {"field_1": 13, "field_3": 1},
        {"field_1": 13, "field_3": 1, "field_4": 2},
        {"field_1": 13, "field_3": 1, "field_5": 2},
        {"field_1": 13, "field_3": 1, "field_5": 4},
        {"field_1": 13, "field_3": 1, "field_4": 2, "field_5": 2},
        {"field_1": 13, "field_3": 1, "field_4": 2, "field_5": 4},
        {"field_1": 13, "field_3": 1, "field_4": 4},
        {"field_1": 13, "field_3": 1, "field_4": 4, "field_5": 2},
        {"field_1": 13, "field_3": 1, "field_4": 4, "field_5": 4},
        {"field_1": 13, "field_3": 1, "field_4": 6},
        {"field_1": 13, "field_3": 1, "field_4": 6, "field_5": 2},
        {"field_1": 13, "field_3": 1, "field_4": 6, "field_5": 4}
    ]
    
    for i, item_id in enumerate(item_ids):
        if i >= len(combinations):
            break
        combo = combinations[i]
        item = container1.field_2.add()
        item.field_1 = combo.get("field_1", 0)
        if "field_3" in combo:
            item.field_3 = combo["field_3"]
        if "field_4" in combo:
            item.field_4 = combo["field_4"]
        if "field_5" in combo:
            item.field_5 = combo["field_5"]
        inner = InnerNestedMessage()
        inner.field_6 = int(item_id)
        item.field_6.CopyFrom(inner)

    container2 = data.field_2.add()
    container2.field_1 = 9
    
    item7 = container2.field_2.add()
    item7.field_4 = 3
    inner7 = InnerNestedMessage()
    inner7.field_14 = 3048205855
    item7.field_6.CopyFrom(inner7)
    
    item8 = container2.field_2.add()
    item8.field_4 = 3
    item8.field_5 = 3
    inner8 = InnerNestedMessage()
    inner8.field_14 = 3048205855
    item8.field_6.CopyFrom(inner8)
    
    return data

def encrypt_protobuf(data):
    """Protobuf data ko encrypt karta hai"""
    data_bytes = data.SerializeToString()
    padded_data = pad(data_bytes, AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(padded_data)

# --- Async Gallery function (provided by user, adapted) ---
async def _async_gallery(payload, url, headers):
    """Send encrypted payload to the FreeFire gallery endpoint asynchronously"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ssl_context) as response:
            if response.status == 200:
                return response.status, await response.text()
            return response.status, None

# --- Synchronous wrapper that uses the async Gallery function ---
def send_profile_request(jwt_token, encrypted_data, lock_region):
    """Profile request bhejta hai (sync wrapper around async Gallery)"""
    url = get_server_url(lock_region)
    
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Content-Type": "application/octet-stream",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Accept-Encoding": "gzip"
    }

    try:
        # Run the async function synchronously
        status_code, response_text = asyncio.run(_async_gallery(encrypted_data, url, headers))
        
        # Create a minimal response object to keep compatibility with existing code
        class MockResponse:
            def __init__(self, status_code, text):
                self.status_code = status_code
                self.text = text if text is not None else ""
        return MockResponse(status_code, response_text)
    except Exception as e:
        raise Exception(f"External request failed: {str(e)}")

# -----------------------------
# ORIGINAL ENDPOINT - JWT Token Based
# -----------------------------
@app.route('/add-profile', methods=['GET'])
def add_profile():
    """
    Original endpoint - JWT token se directly kaam karta hai
    URL: /add-profile?token={jwt_token}&itemid=12345/67890
    """
    jwt_token = request.args.get('token')
    itemid_str = request.args.get('itemid')
    
    if not jwt_token or not itemid_str:
        return jsonify({
            "status": "error",
            "message": "Missing token or itemid parameter"
        }), 400

    # --- JWT decode karke lock_region nikalna ---
    payload = decode_jwt_noverify(jwt_token)
    if not payload:
        return jsonify({
            "status": "error",
            "message": "Invalid JWT token"
        }), 400

    lock_region = payload.get("lock_region", "IND").upper()

    # --- Process item IDs ---
    item_ids = itemid_str.split('/')[:15]
    if not item_ids:
        return jsonify({"status": "error", "message": "At least one item ID required"}), 400

    # Build and encrypt protobuf
    data = build_protobuf_message(item_ids)
    encrypted_data = encrypt_protobuf(data)

    # Send request
    try:
        response = send_profile_request(jwt_token, encrypted_data, lock_region)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    current_time = int(time.time())
    add_profile_list = [{"add_time": current_time, f"item_id{i+1}": int(item_id)} 
                        for i, item_id in enumerate(item_ids)]

    if response.status_code == 200:
        return jsonify({
            "message": "Item added to profile",
            "status": "success",
            "lock_region": lock_region,
            "Add-profile": add_profile_list
        })
    else:
        return jsonify({
            "status": "error",
            "message": f"External server returned status {response.status_code}",
            "lock_region": lock_region,
            "external_response": response.text,
            "request_size": len(encrypted_data)
        }), 400

# -----------------------------
# ORIGINAL ACCESS TOKEN ENDPOINT (kept unchanged)
# -----------------------------
@app.route('/add-profile-access', methods=['GET'])
def add_profile_access():
    """
    Original endpoint - Access token se JWT nikalta hai aur profile add karta hai
    URL: /add-profile-access?accesstoken={access_token}&itemid=12345/67890
    """
    access_token = request.args.get('accesstoken')
    itemid_str = request.args.get('itemid')
    
    if not access_token or not itemid_str:
        return jsonify({
            "status": "error",
            "message": "Missing accesstoken or itemid parameter"
        }), 400

    # Step 1: Access token se JWT nikalo (using old endpoint)
    def get_jwt_from_access_token(access_token):
        try:
            url = f"http://2.56.246.128:30104/access-jwt?access_token={access_token}"
            response = requests.get(url, timeout=10, verify=False)
            response.raise_for_status()
            data = response.json()
            if data.get('status') == 'success' and 'token' in data:
                return data['token'], None
            else:
                return None, "Failed to get JWT from access token"
        except Exception as e:
            return None, f"API request failed: {str(e)}"

    jwt_token, error = get_jwt_from_access_token(access_token)
    if error:
        return jsonify({
            "status": "error",
            "message": f"JWT conversion failed: {error}"
        }), 400

    payload = decode_jwt_noverify(jwt_token)
    if not payload:
        return jsonify({
            "status": "error",
            "message": "Invalid JWT token received from converter"
        }), 400

    lock_region = payload.get("lock_region", "IND").upper()
    item_ids = itemid_str.split('/')[:15]
    if not item_ids:
        return jsonify({"status": "error", "message": "At least one item ID required"}), 400

    data = build_protobuf_message(item_ids)
    encrypted_data = encrypt_protobuf(data)

    try:
        response = send_profile_request(jwt_token, encrypted_data, lock_region)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    current_time = int(time.time())
    add_profile_list = [{"add_time": current_time, f"item_id{i+1}": int(item_id)} 
                        for i, item_id in enumerate(item_ids)]

    if response.status_code == 200:
        return jsonify({
            "message": "Item added to profile via access token",
            "status": "success",
            "lock_region": lock_region,
            "Add-profile": add_profile_list
        })
    else:
        return jsonify({
            "status": "error",
            "message": f"External server returned status {response.status_code}",
            "lock_region": lock_region,
            "external_response": response.text,
            "request_size": len(encrypted_data)
        }), 400

# -----------------------------
# NEW ENDPOINT 1: Access Token to JWT (v2)
# -----------------------------
@app.route('/add-profile-access-v2', methods=['GET'])
def add_profile_access_v2():
    """
    New endpoint - Uses the new URL to convert access token to JWT
    URL: /add-profile-access-v2?accesstoken={access_token}&itemid=12345/67890
    """
    access_token = request.args.get('accesstoken')
    itemid_str = request.args.get('itemid')
    
    if not access_token or not itemid_str:
        return jsonify({
            "status": "error",
            "message": "Missing accesstoken or itemid parameter"
        }), 400

    # Step 1: Get JWT from new API
    jwt_token, error = get_jwt_from_access_token_v2(access_token)
    if error:
        return jsonify({
            "status": "error",
            "message": f"JWT conversion failed (v2): {error}"
        }), 400

    # Step 2: Decode JWT to get lock_region
    payload = decode_jwt_noverify(jwt_token)
    if not payload:
        return jsonify({
            "status": "error",
            "message": "Invalid JWT token received from converter"
        }), 400

    lock_region = payload.get("lock_region", "IND").upper()

    # Step 3: Process item IDs
    item_ids = itemid_str.split('/')[:15]
    if not item_ids:
        return jsonify({"status": "error", "message": "At least one item ID required"}), 400

    # Step 4: Build and encrypt protobuf
    data = build_protobuf_message(item_ids)
    encrypted_data = encrypt_protobuf(data)

    # Step 5: Send request
    try:
        response = send_profile_request(jwt_token, encrypted_data, lock_region)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    current_time = int(time.time())
    add_profile_list = [{"add_time": current_time, f"item_id{i+1}": int(item_id)} 
                        for i, item_id in enumerate(item_ids)]

    if response.status_code == 200:
        return jsonify({
            "message": "Item added to profile via access token (v2)",
            "status": "success",
            "lock_region": lock_region,
            "Add-profile": add_profile_list
        })
    else:
        return jsonify({
            "status": "error",
            "message": f"External server returned status {response.status_code}",
            "lock_region": lock_region,
            "external_response": response.text,
            "request_size": len(encrypted_data)
        }), 400

# -----------------------------
# NEW ENDPOINT 2: Guest Account (uid + password)
# -----------------------------
@app.route('/add-profile-guest', methods=['GET'])
def add_profile_guest():
    """
    New endpoint - Uses uid and password to get JWT from guest account API
    URL: /add-profile-guest?uid={uid}&password={password}&itemid=12345/67890
    """
    uid = request.args.get('uid')
    password = request.args.get('password')
    itemid_str = request.args.get('itemid')
    
    if not uid or not password or not itemid_str:
        return jsonify({
            "status": "error",
            "message": "Missing uid, password or itemid parameter"
        }), 400

    # Step 1: Call guest account API to get JWT
    try:
        guest_url = f"https://rizerxguestaccountacceee.vercel.app/rizer?uid={uid}&password={password}"
        guest_resp = requests.get(guest_url, timeout=10, verify=False)
        guest_resp.raise_for_status()
        guest_data = guest_resp.json()
        
        if guest_data.get('status') != 'success':
            return jsonify({
                "status": "error",
                "message": f"Guest account API returned error: {guest_data.get('message', 'Unknown error')}"
            }), 400
        
        jwt_token = guest_data.get('jwt_token')
        if not jwt_token:
            return jsonify({
                "status": "error",
                "message": "Guest account response missing jwt_token"
            }), 400
        
        # Optionally use region from guest response if needed, but we'll decode JWT for lock_region
        # lock_region = guest_data.get('region', 'IND').upper()
        
    except requests.RequestException as e:
        return jsonify({
            "status": "error",
            "message": f"Guest account API request failed: {str(e)}"
        }), 500
    except ValueError:
        return jsonify({
            "status": "error",
            "message": "Invalid JSON response from guest account API"
        }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Unexpected error: {str(e)}"
        }), 500

    # Step 2: Decode JWT to get lock_region
    payload = decode_jwt_noverify(jwt_token)
    if not payload:
        return jsonify({
            "status": "error",
            "message": "Invalid JWT token received from guest account"
        }), 400

    lock_region = payload.get("lock_region", "IND").upper()

    # Step 3: Process item IDs
    item_ids = itemid_str.split('/')[:15]
    if not item_ids:
        return jsonify({"status": "error", "message": "At least one item ID required"}), 400

    # Step 4: Build and encrypt protobuf
    data = build_protobuf_message(item_ids)
    encrypted_data = encrypt_protobuf(data)

    # Step 5: Send request
    try:
        response = send_profile_request(jwt_token, encrypted_data, lock_region)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    current_time = int(time.time())
    add_profile_list = [{"add_time": current_time, f"item_id{i+1}": int(item_id)} 
                        for i, item_id in enumerate(item_ids)]

    if response.status_code == 200:
        return jsonify({
            "message": "Item added to profile via guest account",
            "status": "success",
            "lock_region": lock_region,
            "Add-profile": add_profile_list
        })
    else:
        return jsonify({
            "status": "error",
            "message": f"External server returned status {response.status_code}",
            "lock_region": lock_region,
            "external_response": response.text,
            "request_size": len(encrypted_data)
        }), 400

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "FreeFire-Profile-API"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
