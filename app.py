import os
from datetime import datetime, timedelta
import random, string, json, time
from functools import wraps
from flask import Flask, request, jsonify, session
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv

load_dotenv()

# ========= App & Security Config =========
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY') or 'fallback_secret_key_DO_NOT_USE_IN_PRODUCTION'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.getenv("SESSION_MINUTES", "30")))
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",")]
CORS(app, supports_credentials=True, origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else "*")

# anti-bruteforce (very simple in-memory)
LOGIN_RPM = int(os.getenv("LOGIN_RPM", "10"))
_login_bucket = {}

# ========= Firebase =========
db = None
try:
    firebase_service_account_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY")
    cred = None
    if firebase_service_account_json:
        cfg = json.loads(firebase_service_account_json)
        if "private_key" in cfg:
            cfg["private_key"] = cfg["private_key"].replace("\\n", "\n")
        cred = credentials.Certificate(cfg)
    else:
        firebase_config = {
            "type": os.getenv("FIREBASE_TYPE"),
            "project_id": os.getenv("FIREBASE_PROJECT_ID"),
            "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
            "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace('\\n','\n') if os.getenv("FIREBASE_PRIVATE_KEY") else None,
            "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
            "client_id": os.getenv("FIREBASE_CLIENT_ID"),
            "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
            "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
            "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
            "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL"),
            "universe_domain": os.getenv("FIREBASE_UNIVERSE_DOMAIN")
        }
        if all(v is not None for v in firebase_config.values()):
            cred = credentials.Certificate(firebase_config)

    if cred:
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("✅ Firebase connected")
    else:
        print("❌ Firebase not initialized")
except Exception as e:
    print("🔥 Firebase init error:", e)

# ========= Admin Auth =========
from werkzeug.security import check_password_hash, generate_password_hash

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH')
if not ADMIN_PASSWORD_HASH:
    ADMIN_PASSWORD_HASH = generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin123'))

def _rate_limit_login(ip: str) -> bool:
    window = 300  # 5 minutes
    now = time.time()
    bucket = _login_bucket.get(ip, [])
    bucket = [t for t in bucket if now - t < window]
    if len(bucket) >= LOGIN_RPM:
        _login_bucket[ip] = bucket
        return True
    bucket.append(now)
    _login_bucket[ip] = bucket
    return False

def require_json(f):
    @wraps(f)
    def w(*a, **k):
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415
        return f(*a, **k)
    return w

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({"error": "Không được ủy quyền. Vui lòng đăng nhập."}), 401
        return f(*args, **kwargs)
    return decorated

# Optional HMAC check
import hmac, hashlib
CLIENT_HMAC_SECRET = os.getenv("CLIENT_HMAC_SECRET")

def hmac_required(f):
    @wraps(f)
    def w(*a, **k):
        if not CLIENT_HMAC_SECRET:
            return f(*a, **k)
        sig = request.headers.get("X-Client-Sign")
        ts = request.headers.get("X-Client-Ts")
        if not sig or not ts:
            return jsonify({"status":"error","message":"Missing signature"}), 401
        try:
            payload = request.get_data() + ts.encode()
            calc = hmac.new(CLIENT_HMAC_SECRET.encode(), payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(calc, sig):
                return jsonify({"status":"error","message":"Invalid signature"}), 401
            if abs(int(time.time()) - int(ts)) > 60:
                return jsonify({"status":"error","message":"Expired signature"}), 401
        except Exception:
            return jsonify({"status":"error","message":"Signature error"}), 401
        return f(*a, **k)
    return w

# ========= Key Format =========
KEY_PREFIX = "AIMX-"
KEY_RANDOM_LENGTH = 7

def generate_key_string():
    chars = string.ascii_uppercase + string.digits
    random_part = ''.join(random.choice(chars) for _ in range(KEY_RANDOM_LENGTH))
    return f"{KEY_PREFIX}{random_part}"

# ========= Firestore Helpers =========
def get_key_doc(key_string):
    if db is None: return None
    return db.collection('keys').document(key_string)

def _now_iso(): return datetime.now().isoformat()

def _parse_iso(dt_str):
    try: return datetime.fromisoformat(dt_str)
    except: return None

def update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip_address, extra_info=None):
    if extra_info is None:
        extra_info = {}
    if not machine_name: machine_name = "UnknownMachine"

    log_entry = {
        "ts": _now_iso(),
        "hwid": hwid,
        "machine_name": machine_name,
        "ip": ip_address,
        "action": "redeem",
        **extra_info
    }

    try:
        key_doc_ref.collection("access_logs").add(log_entry)
    except Exception as e:
        print("WARN access_logs:", e)

    devices = key_data.get("devices", {})
    dev = devices.get(hwid)
    now_iso = _now_iso()
    new_entry = {
        "hwid": hwid,
        "machine_name": machine_name,
        "first_seen": now_iso if not dev else dev.get("first_seen", now_iso),
        "last_seen": now_iso,
        "last_ip": ip_address,
        "usage_count": (dev.get("usage_count", 0) + 1) if dev else 1,
        "extra_info": extra_info
    }
    try:
        key_doc_ref.update({f"devices.{hwid}": new_entry})
    except Exception as e:
        print("WARN update devices:", e)

# ========= Routes =========
@app.route('/')
def home():
    return "AIMX Key Backend OK"

@app.route('/api/session')
def session_info():
    return jsonify({"logged_in": bool(session.get('logged_in'))})

@app.route('/api/login', methods=['POST'])
@require_json
def login():
    ip = request.headers.get("CF-Connecting-IP") or request.remote_addr or "0.0.0.0"
    if _rate_limit_login(ip):
        return jsonify({"error": "Vượt quá số lần thử. Thử lại sau."}), 429

    data = request.get_json()
    username = (data.get('username') or "").strip()
    password = data.get('password') or ""

    if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
        session.clear()
        session['logged_in'] = True
        session.permanent = True
        return jsonify({"message": "Đăng nhập thành công!"}), 200

    return jsonify({"error": "Tài khoản hoặc mật khẩu không đúng."}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({"message": "Đăng xuất thành công."}), 200

@app.route('/api/createkey', methods=['POST'])
@login_required
@require_json
def create_key():
    data = request.get_json()
    try:
        days = int(data.get('days', 3))
    except:
        return jsonify({"error": "days không hợp lệ"}), 400

    if days <= 0:
        return jsonify({"error": "Số ngày > 0"}), 400

    key_string = generate_key_string()
    key_doc_ref = get_key_doc(key_string)
    if key_doc_ref is None:
        return jsonify({"error": "Lỗi kết nối cơ sở dữ liệu"}), 500

    key_data = {
        "key_string": key_string,
        "duration_days": days,
        "expires_at": None,
        "created_at": _now_iso(),
        "created_by": data.get('created_by', 'AdminPanel'),
        "hwid": None,
        "ip_address": None,
        "first_activated_at": None,
        "is_banned": False,
        "devices": {}
    }

    try:
        key_doc_ref.set(key_data)
        return jsonify({
            "message": "Tạo key thành công!",
            "key": key_string,
            "duration_days": days
        }), 201
    except Exception as e:
        return jsonify({"error": f"Lỗi tạo key: {e}"}), 500

@app.route('/api/redeem', methods=['POST'])
@require_json
@hmac_required
def redeem_key():
    data = request.get_json()
    key_string = data.get('key')
    hwid = data.get('hwid')
    machine_name = data.get('machine_name')
    ip_address = request.headers.get("CF-Connecting-IP") or request.remote_addr

    extra_info = {
        "windows_version": data.get('windows_version', 'N/A'),
        "cpu_name": data.get('cpu_name', 'N/A'),
        "disk_serial": data.get('disk_serial', 'N/A'),
        "ram_total_gb": data.get('ram_total_gb', 'N/A'),
        "gpu_name": data.get('gpu_name', 'N/A'),
        "client_version": data.get('client_version', 'N/A'),
    }

    if not key_string or not hwid:
        return jsonify({"status": "error", "message": "Thiếu key hoặc HWID"}), 400

    key_doc_ref = get_key_doc(key_string)
    if key_doc_ref is None:
        return jsonify({"status": "error", "message": "Lỗi cơ sở dữ liệu"}), 500

    key_doc = key_doc_ref.get()
    if not key_doc.exists:
        return jsonify({"status": "error", "message": "Key không tồn tại"}), 404

    key_data = key_doc.to_dict()

    if key_data.get('is_banned'):
        return jsonify({"status": "error", "message": "Key bị cấm"}), 403

    now = datetime.now()
    first_activated_at = key_data.get('first_activated_at')
    duration_days = key_data.get('duration_days')

    if not first_activated_at:
        first_activated_at = now.isoformat()
        expires_at = (now + timedelta(days=duration_days)).isoformat()
        updates = {
            "first_activated_at": first_activated_at,
            "expires_at": expires_at,
            "hwid": hwid,
            "ip_address": ip_address
        }
        key_doc_ref.update(updates)
        key_data.update(updates)
        update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip_address, extra_info)
        return jsonify({
            "status": "success",
            "message": "Key kích hoạt thành công (lần đầu)",
            "expires_at": expires_at
        }), 200

    stored_hwid = key_data.get('hwid')
    if stored_hwid and stored_hwid != hwid:
        update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip_address, extra_info)
        return jsonify({
            "status": "error",
            "message": "Key này đã được kích hoạt trên thiết bị khác",
            "registered_hwid": stored_hwid,
            "your_hwid": hwid
        }), 403

    expires_at_dt = _parse_iso(key_data['first_activated_at']) + timedelta(days=duration_days)
    if now > expires_at_dt:
        return jsonify({"status": "error", "message": "Key đã hết hạn"}), 403

    update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip_address, extra_info)

    return jsonify({
        "status": "success",
        "message": "Key hợp lệ",
        "expires_at": expires_at_dt.isoformat(),
        "registered_hwid": stored_hwid,
        "current_server_time": now.isoformat()
    }), 200

@app.route('/api/keyinfo/<string:key_string>')
@login_required
def key_info(key_string):
    key_doc_ref = get_key_doc(key_string)
    if key_doc_ref is None: return jsonify({"error": "DB error"}), 500
    doc = key_doc_ref.get()
    if not doc.exists: return jsonify({"error": "Key không tồn tại"}), 404
    d = doc.to_dict()
    now = datetime.now()
    status_text = "Chưa kích hoạt"
    expires_display = "Chưa kích hoạt"
    if d.get('first_activated_at'):
        exp = _parse_iso(d['first_activated_at']) + timedelta(days=d.get('duration_days', 0))
        expires_display = exp.strftime("%Y-%m-%d %H:%M:%S")
        status_text = "Hết Hạn" if now > exp else "Đang hoạt động"
    if d.get('is_banned'): status_text = "BANNED"
    return jsonify({
        "key": d.get('key_string'),
        "status": status_text,
        "is_banned": d.get('is_banned'),
        "expires_at": expires_display,
        "hwid": d.get('hwid') or "Chưa đăng ký",
        "ip_address": d.get('ip_address') or "N/A",
        "first_activated_at": d.get('first_activated_at') or "Chưa kích hoạt",
        "created_by": d.get('created_by'),
        "created_at": d.get('created_at')
    })

@app.route('/api/deletekey', methods=['POST'])
@login_required
@require_json
def delete_key():
    data = request.get_json()
    key_string = data.get('key')
    if not key_string:
        return jsonify({"error": "Thiếu key"}), 400
    ref = get_key_doc(key_string)
    if ref is None:
        return jsonify({"error": "DB error"}), 500
    doc = ref.get()
    if not doc.exists:
        return jsonify({"error": "Key không tồn tại"}), 404
    ref.delete()
    return jsonify({"message": f"Đã xoá {key_string}"}), 200

@app.route('/api/ban', methods=['POST'])
@login_required
@require_json
def ban_key():
    data = request.get_json()
    key_string = data.get('key')
    if not key_string:
        return jsonify({"error": "Thiếu key"}), 400
    ref = get_key_doc(key_string)
    if ref is None:
        return jsonify({"error": "DB error"}), 500
    ref.update({"is_banned": True})
    return jsonify({"message": f"Đã ban {key_string}"}), 200

@app.route('/api/unban', methods=['POST'])
@login_required
@require_json
def unban_key():
    data = request.get_json()
    key_string = data.get('key')
    if not key_string:
        return jsonify({"error": "Thiếu key"}), 400
    ref = get_key_doc(key_string)
    if ref is None:
        return jsonify({"error": "DB error"}), 500
    ref.update({"is_banned": False})
    return jsonify({"message": f"Đã unban {key_string}"}), 200

@app.route('/api/keys')
@login_required
def get_all_keys():
    try:
        page = int(request.args.get("page", "1"))
        page_size = min(int(request.args.get("page_size", "100")), 500)

        keys_ref = db.collection('keys')
        try:
            docs = list(keys_ref.order_by("created_at", direction=firestore.Query.DESCENDING).stream())
        except Exception:
            docs = list(keys_ref.stream())

        rows = []
        now = datetime.now()
        for key_doc in docs:
            kd = key_doc.to_dict()
            status_text = "Chưa kích hoạt"
            expires_display = "Chưa kích hoạt"
            fa = kd.get('first_activated_at')
            dur = kd.get('duration_days', 0)
            if fa:
                exp = _parse_iso(fa) + timedelta(days=dur)
                expires_display = exp.strftime("%Y-%m-%d %H:%M:%S")
                status_text = "Hết Hạn" if now > exp else "Đang hoạt động"
            if kd.get('is_banned'):
                status_text = "BANNED"
            rows.append({
                "key_string": kd.get('key_string'),
                "expires_at": expires_display,
                "hwid": kd.get('hwid') or "Chưa đăng ký",
                "ip_address": kd.get('ip_address') or "N/A",
                "first_activated_at": kd.get('first_activated_at') or "Chưa kích hoạt",
                "created_by": kd.get('created_by'),
                "created_at": kd.get('created_at'),
                "is_banned": kd.get('is_banned'),
                "status_text": status_text
            })

        rows.sort(key=lambda x: x.get("created_at") or "", reverse=True)
        total = len(rows)
        start = (page-1)*page_size
        items = rows[start:start + page_size]

        return jsonify({"items": items, "total": total})
    except Exception as e:
        return jsonify({"error": f"Lỗi khi tải keys: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
