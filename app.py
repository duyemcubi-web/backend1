import os
import secrets
import hmac
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, session
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

# ========= App & Security Config =========
app = Flask(__name__)

_secret = os.getenv('FLASK_SECRET_KEY')
if not _secret or len(_secret) < 32:
    raise RuntimeError("FLASK_SECRET_KEY phải được set và có ít nhất 32 ký tự!")
app.secret_key = _secret

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.getenv("SESSION_MINUTES", "30")))
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

_raw_origins = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]
if not ALLOWED_ORIGINS:
    raise RuntimeError("ALLOWED_ORIGINS phải được set! Không dùng wildcard '*' trong production.")

CORS(app, supports_credentials=True, origins=ALLOWED_ORIGINS)

# ========= Rate Limit (in-memory) =========
LOGIN_MAX = int(os.getenv("LOGIN_RPM", "5"))         # max attempts
LOGIN_WINDOW = int(os.getenv("LOGIN_WINDOW_SEC", "300"))  # 5 phút
REDEEM_MAX = int(os.getenv("REDEEM_RPM", "20"))
REDEEM_WINDOW = int(os.getenv("REDEEM_WINDOW_SEC", "60"))

_buckets: dict[str, list[float]] = {}

def _rate_limit(bucket_key: str, max_hits: int, window_sec: int) -> bool:
    """Trả về True nếu bị rate limit."""
    now = time.time()
    hits = [t for t in _buckets.get(bucket_key, []) if now - t < window_sec]
    if len(hits) >= max_hits:
        _buckets[bucket_key] = hits
        return True
    hits.append(now)
    _buckets[bucket_key] = hits
    return False

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
            "private_key": (os.getenv("FIREBASE_PRIVATE_KEY") or "").replace('\\n', '\n') or None,
            "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
            "client_id": os.getenv("FIREBASE_CLIENT_ID"),
            "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
            "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
            "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
            "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL"),
            "universe_domain": os.getenv("FIREBASE_UNIVERSE_DOMAIN", "googleapis.com"),
        }
        if all(v for v in firebase_config.values()):
            cred = credentials.Certificate(firebase_config)

    if cred:
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("✅ Firebase connected")
    else:
        print("❌ Firebase not initialized — kiểm tra biến môi trường Firebase")
except Exception as e:
    print("🔥 Firebase init error:", e)

# ========= Admin Auth =========
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH')
if not ADMIN_PASSWORD_HASH:
    _raw_pw = os.getenv('ADMIN_PASSWORD', '')
    if not _raw_pw:
        raise RuntimeError("Phải set ADMIN_PASSWORD_HASH hoặc ADMIN_PASSWORD trong .env!")
    ADMIN_PASSWORD_HASH = generate_password_hash(_raw_pw)

# ========= HMAC (Optional) =========
CLIENT_HMAC_SECRET = os.getenv("CLIENT_HMAC_SECRET")
HMAC_TIMESTAMP_TOLERANCE = 60  # giây

# ========= Key Format =========
KEY_PREFIX = os.getenv("KEY_PREFIX", "AIMX-")
KEY_RANDOM_LENGTH = int(os.getenv("KEY_RANDOM_LENGTH", "16"))  # tăng lên 16

_KEY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def generate_key_string() -> str:
    """Tạo key dùng secrets (cryptographically secure)."""
    rand_part = ''.join(secrets.choice(_KEY_ALPHABET) for _ in range(KEY_RANDOM_LENGTH))
    return f"{KEY_PREFIX}{rand_part}"

# ========= Time helpers (UTC aware) =========
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _now_iso() -> str:
    return _utcnow().isoformat()

def _parse_iso(dt_str: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

# ========= Firestore Helpers =========
def get_key_doc(key_string: str):
    if db is None:
        return None
    if not key_string or len(key_string) > 64:
        return None
    return db.collection('keys').document(key_string)

def update_usage_tracking(key_doc_ref, key_data: dict, hwid: str,
                           machine_name: str, ip_address: str, extra_info: dict = None):
    if extra_info is None:
        extra_info = {}
    if not machine_name:
        machine_name = "UnknownMachine"

    log_entry = {
        "ts": _now_iso(),
        "hwid": hwid,
        "machine_name": machine_name,
        "ip": ip_address,
        "action": "redeem",
        **extra_info,
    }
    try:
        key_doc_ref.collection("access_logs").add(log_entry)
    except Exception as e:
        print("WARN access_logs:", e)

    devices: dict = key_data.get("devices", {})
    dev = devices.get(hwid)
    now_iso = _now_iso()
    new_entry = {
        "hwid": hwid,
        "machine_name": machine_name,
        "first_seen": now_iso if not dev else dev.get("first_seen", now_iso),
        "last_seen": now_iso,
        "last_ip": ip_address,
        "usage_count": (dev.get("usage_count", 0) + 1) if dev else 1,
        "extra_info": extra_info,
    }
    try:
        key_doc_ref.update({f"devices.{hwid}": new_entry})
    except Exception as e:
        print("WARN update devices:", e)

# ========= Decorators =========
def require_json(f):
    @wraps(f)
    def w(*a, **k):
        if not request.is_json:
            return jsonify({"error": "Content-Type phải là application/json"}), 415
        return f(*a, **k)
    return w

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({"error": "Chưa đăng nhập."}), 401
        return f(*args, **kwargs)
    return decorated

def hmac_required(f):
    """Kiểm tra chữ ký HMAC-SHA256 nếu CLIENT_HMAC_SECRET được cấu hình."""
    @wraps(f)
    def w(*a, **k):
        if not CLIENT_HMAC_SECRET:
            return f(*a, **k)
        sig = request.headers.get("X-Client-Sign", "")
        ts = request.headers.get("X-Client-Ts", "")
        if not sig or not ts:
            return jsonify({"status": "error", "message": "Thiếu chữ ký"}), 401
        try:
            ts_int = int(ts)
            if abs(int(time.time()) - ts_int) > HMAC_TIMESTAMP_TOLERANCE:
                return jsonify({"status": "error", "message": "Chữ ký hết hạn"}), 401
            payload = request.get_data() + ts.encode()
            calc = hmac.new(
                CLIENT_HMAC_SECRET.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(calc, sig):
                return jsonify({"status": "error", "message": "Chữ ký không hợp lệ"}), 401
        except (ValueError, Exception):
            return jsonify({"status": "error", "message": "Lỗi xác thực chữ ký"}), 401
        return f(*a, **k)
    return w

def get_client_ip() -> str:
    return (
        request.headers.get("CF-Connecting-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or "0.0.0.0"
    )

# ========= Routes =========
@app.route('/')
def home():
    return jsonify({"status": "ok", "service": "AIMX Key Backend"}), 200

@app.route('/api/session')
def session_info():
    return jsonify({"logged_in": bool(session.get('logged_in'))})

@app.route('/api/login', methods=['POST'])
@require_json
def login():
    ip = get_client_ip()
    if _rate_limit(f"login:{ip}", LOGIN_MAX, LOGIN_WINDOW):
        return jsonify({"error": "Vượt quá số lần thử. Thử lại sau."}), 429

    data = request.get_json(silent=True) or {}
    username = (data.get('username') or "").strip()
    password = data.get('password') or ""

    # Luôn check_password_hash dù username sai để tránh timing attack
    hash_to_check = ADMIN_PASSWORD_HASH
    valid = (username == ADMIN_USERNAME) and check_password_hash(hash_to_check, password)

    if valid:
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
    data = request.get_json(silent=True) or {}
    try:
        days = int(data.get('days', 3))
    except (TypeError, ValueError):
        return jsonify({"error": "days không hợp lệ"}), 400

    if days <= 0 or days > 3650:
        return jsonify({"error": "Số ngày phải từ 1 đến 3650"}), 400

    # Tạo key, đảm bảo không bị trùng
    for _ in range(5):
        key_string = generate_key_string()
        key_doc_ref = get_key_doc(key_string)
        if key_doc_ref is None:
            return jsonify({"error": "Lỗi kết nối cơ sở dữ liệu"}), 500
        if not key_doc_ref.get().exists:
            break
    else:
        return jsonify({"error": "Không thể tạo key duy nhất, thử lại"}), 500

    key_data = {
        "key_string": key_string,
        "duration_days": days,
        "expires_at": None,           # sẽ set khi kích hoạt lần đầu
        "created_at": _now_iso(),
        "created_by": str(data.get('created_by', 'AdminPanel'))[:64],
        "hwid": None,
        "ip_address": None,
        "first_activated_at": None,
        "is_banned": False,
        "devices": {},
    }

    try:
        key_doc_ref.set(key_data)
        return jsonify({
            "message": "Tạo key thành công!",
            "key": key_string,
            "duration_days": days,
        }), 201
    except Exception as e:
        return jsonify({"error": f"Lỗi tạo key: {e}"}), 500

@app.route('/api/redeem', methods=['POST'])
@require_json
@hmac_required
def redeem_key():
    ip = get_client_ip()
    if _rate_limit(f"redeem:{ip}", REDEEM_MAX, REDEEM_WINDOW):
        return jsonify({"status": "error", "message": "Quá nhiều yêu cầu, thử lại sau."}), 429

    data = request.get_json(silent=True) or {}
    key_string = (data.get('key') or "").strip().upper()
    hwid = (data.get('hwid') or "").strip()
    machine_name = str(data.get('machine_name') or "")[:128]

    if not key_string or not hwid:
        return jsonify({"status": "error", "message": "Thiếu key hoặc HWID"}), 400

    # Validate format cơ bản
    if len(hwid) < 8 or len(hwid) > 128:
        return jsonify({"status": "error", "message": "HWID không hợp lệ"}), 400

    extra_info = {
        "windows_version": str(data.get('windows_version', 'N/A'))[:64],
        "cpu_name": str(data.get('cpu_name', 'N/A'))[:64],
        "disk_serial": str(data.get('disk_serial', 'N/A'))[:64],
        "ram_total_gb": data.get('ram_total_gb', 'N/A'),
        "gpu_name": str(data.get('gpu_name', 'N/A'))[:64],
        "client_version": str(data.get('client_version', 'N/A'))[:32],
    }

    key_doc_ref = get_key_doc(key_string)
    if key_doc_ref is None:
        return jsonify({"status": "error", "message": "Lỗi cơ sở dữ liệu"}), 500

    key_doc = key_doc_ref.get()
    if not key_doc.exists:
        return jsonify({"status": "error", "message": "Key không tồn tại"}), 404

    key_data = key_doc.to_dict()

    if key_data.get('is_banned'):
        return jsonify({"status": "error", "message": "Key bị cấm"}), 403

    now = _utcnow()
    first_activated_at = key_data.get('first_activated_at')
    duration_days = key_data.get('duration_days', 0)

    if not first_activated_at:
        # Kích hoạt lần đầu
        expires_at = (now + timedelta(days=duration_days)).isoformat()
        updates = {
            "first_activated_at": now.isoformat(),
            "expires_at": expires_at,
            "hwid": hwid,
            "ip_address": ip,
        }
        key_doc_ref.update(updates)
        key_data.update(updates)
        update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip, extra_info)
        return jsonify({
            "status": "success",
            "message": "Key kích hoạt thành công (lần đầu)",
            "expires_at": expires_at,
        }), 200

    # Kiểm tra HWID
    stored_hwid = key_data.get('hwid')
    if stored_hwid and stored_hwid != hwid:
        update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip, extra_info)
        return jsonify({
            "status": "error",
            "message": "Key này đã được kích hoạt trên thiết bị khác",
        }), 403

    # Dùng expires_at đã lưu trong Firestore (không tính lại) để admin có thể gia hạn
    expires_at_str = key_data.get('expires_at')
    expires_at_dt = _parse_iso(expires_at_str) if expires_at_str else (
        _parse_iso(key_data['first_activated_at']) + timedelta(days=duration_days)
    )

    if expires_at_dt is None or now > expires_at_dt:
        return jsonify({"status": "error", "message": "Key đã hết hạn"}), 403

    update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip, extra_info)

    return jsonify({
        "status": "success",
        "message": "Key hợp lệ",
        "expires_at": expires_at_dt.isoformat(),
        "current_server_time": now.isoformat(),
    }), 200

@app.route('/api/keyinfo/<string:key_string>')
@login_required
def key_info(key_string):
    key_string = key_string.strip().upper()
    key_doc_ref = get_key_doc(key_string)
    if key_doc_ref is None:
        return jsonify({"error": "DB error"}), 500
    doc = key_doc_ref.get()
    if not doc.exists:
        return jsonify({"error": "Key không tồn tại"}), 404

    d = doc.to_dict()
    now = _utcnow()
    status_text = "Chưa kích hoạt"
    expires_display = "Chưa kích hoạt"

    exp_str = d.get('expires_at') or (
        (_parse_iso(d['first_activated_at']) + timedelta(days=d.get('duration_days', 0))).isoformat()
        if d.get('first_activated_at') else None
    )
    if exp_str:
        exp = _parse_iso(exp_str)
        if exp:
            expires_display = exp.strftime("%Y-%m-%d %H:%M:%S UTC")
            status_text = "Hết Hạn" if now > exp else "Đang hoạt động"

    if d.get('is_banned'):
        status_text = "BANNED"

    return jsonify({
        "key": d.get('key_string'),
        "status": status_text,
        "is_banned": d.get('is_banned'),
        "expires_at": expires_display,
        "hwid": d.get('hwid') or "Chưa đăng ký",
        "ip_address": d.get('ip_address') or "N/A",
        "first_activated_at": d.get('first_activated_at') or "Chưa kích hoạt",
        "created_by": d.get('created_by'),
        "created_at": d.get('created_at'),
    })

@app.route('/api/deletekey', methods=['POST'])
@login_required
@require_json
def delete_key():
    data = request.get_json(silent=True) or {}
    key_string = (data.get('key') or "").strip().upper()
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
    data = request.get_json(silent=True) or {}
    key_string = (data.get('key') or "").strip().upper()
    if not key_string:
        return jsonify({"error": "Thiếu key"}), 400
    ref = get_key_doc(key_string)
    if ref is None:
        return jsonify({"error": "DB error"}), 500
    if not ref.get().exists:
        return jsonify({"error": "Key không tồn tại"}), 404
    ref.update({"is_banned": True})
    return jsonify({"message": f"Đã ban {key_string}"}), 200

@app.route('/api/unban', methods=['POST'])
@login_required
@require_json
def unban_key():
    data = request.get_json(silent=True) or {}
    key_string = (data.get('key') or "").strip().upper()
    if not key_string:
        return jsonify({"error": "Thiếu key"}), 400
    ref = get_key_doc(key_string)
    if ref is None:
        return jsonify({"error": "DB error"}), 500
    if not ref.get().exists:
        return jsonify({"error": "Key không tồn tại"}), 404
    ref.update({"is_banned": False})
    return jsonify({"message": f"Đã unban {key_string}"}), 200

@app.route('/api/extendkey', methods=['POST'])
@login_required
@require_json
def extend_key():
    """Gia hạn key thêm N ngày từ thời điểm hiện tại hoặc từ expires_at hiện tại."""
    data = request.get_json(silent=True) or {}
    key_string = (data.get('key') or "").strip().upper()
    try:
        extra_days = int(data.get('days', 0))
    except (TypeError, ValueError):
        return jsonify({"error": "days không hợp lệ"}), 400

    if not key_string:
        return jsonify({"error": "Thiếu key"}), 400
    if extra_days <= 0 or extra_days > 3650:
        return jsonify({"error": "Số ngày gia hạn phải từ 1 đến 3650"}), 400

    ref = get_key_doc(key_string)
    if ref is None:
        return jsonify({"error": "DB error"}), 500
    doc = ref.get()
    if not doc.exists:
        return jsonify({"error": "Key không tồn tại"}), 404

    d = doc.to_dict()
    now = _utcnow()

    old_expires = _parse_iso(d.get('expires_at') or "") if d.get('expires_at') else None
    base = old_expires if (old_expires and old_expires > now) else now
    new_expires = (base + timedelta(days=extra_days)).isoformat()

    ref.update({
        "expires_at": new_expires,
        "duration_days": d.get('duration_days', 0) + extra_days,
    })
    return jsonify({
        "message": f"Đã gia hạn {key_string} thêm {extra_days} ngày",
        "new_expires_at": new_expires,
    }), 200

@app.route('/api/keys')
@login_required
def get_all_keys():
    try:
        page = max(1, int(request.args.get("page", "1")))
        page_size = min(max(1, int(request.args.get("page_size", "50"))), 200)
        status_filter = request.args.get("status", "")  # all | active | expired | banned | inactive

        keys_ref = db.collection('keys')
        try:
            docs = list(
                keys_ref.order_by("created_at", direction=firestore.Query.DESCENDING)
                        .limit(5000)  # giới hạn để tránh load toàn bộ
                        .stream()
            )
        except Exception:
            docs = list(keys_ref.limit(5000).stream())

        rows = []
        now = _utcnow()
        for key_doc in docs:
            kd = key_doc.to_dict()
            status_text = "Chưa kích hoạt"
            expires_display = "Chưa kích hoạt"

            exp_str = kd.get('expires_at')
            if not exp_str and kd.get('first_activated_at'):
                fa = _parse_iso(kd['first_activated_at'])
                if fa:
                    exp_str = (fa + timedelta(days=kd.get('duration_days', 0))).isoformat()

            if exp_str:
                exp = _parse_iso(exp_str)
                if exp:
                    expires_display = exp.strftime("%Y-%m-%d %H:%M:%S UTC")
                    status_text = "Hết Hạn" if now > exp else "Đang hoạt động"

            if kd.get('is_banned'):
                status_text = "BANNED"

            # Lọc theo status
            if status_filter == "active" and status_text != "Đang hoạt động":
                continue
            elif status_filter == "expired" and status_text != "Hết Hạn":
                continue
            elif status_filter == "banned" and status_text != "BANNED":
                continue
            elif status_filter == "inactive" and status_text != "Chưa kích hoạt":
                continue

            rows.append({
                "key_string": kd.get('key_string'),
                "expires_at": expires_display,
                "hwid": kd.get('hwid') or "Chưa đăng ký",
                "ip_address": kd.get('ip_address') or "N/A",
                "first_activated_at": kd.get('first_activated_at') or "Chưa kích hoạt",
                "created_by": kd.get('created_by'),
                "created_at": kd.get('created_at'),
                "is_banned": kd.get('is_banned', False),
                "status_text": status_text,
                "duration_days": kd.get('duration_days'),
            })

        total = len(rows)
        start = (page - 1) * page_size
        items = rows[start: start + page_size]

        return jsonify({"items": items, "total": total, "page": page, "page_size": page_size})
    except Exception as e:
        return jsonify({"error": f"Lỗi khi tải keys: {str(e)}"}), 500

# Tắt debug trong production — gunicorn sẽ không chạy __main__ này
if __name__ == "__main__":
    app.run(debug=False, port=5000)
