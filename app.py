from datetime import datetime
from functools import wraps
import os
import re
import secrets
import sqlite3
import sys
import time

from flask import (Flask, render_template, request, redirect, jsonify,
                   session, url_for)
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "parking.db")
STARTED = time.time()

# --- настройки -------------------------------------------------------------
# Регистрация только по университетской почте. Пустой кортеж () = любая почта.
ALLOWED_DOMAINS = ("astanait.edu.kz",)
# Секрет датчиков: симулятор шлёт его в заголовке X-Sensor-Token.
SENSOR_TOKEN = os.environ.get("PARKGO_SENSOR_TOKEN", "parkgo-sensor-demo")

# 7 парковок вокруг Astana IT University (Мангілік Ел 55/11, блок C1, EXPO; ~51.0909, 71.4184):
# координаты [долгота, широта] и места.
LOTS = {
    "Campus North":    {"xy": [71.4184, 51.0925], "price": 500, "spots": ["A01", "A02"]},
    "Campus South":    {"xy": [71.4196, 51.0890], "price": 400, "spots": ["B01", "B02"]},
    "Main Building":   {"xy": [71.4190, 51.0906], "price": 600, "spots": ["C01"]},
    "EXPO East":       {"xy": [71.4210, 51.0912], "price": 450, "spots": ["E01", "E02", "E03", "E04"]},
    "Mega Silk Way":   {"xy": [71.4170, 51.0893], "price": 600, "spots": ["M01", "M02", "M03", "M04"]},
    "AITU Gate":       {"xy": [71.4170, 51.0912], "price": 350, "spots": ["G01", "G02", "G03", "G04"]},
    "Botanical Garden": {"xy": [71.4200, 51.0935], "price": 300, "spots": ["T01", "T02", "T03", "T04"]},
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
FAILS = {}  # защита входа от подбора пароля: {ключ: [время неудачных попыток]}


def get_secret():
    path = os.path.join(BASE, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or get_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


# --- база данных -----------------------------------------------------------
def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS parking_spots (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                location TEXT NOT NULL,
                price REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'Available'
            )""")
        con.execute("""
            CREATE TABLE IF NOT EXISTS reservations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                spot_id INTEGER NOT NULL,
                customer_name TEXT NOT NULL,
                car_number TEXT NOT NULL,
                FOREIGN KEY (spot_id) REFERENCES parking_spots(id)
            )""")
        con.execute("""
            CREATE TABLE IF NOT EXISTS support_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                message TEXT NOT NULL,
                contact TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL
            )""")
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                full_name TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
                created_at TEXT NOT NULL
            )""")
        for col in ("created_at TEXT", "user_id INTEGER"):  # миграция старой базы
            try:
                con.execute(f"ALTER TABLE reservations ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass

        # добавляем парковки, которых ещё нет (старые данные не трогаем)
        for lot, d in LOTS.items():
            exists = con.execute(
                "SELECT 1 FROM parking_spots WHERE location = ?", (lot,)
            ).fetchone()
            if not exists:
                con.executemany(
                    "INSERT INTO parking_spots (name, location, price, status) VALUES (?, ?, ?, 'Available')",
                    [(n, lot, d["price"]) for n in d["spots"]],
                )

        # первый администратор (пароль показывается один раз в консоли)
        has_admin = con.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone()
        if not has_admin:
            pwd = secrets.token_urlsafe(9)
            con.execute(
                "INSERT INTO users (email, full_name, password_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
                ("admin@astanait.edu.kz", "Administrator", generate_password_hash(pwd), now()),
            )
            print("\n=== ParkGo: создан администратор ===")
            print("    email:  admin@astanait.edu.kz")
            print(f"    пароль: {pwd}")
            print("    (показывается один раз; сменить: python app.py make-admin EMAIL ПАРОЛЬ)\n")


def make_admin(email, password):
    email = email.strip().lower()
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        h = generate_password_hash(password)
        if row:
            con.execute("UPDATE users SET password_hash = ?, role = 'admin' WHERE id = ?", (h, row[0]))
        else:
            con.execute(
                "INSERT INTO users (email, full_name, password_hash, role, created_at) VALUES (?, 'Administrator', ?, 'admin', ?)",
                (email, h, now()),
            )


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ago(ts):
    if not ts:
        return ""
    try:
        sec = (datetime.now() - datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")).total_seconds()
    except ValueError:
        return ""
    if sec < 60:
        return "just now"
    if sec < 3600:
        return f"{int(sec // 60)} min ago"
    if sec < 86400:
        return f"{int(sec // 3600)} h ago"
    return f"{int(sec // 86400)} d ago"


# --- вход и права ----------------------------------------------------------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    with sqlite3.connect(DB) as con:
        con.row_factory = sqlite3.Row
        return con.execute(
            "SELECT id, email, full_name, role FROM users WHERE id = ?", (uid,)
        ).fetchone()


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            if request.method == "GET":
                return redirect(url_for("login", next=request.path))
            return "Please log in.", 401
        if user["role"] != "admin":
            return "Administrators only.", 403
        return view(*args, **kwargs)
    return wrapper


def safe_next(value):
    return value if value and value.startswith("/") and not value.startswith("//") else "/"


def too_many(key):
    t = time.time()
    FAILS[key] = [x for x in FAILS.get(key, []) if t - x < 300]
    return len(FAILS[key]) >= 5


def login_page(error=None, mode="login", status=200):
    return render_template("login.html", error=error, mode=mode,
                           next=safe_next(request.values.get("next"))), status


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return login_page(mode=request.args.get("mode", "login"))
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    key = f"{email}|{request.remote_addr}"
    if too_many(key):
        return login_page("Too many attempts. Try again in 5 minutes.", status=429)
    with sqlite3.connect(DB) as con:
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if row and check_password_hash(row["password_hash"], password):
        session.clear()
        session["uid"] = row["id"]
        return redirect(safe_next(request.form.get("next")))
    FAILS.setdefault(key, []).append(time.time())
    return login_page("Wrong email or password.", status=401)


@app.route("/register", methods=["POST"])
def register():
    email = request.form.get("email", "").strip().lower()
    name = request.form.get("full_name", "").strip()[:80]
    password = request.form.get("password", "")
    if not EMAIL_RE.match(email):
        return login_page("Enter a valid email.", "register", 400)
    if ALLOWED_DOMAINS and email.split("@")[1] not in ALLOWED_DOMAINS:
        return login_page("Use your university email: @" + ALLOWED_DOMAINS[0], "register", 400)
    if len(password) < 8:
        return login_page("Password must have at least 8 characters.", "register", 400)
    try:
        with sqlite3.connect(DB) as con:
            cur = con.execute(
                "INSERT INTO users (email, full_name, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, name, generate_password_hash(password), now()),
            )
    except sqlite3.IntegrityError:
        return login_page("This email is already registered.", "register", 409)
    session.clear()
    session["uid"] = cur.lastrowid
    return redirect(safe_next(request.form.get("next")))


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# --- сайт и бронирование ---------------------------------------------------
def spots_json(con):
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM parking_spots ORDER BY id").fetchall()
    return [{"id": r["id"], "name": r["name"], "loc": r["location"],
             "price": int(r["price"]), "status": r["status"],
             "free": r["status"] == "Available"} for r in rows]


@app.route("/")
def home():
    with sqlite3.connect(DB) as con:
        spots = spots_json(con)
    return render_template("index.html", spots=spots,
                           lots={k: v["xy"] for k, v in LOTS.items()},
                           user=current_user())


@app.route("/api/spots")
def api_spots():
    """Страница опрашивает этот адрес каждые несколько секунд (обновление в реальном времени)."""
    with sqlite3.connect(DB) as con:
        resp = jsonify(spots_json(con))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/book/<int:spot_id>", methods=["POST"])
def book(spot_id):
    user = current_user()
    if user is None:
        return "Please log in to book a spot.", 401

    name = request.form.get("customer_name", "").strip()[:80]
    car = request.form.get("car_number", "").strip()[:20]
    if not name or not car:
        return "Please enter your name and car number.", 400

    with sqlite3.connect(DB) as con:
        con.execute("PRAGMA foreign_keys = ON")
        spot = con.execute(
            "SELECT status FROM parking_spots WHERE id = ?", (spot_id,)
        ).fetchone()
        if spot is None:
            return "Parking spot not found.", 404
        if spot[0] != "Available":
            return "This parking spot is no longer available.", 409

        cur = con.execute(
            """INSERT INTO reservations (spot_id, customer_name, car_number, created_at, user_id)
               VALUES (?, ?, ?, ?, ?)""",
            (spot_id, name, car, now(), user["id"]),
        )
        reservation_id = cur.lastrowid
        con.execute("UPDATE parking_spots SET status = 'Reserved' WHERE id = ?", (spot_id,))

    if request.headers.get("X-Requested-With") == "fetch":
        return jsonify(ok=True, reservation_id=reservation_id)
    return redirect("/")


@app.route("/cancel/<int:reservation_id>", methods=["POST"])
def cancel(reservation_id):
    user = current_user()
    if user is None:
        return "Please log in.", 401
    with sqlite3.connect(DB) as con:
        row = con.execute(
            "SELECT spot_id, user_id FROM reservations WHERE id = ?", (reservation_id,)
        ).fetchone()
        if row is None:
            return "Reservation not found.", 404
        if user["role"] != "admin" and row[1] != user["id"]:
            return "You can cancel only your own booking.", 403
        con.execute("DELETE FROM reservations WHERE id = ?", (reservation_id,))
        con.execute("UPDATE parking_spots SET status = 'Available' WHERE id = ?", (row[0],))
    return jsonify(ok=True)


@app.route("/support", methods=["POST"])
def support():
    category = request.form.get("category", "chat").strip()[:30] or "chat"
    message = request.form.get("message", "").strip()
    contact = request.form.get("contact", "").strip()[:80]
    if not message:
        return "Please describe your problem.", 400
    with sqlite3.connect(DB) as con:
        cur = con.execute(
            "INSERT INTO support_reports (category, message, contact, created_at) VALUES (?, ?, ?, ?)",
            (category, message[:1000], contact, now()),
        )
    return jsonify(ok=True, id=cur.lastrowid)


# --- датчики (симулятор sensor_simulator.py шлёт сюда данные) ---------------
@app.route("/api/sensor", methods=["POST"])
def sensor():
    if not secrets.compare_digest(request.headers.get("X-Sensor-Token", ""), SENSOR_TOKEN):
        return jsonify(ok=False, error="bad token"), 401
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    try:
        spot_id = int(data.get("spot_id"))
    except (TypeError, ValueError):
        return jsonify(ok=False, error="bad spot_id"), 400
    if status not in ("Occupied", "Available"):
        return jsonify(ok=False, error="status must be Occupied or Available"), 400
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT status FROM parking_spots WHERE id = ?", (spot_id,)).fetchone()
        if row is None:
            return jsonify(ok=False, error="spot not found"), 404
        if row[0] == "Reserved":  # забронированное место датчик не меняет
            return jsonify(ok=False, error="spot is reserved"), 409
        con.execute("UPDATE parking_spots SET status = ? WHERE id = ?", (status, spot_id))
    return jsonify(ok=True)


# --- админка ---------------------------------------------------------------
@app.route("/admin/report/<int:report_id>/resolve", methods=["POST"])
@admin_required
def resolve_report(report_id):
    with sqlite3.connect(DB) as con:
        con.execute("UPDATE support_reports SET status = 'resolved' WHERE id = ?", (report_id,))
    return jsonify(ok=True)


@app.route("/admin")
@admin_required
def admin():
    with sqlite3.connect(DB) as con:
        con.row_factory = sqlite3.Row
        spots = con.execute("""
            SELECT p.*, r.id AS rid, r.customer_name, r.car_number
            FROM parking_spots p
            LEFT JOIN reservations r
              ON r.id = (SELECT MAX(id) FROM reservations WHERE spot_id = p.id)
            ORDER BY p.id
        """).fetchall()
        reports = con.execute(
            "SELECT * FROM support_reports ORDER BY (status = 'open') DESC, id DESC"
        ).fetchall()
        bookings = con.execute("""
            SELECT r.id, r.customer_name, r.created_at, p.name AS spot
            FROM reservations r JOIN parking_spots p ON p.id = r.spot_id
            ORDER BY r.id DESC LIMIT 8
        """).fetchall()
        db_ok = con.execute("SELECT 1").fetchone() is not None

    free_by_loc = {}
    for s in spots:
        free_by_loc.setdefault(s["location"], 0)
        if s["status"] == "Available":
            free_by_loc[s["location"]] += 1

    up = int(time.time() - STARTED)
    uptime = f"{up // 3600}h {up % 3600 // 60}m" if up >= 3600 else f"{up // 60}m {up % 60}s"

    activity = [
        {"title": "New booking", "text": f"Spot {b['spot']} · {b['customer_name']}",
         "ts": b["created_at"], "ago": ago(b["created_at"])} for b in bookings
    ] + [
        {"title": "Support message" + (" resolved" if r["status"] == "resolved" else ""),
         "text": f"{r['category']}: {r['message'][:60]}",
         "ts": r["created_at"], "ago": ago(r["created_at"])} for r in reports
    ]
    activity.sort(key=lambda a: a["ts"] or "", reverse=True)

    stats = {
        "locations": len(free_by_loc),
        "open_reports": sum(1 for r in reports if r["status"] == "open"),
        "unavailable": sum(1 for n in free_by_loc.values() if n == 0),
        "uptime": uptime,
    }
    return render_template("admin.html", stats=stats, spots=spots, reports=reports,
                           activity=activity[:10], db_ok=db_ok)


init_db()

if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "make-admin":
        make_admin(sys.argv[2], sys.argv[3])
        print("Администратор сохранён:", sys.argv[2].lower())
        sys.exit(0)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)

