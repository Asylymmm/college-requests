from flask import Flask, render_template, request, redirect, url_for, session
from pathlib import Path
from functools import wraps

from werkzeug.utils import secure_filename
from uuid import uuid4
import os
import re
import psycopg2
import psycopg2.extras
from datetime import datetime, date, timedelta

from werkzeug.security import generate_password_hash, check_password_hash

import smtplib
from email.message import EmailMessage
import random

from dotenv import load_dotenv

load_dotenv()

def send_email_code(to_email: str, code: str):
    """
    Отправка кода через SMTP.
    Нужны переменные окружения:
      SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    mail_from = os.getenv("MAIL_FROM")

    if not all([smtp_host, smtp_user, smtp_pass, mail_from]):
        raise RuntimeError("Нет SMTP_HOST/SMTP_USER/SMTP_PASS/MAIL_FROM в переменных окружения")

    msg = EmailMessage()
    msg["Subject"] = "Код подтверждения"
    msg["From"] = mail_from
    msg["To"] = to_email
    msg.set_content(f"Ваш код подтверждения: {code}\nКод действует 10 минут.")
    msg.add_alternative(f"""
    <div style="font-family:Arial,sans-serif;font-size:16px">
      <p>Ваш код подтверждения:</p>
      <h2 style="letter-spacing:2px">{code}</h2>
      <p>Код действует 10 минут.</p>
    </div>
    """, subtype="html")

    with smtplib.SMTP(smtp_host, smtp_port) as s:
        s.ehlo()
        s.starttls()
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)


def create_or_replace_email_code(conn, user_id: int, email: str):
    """
    Создаёт/обновляет код подтверждения в таблице email_codes и отправляет письмо.
    Таблица email_codes должна существовать.
    """
    code = f"{random.randint(100000, 999999)}"
    code_hash = generate_password_hash(code)
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    created_at = datetime.utcnow()

    cur = conn.cursor()
    # Держим один актуальный код на пользователя (работает без UNIQUE)
    cur.execute(sql("DELETE FROM email_codes WHERE user_id=?"), (user_id,))
    cur.execute(sql("""
        INSERT INTO email_codes (user_id, code_hash, expires_at, created_at)
        VALUES (?, ?, ?, ?)
    """), (user_id, code_hash, expires_at, created_at))
    conn.commit()

    send_email_code(email, code)


def verify_email_code(conn, user_id: int, code: str) -> bool:
    """
    Проверяет код. Если верный и не просрочен — ставит users.email_confirmed=1.
    """
    cur = conn.cursor()
    cur.execute(sql("""
        SELECT code_hash, expires_at
        FROM email_codes
        WHERE user_id=?
        ORDER BY created_at DESC
        LIMIT 1
    """), (user_id,))
    row = cur.fetchone()

    if not row:
        return False

    # совместимо с RealDictCursor и sqlite Row
    db_code_hash = row["code_hash"] if hasattr(row, "keys") else row[0]
    expires_at = row["expires_at"] if hasattr(row, "keys") else row[1]

    # expires_at может быть datetime или строкой
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at)
        except Exception:
            return False
    elif isinstance(expires_at, (int, float)):
        expires_at = datetime.utcfromtimestamp(expires_at)

    if datetime.utcnow() > expires_at:
        return False

    if not check_password_hash(db_code_hash, code):
        return False

    cur.execute(sql("UPDATE users SET email_confirmed=1 WHERE id=?"), (user_id,))
    cur.execute(sql("DELETE FROM email_codes WHERE user_id=?"), (user_id,))
    conn.commit()
    return True


def get_last_email_code_time(conn, user_id: int):
    cur = conn.cursor()
    cur.execute(sql("""
        SELECT created_at
        FROM email_codes
        WHERE user_id=?
        ORDER BY created_at DESC
        LIMIT 1
    """), (user_id,))
    row = cur.fetchone()
    if not row:
        return None

    created_at = row["created_at"] if hasattr(row, "keys") else row[0]
    if isinstance(created_at, str):
        try:
            created_at = datetime.fromisoformat(created_at)
        except Exception:
            return None
    return created_at


def request_email_code(conn, user_id: int, email: str):
    last_sent_at = get_last_email_code_time(conn, user_id)
    if last_sent_at:
        elapsed = (datetime.utcnow() - last_sent_at).total_seconds()
        remaining = int(EMAIL_CODE_COOLDOWN_SECONDS - elapsed)
        if remaining > 0:
            return False, remaining

    create_or_replace_email_code(conn, user_id, email)
    return True, 0


def login_required(f):
    @wraps(f)
    def w(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return w


def role_required(*roles):
    def deco(f):
        @wraps(f)
        def w(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                return redirect(url_for("home"))
            return f(*args, **kwargs)
        return w
    return deco


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


app = Flask(__name__)
app.secret_key = require_env("SECRET_KEY")

STAFF_REGISTER_CODE = require_env("STAFF_REGISTER_CODE")

ALLOWED_AVATAR_EXT = {"png", "jpg", "jpeg", "webp"}
EMAIL_CODE_COOLDOWN_SECONDS = 60
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB

BASE_DIR = Path(__file__).resolve().parent

def sql(q: str) -> str:
    if os.getenv("DATABASE_URL"):
        return q.replace("?", "%s")
    return q

def get_db():
    db_url = os.getenv("DATABASE_URL")

    if db_url:
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)

        conn = psycopg2.connect(
            db_url,
            cursor_factory=psycopg2.extras.RealDictCursor
        )
        return conn

    import sqlite3
    conn = sqlite3.connect(BASE_DIR / "app.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/_db_check")
def db_check():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql("SELECT 1"))
    conn.close()
    return "Postgres OK"


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute(sql("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        approved INTEGER NOT NULL DEFAULT 1,

        username TEXT UNIQUE,
        avatar TEXT,
        group_name TEXT,
        birth_date DATE,
        bio TEXT,
        
        email_confirmed INTEGER NOT NULL DEFAULT 0,
        email_code TEXT,
        email_code_expires TIMESTAMP
    )
    """))

    cur.execute(sql("""
    CREATE TABLE IF NOT EXISTS requests (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        req_type TEXT NOT NULL,
        title TEXT NOT NULL,
        body_text TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('review','accepted','returned')) DEFAULT 'review',
        created_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP NOT NULL
    )
    """))

    cur.execute(sql("""
    CREATE TABLE IF NOT EXISTS email_codes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP NOT NULL
    )
    """))

    conn.commit()
    conn.close()

def migrate_email_confirm():
    conn = get_db()
    cur = conn.cursor()

    # Определяем тип БД
    is_pg = bool(os.getenv("DATABASE_URL"))

    if is_pg:
        # Postgres: добавляем колонки, если нет
        cur.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS email_confirmed INTEGER NOT NULL DEFAULT 0
        """)
        cur.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS email_confirm_code TEXT
        """)
    else:
        # SQLite: проверяем через PRAGMA table_info
        cur.execute("PRAGMA table_info(users)")
        cols = [r[1] for r in cur.fetchall()]  # column name = index 1

        if "email_confirmed" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN email_confirmed INTEGER NOT NULL DEFAULT 0")
        if "email_confirm_code" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN email_confirm_code TEXT")

    conn.commit()
    conn.close()


def migrate_email_codes():
    conn = get_db()
    cur = conn.cursor()

    is_pg = bool(os.getenv("DATABASE_URL"))

    if is_pg:
        cur.execute("ALTER TABLE email_codes ADD COLUMN IF NOT EXISTS code_hash TEXT")
        cur.execute("ALTER TABLE email_codes ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP")
        cur.execute("ALTER TABLE email_codes ADD COLUMN IF NOT EXISTS created_at TIMESTAMP")
    else:
        cur.execute("PRAGMA table_info(email_codes)")
        cols = [r[1] for r in cur.fetchall()]

        if "code_hash" not in cols:
            cur.execute("ALTER TABLE email_codes ADD COLUMN code_hash TEXT")
        if "expires_at" not in cols:
            cur.execute("ALTER TABLE email_codes ADD COLUMN expires_at TIMESTAMP")
        if "created_at" not in cols:
            cur.execute("ALTER TABLE email_codes ADD COLUMN created_at TIMESTAMP")

    conn.commit()
    conn.close()


def calc_age(birth_date_val):
    # birth_date_val в Postgres row_factory=dict_row обычно будет date или None
    if not birth_date_val:
        return None
    if isinstance(birth_date_val, str):
        try:
            b = datetime.strptime(birth_date_val, "%Y-%m-%d").date()
        except:
            return None
    else:
        b = birth_date_val  # date

    today = date.today()
    return today.year - b.year - ((today.month, today.day) < (b.month, b.day))


def find_user(email, password):
    conn = get_db()
    cur = conn.cursor()

    cur.execute(sql("SELECT * FROM users WHERE email=?"), (email,))
    user = cur.fetchone()
    conn.close()

    if not user:
        return None

    if not check_password_hash(user["password"], password):
        return None

    return user


ADMIN_EMAIL = require_env("ADMIN_EMAIL")
ADMIN_PASSWORD = require_env("ADMIN_PASSWORD")
ADMIN_FULLNAME = require_env("ADMIN_FULLNAME")
ADMIN_DELETE_CODE = require_env("ADMIN_DELETE_CODE")


def ensure_admin_exists():
    conn = get_db()
    cur = conn.cursor()

    admin_email = ADMIN_EMAIL.strip().lower()
    admin_hash = generate_password_hash(ADMIN_PASSWORD)

    cur.execute(sql("SELECT id FROM users WHERE email=?"), (admin_email,))
    row = cur.fetchone()

    if row:
        cur.execute(sql("""
            UPDATE users
            SET full_name=?,
                password=?,
                role='admin',
                approved=1
            WHERE id=?
        """), (ADMIN_FULLNAME, admin_hash, row["id"]))
    else:
        cur.execute(sql("""
            INSERT INTO users (full_name, email, password, role, approved)
            VALUES (?, ?, ?, 'admin', 1)
        """), (ADMIN_FULLNAME, admin_email, admin_hash))

    conn.commit()
    conn.close()


def ensure_test_users():
    conn = get_db()
    cur = conn.cursor()

    users = [
        {"full_name": "Тест Студент", "email": "student1", "password": "1234", "role": "student", "approved": 1},
        {"full_name": "Тест Сотрудник", "email": "staff1", "password": "1234", "role": "staff", "approved": 1},
    ]

    for u in users:
        cur.execute(sql("SELECT id FROM users WHERE email=?"), (u["email"],))
        if not cur.fetchone():
            cur.execute(sql("""
                INSERT INTO users (full_name, email, password, role, approved)
                VALUES (?, ?, ?, ?, ?)
            """), (
                u["full_name"],
                u["email"],
                generate_password_hash(u["password"]),
                u["role"],
                u["approved"]
            ))

    conn.commit()
    conn.close()


USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")


@app.route("/profile")
@login_required
@role_required("student", "staff", "admin")
def profile_view():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql("""
        SELECT id, full_name, username, email, role, avatar, group_name, birth_date, bio
        FROM users
        WHERE id=?
    """), (session["user_id"],))
    u = cur.fetchone()
    conn.close()

    if not u:
        return "Пользователь не найден"

    age = calc_age(u["birth_date"])
    return render_template("profile.html", u=u, age=age)


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
@role_required("student", "staff")
def profile_edit():
    conn = get_db()
    cur = conn.cursor()

    cur.execute(sql("""
        SELECT id, full_name, email, role, username, avatar, group_name, birth_date, bio
        FROM users
        WHERE id=?
    """), (session["user_id"],))
    u = cur.fetchone()

    if not u:
        conn.close()
        return "Пользователь не найден"

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        bio = request.form.get("bio", "").strip()

        birth_date_raw = request.form.get("birth_date", "").strip()  # YYYY-MM-DD
        if birth_date_raw == "":
            birth_date = None
        else:
            try:
                birth_date = datetime.strptime(birth_date_raw, "%Y-%m-%d").date()
            except:
                conn.close()
                return "Неверная дата рождения"

        group_name_new = request.form.get("group_name", "").strip()
        username_raw = request.form.get("username", "").strip().lower()

        if not full_name:
            conn.close()
            return "Введите ФИО"

        # группа: выбрать можно только 1 раз
        group_to_save = u["group_name"]
        if not u["group_name"] and group_name_new:
            group_to_save = group_name_new

        # username: выбрать можно только 1 раз + уникальность
        username_to_save = u["username"]
        if not u["username"] and username_raw:
            if not USERNAME_RE.match(username_raw):
                conn.close()
                return "Ник: 3–20 символов, только a-z, 0-9 и _"

            cur.execute(sql("SELECT id FROM users WHERE username=? AND id<>?"), (username_raw, u["id"]))
            if cur.fetchone():
                conn.close()
                return "Этот ник уже занят"

            username_to_save = username_raw

        # обработка аватара
        avatar_rel = u["avatar"]
        f = request.files.get("avatar")
        if f and f.filename:
            ext = f.filename.rsplit(".", 1)[-1].lower()
            if ext in ALLOWED_AVATAR_EXT:
                filename = secure_filename(f"{uuid4().hex}.{ext}")
                rel_path = f"uploads/avatars/{filename}"
                save_path = BASE_DIR / "static" / rel_path
                save_path.parent.mkdir(parents=True, exist_ok=True)
                f.save(save_path)
                avatar_rel = rel_path
            else:
                conn.close()
                return "Аватар: разрешены png/jpg/jpeg/webp"

        cur.execute(sql("""
            UPDATE users
            SET full_name=?, birth_date=?, username=?, bio=?, group_name=?, avatar=?
            WHERE id=?
        """), (
            full_name,
            birth_date,
            username_to_save,
            bio,
            group_to_save,
            avatar_rel,
            session["user_id"]
        ))

        conn.commit()
        conn.close()

        session["full_name"] = full_name
        session["avatar"] = avatar_rel
        session["username"] = username_to_save

        return redirect(url_for("profile_view"))

    # GET
    conn.close()

    age = calc_age(u["birth_date"])
    group_locked = bool(u["group_name"])
    username_locked = bool(u["username"])
    allowed_groups = ["2ВТ-9А2"]

    return render_template(
        "profile_edit.html",
        u=u,
        age=age,
        group_locked=group_locked,
        username_locked=username_locked,
        allowed_groups=allowed_groups
    )


@app.route("/panel/requests")
@login_required
@role_required("staff")
def panel_requests():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT r.id, r.req_type, r.title, r.status, r.created_at,
               u.full_name, u.email, u.role as user_role
        FROM requests r
        JOIN users u ON u.id = r.user_id
        ORDER BY r.id DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return render_template("panel_requests.html", rows=rows)


@app.route("/panel/request/<int:req_id>/status/<status>", methods=["POST"])
@login_required
@role_required("staff", "admin")
def panel_request_set_status(req_id, status):
    if status not in ("review", "accepted", "returned"):
        return "Неверный статус"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql("""
        UPDATE requests
        SET status=?, updated_at=?
        WHERE id=?
    """), (status, datetime.now(), req_id))
    conn.commit()
    conn.close()
    return redirect(url_for("panel_requests"))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    role = session.get("role")
    if role == "student":
        return redirect(url_for("student_dashboard"))
    if role == "staff":
        return redirect(url_for("staff_dashboard"))
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("home"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        user = find_user(email, password)

        if user:
            if user["role"] == "staff" and int(user["approved"]) != 1:
                return render_template("login.html", error="Доступ сотрудника ожидает подтверждения администратора")

            email_confirmed = user["email_confirmed"] if "email_confirmed" in user.keys() else 0
            if int(email_confirmed) != 1:
                try:
                    conn = get_db()
                    sent, wait_seconds = request_email_code(conn, user["id"], user["email"])
                except Exception as e:
                    return render_template("login.html", error=f"Не удалось отправить код подтверждения: {e}", email=email)
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass

                if sent:
                    return redirect(url_for("verify_email", email=email))
                return redirect(url_for("verify_email", email=email, wait=wait_seconds))

            session["user_id"] = user["id"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]

            # ВАЖНО: для sqlite Row нет .get(), поэтому так:
            session["avatar"] = user["avatar"] if "avatar" in user.keys() else None
            session["username"] = user["username"] if "username" in user.keys() else None

            if user["role"] == "student":
                return redirect(url_for("student_dashboard"))
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("staff_dashboard"))

        # ❗ вот это вместо "return Ошибка..."
        return render_template("login.html", error="Неверный email или пароль", email=email)

    return render_template("login.html")


@app.route("/admin")
@login_required
@role_required("admin")
def admin_root():
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS c FROM users WHERE role='student'")
    students_count = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM users WHERE role='staff'")
    staff_count = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM users WHERE role='staff' AND approved=0")
    staff_pending = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM requests")
    requests_count = cur.fetchone()["c"]

    conn.close()

    return render_template(
        "admin_dashboard.html",
        students_count=students_count,
        staff_count=staff_count,
        staff_pending=staff_pending,
        requests_count=requests_count,
        full_name=session.get("full_name", "Неизвестно"),
    )


@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, full_name, email, role, approved
        FROM users
        ORDER BY role DESC, approved ASC, id DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return render_template("admin_users.html", rows=rows)


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def admin_user_delete(user_id):
    confirm_code = request.form.get("confirm_code", "").strip()
    if confirm_code != ADMIN_DELETE_CODE:
        return "Неверный код подтверждения"

    if int(session.get("user_id", 0)) == int(user_id):
        return "Нельзя удалить текущего пользователя"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql("DELETE FROM users WHERE id=?"), (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_users"))


@app.route("/admin/requests")
@login_required
@role_required("admin")
def admin_requests():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT r.id, r.req_type, r.title, r.status, r.created_at,
               u.full_name, u.email, u.role as user_role
        FROM requests r
        JOIN users u ON u.id = r.user_id
        ORDER BY r.id DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return render_template("admin_requests.html", rows=rows)


@app.route("/admin/request/<int:req_id>")
@login_required
@role_required("admin")
def admin_request_view_page(req_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql("""
        SELECT r.*, u.full_name, u.email
        FROM requests r
        JOIN users u ON u.id = r.user_id
        WHERE r.id=?
    """), (req_id,))
    r = cur.fetchone()
    conn.close()

    if not r:
        return "Заявка не найдена"

    return render_template("admin_request_view.html", r=r)


@app.route("/student")
def student_dashboard():
    return render_template("student.html", full_name=session.get("full_name", "Неизвестно"))


@app.route("/staff")
@login_required
@role_required("staff")
def staff_dashboard():
    return render_template("staff.html", full_name=session.get("full_name", "Неизвестно"))


@app.route("/request/new", methods=["GET", "POST"])
def new_request():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        req_type = request.form.get("req_type")
        title = request.form.get("title")
        body_text = request.form.get("body_text")

        conn = get_db()
        cur = conn.cursor()
        cur.execute(sql("""
            INSERT INTO requests (user_id, req_type, title, body_text, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'review', ?, ?)
        """), (
            session["user_id"],
            req_type,
            title,
            body_text,
            datetime.now(),
            datetime.now()
        ))
        conn.commit()
        conn.close()

        return redirect(url_for("student_dashboard"))

    return render_template("new_request.html")


@app.route("/my-requests")
def my_requests():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql("""
        SELECT id, req_type, title, status, created_at
        FROM requests
        WHERE user_id = ?
        ORDER BY id DESC
    """), (session["user_id"],))
    rows = cur.fetchall()
    conn.close()

    return render_template("my_requests.html", rows=rows)


@app.route("/request/delete/<int:req_id>", methods=["POST"])
def delete_request(req_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql(
        "DELETE FROM requests WHERE id=? AND user_id=? AND status='review'"),
        (req_id, session["user_id"])
    )
    conn.commit()
    conn.close()

    return redirect(url_for("my_requests"))


@app.route("/admin/staff-approvals")
@login_required
@role_required("admin")
def admin_staff_approvals():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, full_name, email, approved
        FROM users
        WHERE role='staff'
        ORDER BY approved ASC, id DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return render_template("admin_staff_approvals.html", rows=rows)


@app.route("/admin/staff/<int:user_id>/approve", methods=["POST"])
@login_required
@role_required("admin")
def admin_staff_approve(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql("UPDATE users SET approved=1 WHERE id=? AND role='staff'"), (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_staff_approvals"))


@app.route("/admin/staff/<int:user_id>/reject", methods=["POST"])
@login_required
@role_required("admin")
def admin_staff_reject(user_id):
    confirm_code = request.form.get("confirm_code", "").strip()
    if confirm_code != ADMIN_DELETE_CODE:
        return "Неверный код подтверждения"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql("DELETE FROM users WHERE id=? AND role='staff'"), (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_staff_approvals"))


@app.route("/panel/request/<int:req_id>")
@login_required
@role_required("staff")
def panel_request_view(req_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql("""
        SELECT r.*, u.full_name, u.email
        FROM requests r
        JOIN users u ON u.id = r.user_id
        WHERE r.id=?
    """), (req_id,))
    r = cur.fetchone()
    conn.close()

    if not r:
        return "Заявка не найдена"

    return render_template("panel_request_view.html", r=r)


@app.route("/admin/request/<int:req_id>/status/<status>", methods=["POST"])
@login_required
@role_required("admin")
def admin_request_set_status(req_id, status):
    if status not in ("review", "accepted", "returned"):
        return "Неверный статус"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql("""
        UPDATE requests
        SET status=?, updated_at=?
        WHERE id=?
    """), (status, datetime.now(), req_id))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_requests"))


@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    email_prefill = request.args.get("email", "").strip().lower()
    wait_param = request.args.get("wait", "").strip()
    wait_seconds = int(wait_param) if wait_param.isdigit() else 0

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        code = request.form.get("code", "").strip()
        action = request.form.get("action", "verify")

        if not email:
            return render_template("verify_email.html", error="Введите email", email=email)

        conn = get_db()
        cur = conn.cursor()
        cur.execute(sql("SELECT id, email_confirmed FROM users WHERE email=?"), (email,))
        user = cur.fetchone()

        if not user:
            conn.close()
            return render_template("verify_email.html", error="Пользователь с таким email не найден", email=email)

        user_id = user["id"] if hasattr(user, "keys") else user[0]
        email_confirmed = user["email_confirmed"] if hasattr(user, "keys") else user[1]

        if int(email_confirmed) == 1:
            conn.close()
            return render_template("verify_email.html", success="Почта уже подтверждена. Теперь можно войти.", email=email)

        if action == "resend":
            try:
                sent, wait_seconds = request_email_code(conn, user_id, email)
            except Exception as e:
                conn.close()
                return render_template("verify_email.html", error=f"Не удалось отправить код: {e}", email=email)

            conn.close()
            if sent:
                return render_template("verify_email.html", info="Код отправлен повторно.", email=email)
            return render_template(
                "verify_email.html",
                info=f"Код уже отправлен. Подождите {wait_seconds} сек.",
                email=email,
                wait_seconds=wait_seconds,
            )

        if not code:
            conn.close()
            return render_template("verify_email.html", error="Введите код из письма", email=email)

        ok = verify_email_code(conn, user_id, code)
        conn.close()

        if ok:
            return render_template("verify_email.html", success="Почта подтверждена! Теперь можно войти.", email=email)

        return render_template("verify_email.html", error="Неверный или просроченный код.", email=email)

    if wait_seconds > 0:
        return render_template(
            "verify_email.html",
            info=f"Код уже отправлен. Подождите {wait_seconds} сек.",
            email=email_prefill,
            wait_seconds=wait_seconds,
        )

    return render_template("verify_email.html", email=email_prefill)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "student")
        staff_code = request.form.get("staff_code", "").strip()

        if not full_name or not email or not password:
            return "Ошибка: заполните все поля"

        if "@" not in email:
            return "Ошибка: введите корректный Gmail"

        if role == "staff" and staff_code != STAFF_REGISTER_CODE:
            return "Ошибка: неверный код сотрудника"

        conn = get_db()
        cur = conn.cursor()

        cur.execute(sql("SELECT id FROM users WHERE email=?"), (email,))
        if cur.fetchone():
            conn.close()
            return "Ошибка: такой Gmail уже зарегистрирован"

        approved = 1 if role == "student" else 0

        cur.execute(sql("""
            INSERT INTO users (full_name, email, password, role, approved)
            VALUES (?, ?, ?, ?, ?)
        """), (
            full_name,
            email,
            generate_password_hash(password),
            role,
            approved
        ))
        cur.execute(sql("SELECT id FROM users WHERE email=?"), (email,))
        row = cur.fetchone()
        user_id = row["id"] if hasattr(row, "keys") else row[0]

        try:
            sent, wait_seconds = request_email_code(conn, user_id, email)
        except Exception as e:
            conn.close()
            return f"Ошибка: не удалось отправить код подтверждения: {e}"

        conn.close()
        if sent:
            return redirect(url_for("verify_email", email=email))
        return redirect(url_for("verify_email", email=email, wait=wait_seconds))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ✅ Инициализация (Postgres)
init_db()
migrate_email_confirm()
migrate_email_codes()
ensure_admin_exists()
ensure_test_users()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
