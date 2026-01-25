from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from pathlib import Path
from functools import wraps

from werkzeug.utils import secure_filename
from uuid import uuid4
import os
from datetime import datetime
import re
from sqlite3 import IntegrityError

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


app = Flask(__name__)

app.secret_key = "dev_key_123"
import os
from werkzeug.security import generate_password_hash, check_password_hash

STAFF_REGISTER_CODE = os.getenv("STAFF_REGISTER_CODE", "AKS&T-STAFF-2026")

ALLOWED_AVATAR_EXT = {"png", "jpg", "jpeg", "webp"}
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # 1) USERS (новая схема)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL,              -- student / staff / admin
        approved INTEGER NOT NULL DEFAULT 1  -- для staff можно будет ставить 0 до подтверждения
    )
    """)

    # 2) REQUESTS (как было)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        req_type TEXT NOT NULL,
        title TEXT NOT NULL,
        body_text TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('review','accepted','returned')) DEFAULT 'review',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")

def normalize_username(v: str) -> str:
    return (v or "").strip().lower()

def is_valid_username(v: str) -> bool:
    return bool(USERNAME_RE.match(v))

def migrate_add_username_column():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("PRAGMA table_info(users)")
    cols = [c[1] for c in cur.fetchall()]

    if "username" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN username TEXT")
        conn.commit()

    # уникальный индекс (если ещё не создан)
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    conn.commit()
    conn.close()


def migrate_users_table_if_needed():
    conn = get_db()
    cur = conn.cursor()

    # Проверяем структуру таблицы users
    cur.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in cur.fetchall()]  # row[1] = name

    # если уже есть email/approved — значит новая структура, ничего не делаем
    if "email" in cols and "approved" in cols and "role" in cols:
        conn.close()
        return

    # Иначе — делаем миграцию: переименуем старую и создадим новую
    cur.execute("ALTER TABLE users RENAME TO users_old")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('student','staff','admin')) DEFAULT 'student',
        staff_code TEXT,
        approved INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """)

    # переносим старых пользователей (username кладём в email как есть, чтобы не потерять записи)
    from datetime import datetime
    cur.execute("""
    INSERT INTO users (id, full_name, email, password, role, approved, created_at)
    SELECT id,
        full_name,
        username as email,
        password,
        CASE role WHEN 'staff' THEN 'staff' ELSE 'student' END,
        1,
        ?
    FROM users_old
    """, (datetime.now().isoformat(),))

    conn.commit()
    conn.close()

def migrate_add_avatar_column():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(users)")
    cols = [c[1] for c in cur.fetchall()]
    if "avatar" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN avatar TEXT")
        conn.commit()
    conn.close()

def migrate_add_profile_fields():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in cur.fetchall()]

    if "avatar" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN avatar TEXT")
    if "group_name" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN group_name TEXT")
    if "birth_year" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN birth_year INTEGER")
    if "bio" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN bio TEXT")

    conn.commit()
    conn.close()


def find_user(email, password):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    conn.close()

    if not user:
        return None

    if not check_password_hash(user["password"], password):
        return None

    return user


ADMIN_EMAIL = "shingissuleymen@gmail.com"
ADMIN_PASSWORD = "Asylym_0309"
ADMIN_FULLNAME = "Сулеймен Шынгысхан"
ADMIN_DELETE_CODE = "0309"


def ensure_admin_exists():
    conn = get_db()
    cur = conn.cursor()

    admin_email = ADMIN_EMAIL.strip().lower()
    admin_hash = generate_password_hash(ADMIN_PASSWORD)

    # ищем админа по email (самый надежный ключ)
    cur.execute("SELECT id FROM users WHERE email=?", (admin_email,))
    row = cur.fetchone()

    if row:
        # обновляем существующую запись (исправит старый пароль/роль)
        cur.execute("""
            UPDATE users
            SET full_name=?,
                password=?,
                role='admin',
                approved=1
            WHERE id=?
        """, (ADMIN_FULLNAME, admin_hash, row["id"]))
    else:
        # создаём нового
        cur.execute("""
            INSERT INTO users (full_name, email, password, role, approved)
            VALUES (?, ?, ?, 'admin', 1)
        """, (ADMIN_FULLNAME, admin_email, admin_hash))

    conn.commit()
    conn.close()

def calc_age(birth_year: int | None) -> int | None:
    if not birth_year:
        return None
    y = datetime.now().year
    if birth_year < 1900 or birth_year > y:
        return None
    return y - birth_year


@app.route("/profile")
@login_required
@role_required("student", "staff")
def profile_view():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, full_name, email, role, avatar, group_name, birth_year, bio
        FROM users
        WHERE id=?
    """, (session["user_id"],))
    u = cur.fetchone()
    conn.close()

    age = calc_age(u["birth_year"])
    return render_template("profile.html", u=u, age=age)


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
@role_required("student", "staff")
def profile_edit():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, full_name, email, role, avatar, group_name, birth_year, bio
        FROM users
        WHERE id=?
    """, (session["user_id"],))
    u = cur.fetchone()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        birth_year_raw = request.form.get("birth_year", "").strip()
        bio = request.form.get("bio", "").strip()
        group_name_new = request.form.get("group_name", "").strip()

        # год рождения
        birth_year = None
        if birth_year_raw:
            try:
                birth_year = int(birth_year_raw)
            except:
                birth_year = None

        # группа: выбрать можно только 1 раз
        group_to_save = u["group_name"]
        if not u["group_name"] and group_name_new:
            group_to_save = group_name_new  # только если раньше не было

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

        if not full_name:
            conn.close()
            return "Введите ФИО"

        cur.execute("""
            UPDATE users
            SET full_name=?, birth_year=?, bio=?, group_name=?, avatar=?
            WHERE id=?
        """, (full_name, birth_year, bio, group_to_save, avatar_rel, session["user_id"]))
        conn.commit()
        conn.close()

        # обновим session (чтобы сразу отражалось в шапке)
        session["full_name"] = full_name

        return redirect(url_for("profile_view"))

    conn.close()

    age = calc_age(u["birth_year"])
    group_locked = bool(u["group_name"])  # если уже есть — блокируем выбор
    allowed_groups = ["2ВТ-9А2"]          # пока одна группа

    return render_template(
        "profile_edit.html",
        u=u,
        age=age,
        group_locked=group_locked,
        allowed_groups=allowed_groups
    )


def ensure_test_users():
    conn = get_db()
    cur = conn.cursor()

    users = [
        {
            "full_name": "Тест Студент",
            "email": "student1",
            "password": "1234",
            "role": "student",
            "approved": 1
        },
        {
            "full_name": "Тест Сотрудник",
            "email": "staff1",
            "password": "1234",
            "role": "staff",
            "approved": 1
        }
    ]

    for u in users:
        cur.execute("SELECT id FROM users WHERE email=?", (u["email"],))
        if not cur.fetchone():
            cur.execute("""
                INSERT INTO users (full_name, email, password, role, approved)
                VALUES (?, ?, ?, ?, ?)
            """, (
                u["full_name"],
                u["email"],
                generate_password_hash(u["password"]),
                u["role"],
                u["approved"]
            ))

    conn.commit()
    conn.close()



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
@role_required("staff" , "admin")
def panel_request_set_status(req_id, status):
    if status not in ("review", "accepted", "returned"):
        return "Неверный статус"

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE requests
        SET status=?, updated_at=?
        WHERE id=?
    """, (status, datetime.now().isoformat(), req_id))
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
            # если staff и ещё не подтверждён
            if user["role"] == "staff" and int(user["approved"]) != 1:
                return "Доступ сотрудника ожидает подтверждения администратора"

            session["user_id"] = user["id"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            session["avatar"] = user["avatar"]  # может быть None

            if user["role"] == "student":
                return redirect(url_for("student_dashboard"))
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("staff_dashboard"))
        else:
            return "Ошибка: неверный email или пароль"

    return render_template("login.html")

# =========================
# Главный админ (admin)
# =========================

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
    cur.execute("DELETE FROM requests WHERE user_id=?", (user_id,))
    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
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
    cur.execute("""
        SELECT r.*, u.full_name, u.email
        FROM requests r
        JOIN users u ON u.id = r.user_id
        WHERE r.id=?
    """, (req_id,))
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

from datetime import datetime


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
        cur.execute("""
            INSERT INTO requests (user_id, req_type, title, body_text, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'review', ?, ?)
        """, (
            session["user_id"],
            req_type,
            title,
            body_text,
            datetime.now().isoformat(),
            datetime.now().isoformat()
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
    cur.execute("""
        SELECT id, req_type, title, status, created_at
        FROM requests
        WHERE user_id = ?
        ORDER BY id DESC
    """, (session["user_id"],))
    rows = cur.fetchall()
    conn.close()

    return render_template("my_requests.html", rows=rows)

@app.route("/request/delete/<int:req_id>", methods=["POST"])
def delete_request(req_id):
    # 1) проверка что вошел
    if not session.get("user_id"):
        return redirect(url_for("login"))

    # 2) удаляем только свои заявки (безопасно)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM requests WHERE id=? AND user_id=? AND status 'review' ",
        (req_id, session["user_id"])
    )
    conn.commit()
    conn.close()

    # 3) ВСЕГДА возвращаем ответ
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
    cur.execute("UPDATE users SET approved=1 WHERE id=? AND role='staff'", (user_id,))
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
    cur.execute("DELETE FROM users WHERE id=? AND role='staff'", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_staff_approvals"))


@app.route("/panel/request/<int:req_id>")
@login_required
@role_required("staff")
def panel_request_view(req_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT r.*, u.full_name, u.email
        FROM requests r
        JOIN users u ON u.id = r.user_id
        WHERE r.id=?
    """, (req_id,))
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
    cur.execute("""
        UPDATE requests
        SET status = ?, updated_at = ?
        WHERE id = ?
    """, (status, datetime.now().isoformat(), req_id))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_requests"))


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

        # 🔹 ПРОВЕРКА EMAIL
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        if cur.fetchone():
            conn.close()
            return "Ошибка: такой Gmail уже зарегистрирован"

        # 🔹 APPROVED (РАЗДЕЛ 3)
        approved = 1 if role == "student" else 0

        # 🔹 INSERT
        cur.execute("""
            INSERT INTO users (full_name, email, password, role, approved)
            VALUES (?, ?, ?, ?, ?)
        """, (
            full_name,
            email,
            generate_password_hash(password),
            role,
            approved
        ))

        conn.commit()
        conn.close()
        return redirect(url_for("login"))


    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ✅ Инициализация для Railway/Gunicorn (когда файл импортируется)
init_db()
migrate_users_table_if_needed()
migrate_add_username_column()
migrate_add_avatar_column()
migrate_add_profile_fields()
ensure_admin_exists()
ensure_test_users()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)