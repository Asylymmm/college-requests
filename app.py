from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from pathlib import Path
from functools import wraps

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

def ensure_test_users():
    conn = get_db()
    cur = conn.cursor()

    users = [
        {
            "full_name": "Тест Студент",
            "email": "student1",
            "password": "123456",
            "role": "student",
            "approved": 1
        },
        {
            "full_name": "Тест Сотрудник",
            "email": "staff1",
            "password": "123456",
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
@role_required("staff", "admin")
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
    cur.execute("""
        UPDATE requests
        SET status=?, updated_at=?
        WHERE id=?
    """, (status, datetime.now().isoformat(), req_id))
    conn.commit()
    conn.close()
    return redirect(url_for("panel_requests"))

@app.route("/panel/request/<int:req_id>")
@login_required
@role_required("staff", "admin")
def panel_request_view(req_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT r.*, u.full_name, u.email
        FROM requests r
        JOIN users u ON u.id = r.user_id
        WHERE r.id = ?
    """, (req_id,))
    r = cur.fetchone()
    conn.close()

    if not r:
        return "Заявка не найдена"

    # ВАЖНО: имя файла ТОЧНО как в templates
    return render_template("panel_request_view.html", r=r)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    role = session.get("role")
    if role == "student":
        return redirect(url_for("student_dashboard"))
    if role in ("staff", "admin"):
        return redirect(url_for("staff_dashboard"))
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

            if user["role"] == "student":
                return redirect(url_for("student_dashboard"))
            else:
                # staff и admin
                return redirect(url_for("panel_requests"))
        else:
            return "Ошибка: неверный email или пароль"

    return render_template("login.html")

@app.route("/student")
def student_dashboard():
    return render_template("student.html", full_name=session.get("full_name", "Неизвестно"))

@app.route("/staff")
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
        "DELETE FROM requests WHERE id=? AND user_id=?",
        (req_id, session["user_id"])
    )
    conn.commit()
    conn.close()

    # 3) ВСЕГДА возвращаем ответ
    return redirect(url_for("my_requests"))

@app.route("/admin/requests")
def admin_requests():
    if session.get("role") != "staff":
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT r.id, r.req_type, r.title, r.status, r.created_at, u.full_name
        FROM requests r
        JOIN users u ON u.id = r.user_id
        ORDER BY r.id DESC
    """)
    rows = cur.fetchall()
    conn.close()

    return render_template("admin_requests.html", rows=rows)

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
    conn = get_db()
    cur = conn.cursor()
    # вариант 1: удалить
    cur.execute("DELETE FROM users WHERE id=? AND role='staff'", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_staff_approvals"))


@app.route("/admin/request/<int:req_id>")
def admin_request_view(req_id):
    if session.get("role") != "staff":
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT r.id, r.req_type, r.title, r.body_text, r.status, r.created_at, u.full_name
        FROM requests r
        JOIN users u ON u.id = r.user_id
        WHERE r.id = ?
    """, (req_id,))
    r = cur.fetchone()
    conn.close()

    if not r:
        return "Заявление не найдено"

    return render_template("panel_request_view.html", r=r)

@app.route("/admin/request/<int:req_id>/status/<status>", methods=["POST"])
def admin_request_set_status(req_id, status):
    if session.get("role") != "staff":
        return redirect(url_for("login"))

    if status not in ("review", "accepted", "returned"):
        return "Неверный статус"

    from datetime import datetime
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE requests
        SET status = ?, updated_at = ?
        WHERE id = ?
    """, (status, datetime.now().isoformat(), req_id))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_request_view", req_id=req_id))

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
ensure_admin_exists()
ensure_test_users()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)