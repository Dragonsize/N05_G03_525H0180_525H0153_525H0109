import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import bcrypt
from flask import Flask, abort, flash, g, redirect, render_template_string, request, session, url_for

try:
    from .audit_logger import log_security_event, read_audit_logs
    from .db import DEFAULT_DB_PATH, get_db_connection, init_database, safe_execute, safe_query_all, safe_query_one
except ImportError:  # Also support running with source/ as deployment root.
    from audit_logger import log_security_event, read_audit_logs
    from db import DEFAULT_DB_PATH, get_db_connection, init_database, safe_execute, safe_query_all, safe_query_one

ROOT = Path(__file__).resolve().parent.parent
app = Flask(__name__)
secret_key = os.environ.get("SECRET_KEY")
if not secret_key and os.environ.get("RENDER", "").lower() == "true":
    raise RuntimeError("SECRET_KEY must be configured for deployment")
app.config.update(
    SECRET_KEY=secret_key or "local-development-key-change-me",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER", "").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

# Small server-rendered UI keeps this assignment focused on backend access control.
PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>University Records</title><style>
*{box-sizing:border-box}body{font:16px system-ui,sans-serif;background:#f3f5f9;color:#172033;margin:0}.wrap{max-width:1050px;margin:36px auto;padding:0 18px}.card{background:white;border:1px solid #dce2ec;border-radius:12px;padding:22px;margin:16px 0;box-shadow:0 3px 14px #1720330a}h1,h2{margin-top:0}a{color:#2459bc}input,select,button{font:inherit;padding:9px 11px;border:1px solid #bac5d5;border-radius:7px;margin:4px 4px 4px 0}button{background:#1d4ed8;color:white;border:0;cursor:pointer}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:9px;border-bottom:1px solid #e5e9f0}.msg{padding:10px;background:#e8f5e9;border-radius:6px}.nav{display:flex;gap:14px;flex-wrap:wrap}.muted{color:#667085;font-size:.9rem}.row{display:flex;gap:12px;flex-wrap:wrap}.row>*{flex:1;min-width:180px}code{overflow-wrap:anywhere}</style></head><body><main class="wrap"><header><h1>University Records System</h1>{% if user %}<div class="nav"><span>{{ user['full_name'] }} · {{ roles|join(', ') }}</span><a href="{{ url_for('dashboard') }}">Dashboard</a><form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Log out</button></form></div>{% endif %}</header>{% for message in get_flashed_messages() %}<p class="msg">{{ message }}</p>{% endfor %}{{ body|safe }}</main></body></html>'''


def _table_exists(conn, name):
    return safe_query_one(conn, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)) is not None


def _database_path():
    return os.environ.get("URS_DB_PATH", str(DEFAULT_DB_PATH))


def _ensure_database():
    path = Path(_database_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection(str(path))
    try:
        # schema.sql drops tables when invoked, so initialize only on a new database.
        if not _table_exists(conn, "users"):
            init_database(conn=conn)
    finally:
        conn.close()


@app.before_request
def open_request_db():
    _ensure_database()
    g.db = get_db_connection(_database_path())
    g.user = None
    token = session.get("session_token")
    if token:
        hashed = hashlib.sha256(token.encode()).hexdigest()
        active = safe_query_one(g.db, """SELECT u.id,u.username,u.full_name,u.is_active,us.id AS session_id
            FROM user_sessions us JOIN users u ON u.id=us.user_id
            WHERE us.session_token_hash=? AND us.is_revoked=0 AND us.expires_at > datetime('now')""", (hashed,))
        if active and active["is_active"]:
            g.user = active
        else:
            session.clear()


@app.teardown_request
def close_request_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def roles_for(uid):
    rows = safe_query_all(g.db, "SELECT r.role_name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=?", (uid,))
    return [row["role_name"] for row in rows]


def audit(event, target, result="SUCCESS", details=""):
    user = g.user or {}
    log_security_event(g.db, user.get("id"), user.get("username", "anonymous"), event, target, result, details,
                       request.remote_addr or "127.0.0.1")


def page(body, **context):
    user = g.get("user")
    roles = roles_for(user["id"]) if user else []
    csrf = session.setdefault("csrf", secrets.token_urlsafe(24))
    return render_template_string(PAGE, body=render_template_string(body, **context), user=user, roles=roles, csrf=csrf)


def require_login(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


def require_role(*allowed):
    def deco(fn):
        @wraps(fn)
        @require_login
        def wrapped(*args, **kwargs):
            current_roles = roles_for(g.user["id"])
            if not any(role in current_roles for role in allowed):
                audit("UNAUTHORIZED_ACCESS_REJECTED", request.path, "REJECTED", "Role authorization denied")
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco


def csrf_check():
    expected = session.get("csrf", "")
    supplied = request.form.get("csrf", "")
    if not expected or not hmac.compare_digest(expected, supplied):
        abort(400, "Invalid CSRF token")


@app.route("/")
def index():
    return redirect(url_for("dashboard") if g.user else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        csrf_check()
        username = request.form.get("username", "")[:50]
        password = request.form.get("password", "")
        user = safe_query_one(g.db, "SELECT id,username,password_hash,is_active FROM users WHERE username=?", (username,))
        valid = False
        if user and user["is_active"]:
            try:
                valid = bcrypt.checkpw(password.encode(), user["password_hash"].encode())
            except (ValueError, TypeError):
                valid = False
        if not valid:
            log_security_event(g.db, user["id"] if user else None, username or "anonymous", "LOGIN_FAILED", "auth/login", "FAILURE", "Invalid login credentials", request.remote_addr or "127.0.0.1")
            flash("Invalid username or password")
        else:
            raw = secrets.token_urlsafe(32)
            hashed = hashlib.sha256(raw.encode()).hexdigest()
            expires = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
            safe_execute(g.db, "INSERT INTO user_sessions(user_id,session_token_hash,expires_at) VALUES(?,?,?)", (user["id"], hashed, expires))
            session.clear()
            session["session_token"] = raw
            session["csrf"] = secrets.token_urlsafe(24)
            session.permanent = True
            log_security_event(g.db, user["id"], user["username"], "LOGIN_SUCCESS", "auth/login", "SUCCESS", "User logged in", request.remote_addr or "127.0.0.1")
            return redirect(url_for("dashboard"))
    return page('''<section class="card"><h2>Sign in</h2><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><p><input name="username" autocomplete="username" required placeholder="Username"></p><p><input type="password" name="password" autocomplete="current-password" required placeholder="Password"></p><button>Sign in</button></form><p class="muted">Demo users: student_an, lecturer_tu, registrar1, auditor1, admin1. Password: password</p></section>''')


@app.post("/logout")
@require_login
def logout():
    csrf_check()
    token = session.get("session_token", "")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    safe_execute(g.db, "UPDATE user_sessions SET is_revoked=1 WHERE session_token_hash=?", (token_hash,))
    audit("LOGOUT", "auth/logout", "SUCCESS", "Session revoked")
    session.clear()
    return redirect(url_for("login"))


@app.get("/dashboard")
@require_login
def dashboard():
    role = roles_for(g.user["id"])
    profile = safe_query_one(g.db, "SELECT id,student_code,major,phone,address FROM student_profiles WHERE user_id=?", (g.user["id"],))
    if "Student" in role and profile:
        grades = safe_query_all(g.db, """SELECT c.course_code,c.course_name,g.midterm_score,g.final_score,g.total_score,g.letter_grade
          FROM enrollments e JOIN courses c ON c.id=e.course_id LEFT JOIN grades g ON g.enrollment_id=e.id WHERE e.student_id=?""", (profile["id"],))
    else:
        grades = []
    courses = []
    if "Lecturer" in role:
        courses = safe_query_all(g.db, "SELECT id,course_code,course_name FROM courses WHERE lecturer_id=?", (g.user["id"],))
    students = safe_query_all(g.db, "SELECT sp.id,sp.student_code,u.full_name,sp.major,sp.phone,sp.address FROM student_profiles sp JOIN users u ON u.id=sp.user_id ORDER BY sp.id") if "Registrar" in role else []
    enrollments = safe_query_all(g.db, "SELECT e.id,sp.student_code,c.course_code,g.final_score FROM enrollments e JOIN student_profiles sp ON e.student_id=sp.id JOIN courses c ON e.course_id=c.id LEFT JOIN grades g ON g.enrollment_id=e.id ORDER BY e.id") if "Lecturer" in role else []
    users = safe_query_all(g.db, "SELECT u.id,u.username,u.full_name,u.is_active,group_concat(r.role_name, ', ') AS roles FROM users u LEFT JOIN user_roles ur ON ur.user_id=u.id LEFT JOIN roles r ON r.id=ur.role_id GROUP BY u.id ORDER BY u.id") if "System Administrator" in role else []
    logs = read_audit_logs(g.db, g.user["id"], g.user["username"], role).get("logs", []) if "Security Auditor" in role else []
    return page('''
    {% if profile %}<section class="card"><h2>My profile</h2><p>{{ profile.student_code }} · {{ profile.major }}</p><form method="post" action="{{ url_for('profile_update',pid=profile.id) }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input name="phone" value="{{ profile.phone or '' }}" placeholder="Phone"><input name="address" value="{{ profile.address or '' }}" placeholder="Address"><button>Save contact info</button></form><h3>My grades</h3>{{ table(grades) }}</section>{% endif %}
    {% if courses %}<section class="card"><h2>Assigned courses</h2>{{ table(courses) }}{% for c in courses %}<p><a href="{{ url_for('roster',cid=c.id) }}">Open roster: {{ c.course_code }}</a></p>{% endfor %}</section>{% endif %}
    {% if enrollments %}<section class="card"><h2>Grade entry</h2>{{ table(enrollments) }}{% for e in enrollments %}<form class="row" method="post" action="{{ url_for('grade_update',eid=e.id) }}"><input type="hidden" name="csrf" value="{{ csrf }}"><span>{{ e.student_code }} · {{ e.course_code }}</span><input name="score" type="number" min="0" max="10" step="0.1" required placeholder="Final score"><button>Save grade</button></form>{% endfor %}</section>{% endif %}
    {% if students %}<section class="card"><h2>Student records</h2>{{ table(students) }}<h3>Create enrollment</h3><form method="post" action="{{ url_for('enroll') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><select name="student_id">{% for s in students %}<option value="{{ s.id }}">{{ s.student_code }} — {{ s.full_name }}</option>{% endfor %}</select><select name="course_id">{% for c in all_courses %}<option value="{{ c.id }}">{{ c.course_code }} — {{ c.course_name }}</option>{% endfor %}</select><button>Enroll</button></form></section>{% endif %}
    {% if users %}<section class="card"><h2>User administration</h2>{{ table(users) }}{% for u in users %}<form method="post" action="{{ url_for('disable_user',uid=u.id) }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button {% if not u.is_active %}disabled{% endif %}>Disable {{ u.username }}</button></form>{% endfor %}</section>{% endif %}
    {% if logs %}<section class="card"><h2>Audit trail</h2>{{ table(logs) }}</section>{% endif %}
    {% if not profile and not courses and not students and not users and not logs %}<section class="card"><p>Signed in. No additional records available for your roles.</p></section>{% endif %}
    ''', profile=profile, grades=grades, courses=courses, enrollments=enrollments, students=students, all_courses=safe_query_all(g.db,"SELECT id,course_code,course_name FROM courses"), users=users, logs=logs, table=_table_html)


def _table_html(rows):
    if not rows:
        return '<p class="muted">No records.</p>'
    headers = list(rows[0].keys())
    out = '<div style="overflow:auto"><table><thead><tr>' + ''.join(f'<th>{h}</th>' for h in headers) + '</tr></thead><tbody>'
    # Render as escaped text, never trust stored data as markup.
    from markupsafe import Markup, escape
    for row in rows:
        out += '<tr>' + ''.join(f'<td>{escape(str(row[h]) if row[h] is not None else "")}</td>' for h in headers) + '</tr>'
    return Markup(out + '</tbody></table></div>')


@app.post("/profile/<int:pid>")
@require_login
def profile_update(pid):
    csrf_check()
    roles = roles_for(g.user["id"])
    profile = safe_query_one(g.db, "SELECT user_id FROM student_profiles WHERE id=?", (pid,))
    if not profile or not ("Registrar" in roles or ("Student" in roles and profile["user_id"] == g.user["id"])):
        audit("UNAUTHORIZED_ACCESS_REJECTED", f"student_profile:{pid}", "REJECTED", "Profile ownership check failed")
        abort(403)
    phone, address = request.form.get("phone", "")[:20], request.form.get("address", "")[:255]
    safe_execute(g.db, "UPDATE student_profiles SET phone=?,address=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (phone,address,pid))
    audit("PROFILE_UPDATED", f"student_profile:{pid}", "SUCCESS", "Contact information updated")
    flash("Profile updated")
    return redirect(url_for("dashboard"))


@app.get("/course/<int:cid>/roster")
@require_role("Lecturer", "Registrar")
def roster(cid):
    course = safe_query_one(g.db, "SELECT id,course_code,lecturer_id FROM courses WHERE id=?", (cid,))
    if not course or ("Lecturer" in roles_for(g.user["id"]) and "Registrar" not in roles_for(g.user["id"]) and course["lecturer_id"] != g.user["id"]):
        audit("UNAUTHORIZED_ACCESS_REJECTED", f"course:{cid}/roster", "REJECTED", "Course assignment check failed")
        abort(403)
    rows = safe_query_all(g.db, "SELECT sp.student_code,u.full_name,e.id AS enrollment_id,g.final_score FROM enrollments e JOIN student_profiles sp ON sp.id=e.student_id JOIN users u ON u.id=sp.user_id LEFT JOIN grades g ON g.enrollment_id=e.id WHERE e.course_id=?", (cid,))
    return page('''<section class="card"><h2>Roster: {{ code }}</h2>{{ table(rows) }}<a href="{{ url_for('dashboard') }}">Back</a></section>''', code=course["course_code"], rows=rows, table=_table_html)


@app.post("/grade/<int:eid>")
@require_role("Lecturer")
def grade_update(eid):
    csrf_check()
    item = safe_query_one(g.db, "SELECT e.id,c.course_code,c.lecturer_id FROM enrollments e JOIN courses c ON c.id=e.course_id WHERE e.id=?", (eid,))
    try:
        score = float(request.form.get("score", ""))
    except ValueError:
        abort(400, "Score must be numeric")
    if not item or item["lecturer_id"] != g.user["id"]:
        audit("GRADE_MODIFY_REJECTED", f"enrollment:{eid}", "REJECTED", "Course assignment check failed")
        abort(403)
    if not 0 <= score <= 10:
        abort(400, "Score must be between 0 and 10")
    exists = safe_query_one(g.db,"SELECT id FROM grades WHERE enrollment_id=?",(eid,))
    if exists:
        result=safe_execute(g.db,"UPDATE grades SET final_score=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE enrollment_id=?",(score,g.user["id"],eid))
    else:
        result=safe_execute(g.db,"INSERT INTO grades(enrollment_id,final_score,updated_by) VALUES(?,?,?)",(eid,score,g.user["id"]))
    if not result["ok"]:
        abort(400, result.get("error", "Grade update failed"))
    audit("GRADE_MODIFIED", f"enrollment:{eid}", "SUCCESS", f"Final score updated for {item['course_code']}")
    flash("Grade saved")
    return redirect(url_for("dashboard"))


@app.post("/enroll")
@require_role("Registrar")
def enroll():
    csrf_check()
    result=safe_execute(g.db,"INSERT INTO enrollments(student_id,course_id,enrolled_by,status) VALUES(?,?,?,'ENROLLED')",(request.form.get("student_id"),request.form.get("course_id"),g.user["id"]))
    if not result["ok"]:
        flash("Enrollment could not be created")
    else:
        audit("ENROLLMENT_CREATED",f"enrollment:{result['lastrowid']}","SUCCESS","Registrar created enrollment")
        flash("Enrollment created")
    return redirect(url_for("dashboard"))


@app.post("/admin/user/<int:uid>/disable")
@require_role("System Administrator")
def disable_user(uid):
    csrf_check()
    safe_execute(g.db,"UPDATE users SET is_active=0 WHERE id=?",(uid,))
    safe_execute(g.db,"UPDATE user_sessions SET is_revoked=1 WHERE user_id=?",(uid,))
    audit("USER_DISABLED",f"user:{uid}","SUCCESS","Account disabled and sessions revoked")
    flash("User disabled; active sessions revoked")
    return redirect(url_for("dashboard"))


@app.errorhandler(403)
def forbidden(_error):
    return page('<section class="card"><h2>403 Forbidden</h2><p>Access denied. Attempt recorded in audit log.</p></section>'), 403


@app.errorhandler(400)
def bad_request(error):
    return page('<section class="card"><h2>400 Bad Request</h2><p>{{ message }}</p></section>', message=getattr(error, "description", "Invalid request")), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
