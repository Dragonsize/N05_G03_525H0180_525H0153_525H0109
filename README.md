# University Records System

Flask application for managing university student records, enrollments, grades, user accounts, and security audit events. The project demonstrates role-based and record-level access control.

**Live Demo (Render):** <https://bigassignmentinfosecyes.onrender.com/login>

## Requirements

- Python 3.12 or newer
- Dependencies listed in `source/requirements.txt`

## Run locally

From the repository root, create and activate a virtual environment, then install dependencies:

```cmd
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r source/requirements.txt
```

Set a local Flask secret and start the app:

```cmd
set SECRET_KEY=my-local-secret-key-123456
python source/app.py
```


Open <http://127.0.0.1:5000>. The app initializes the SQLite database and inserts demo data when the configured database has no `users` table. By default, local data is stored in `database/university_records.db`. To use another database file, set `URS_DB_PATH` before starting the app.

> `database/schema.sql` drops and recreates tables. Do not run schema initialization against a database whose data you need to keep.

## Demo accounts

Seeded accounts use password `password`. Change demo credentials before exposing an instance publicly. One account is intentionally disabled for access-control testing.

| Username | Role(s) | Status |
|---|---|---|
| `admin1` | System Administrator | Active |
| `auditor1` | Security Auditor | Active |
| `registrar1` | Registrar | Active |
| `lecturer_tu` | Lecturer | Active |
| `lecturer_other` | Lecturer | Active |
| `student_an` | Student | Active |
| `student_khoi` | Student | Active |
| `student_phat` | Student | Active |
| `student_disabled` | Student | Disabled |
| `lecturer_auditor` | Lecturer, Security Auditor | Active |

Users can change their own password from the dashboard. Passwords are stored as bcrypt hashes and cannot be retrieved in plaintext.

## Roles and features

- **Student:** view own grades and update own contact information.
- **Lecturer:** view assigned course rosters and update grades for assigned courses.
- **Registrar:** view student records and create enrollments.
- **Security Auditor:** read audit logs.
- **System Administrator:** enable or disable user accounts.

Protected routes enforce permissions server-side. Forms include CSRF tokens; database operations use parameterized queries; HTML output is escaped; relevant security events are audit-logged.

## Tests

Run the project security test script from the repository root:

```powershell
python tests/test_security.py
```

The script runs 30 security checks covering authentication, authorization, ownership, injection, validation, and audit-log protections. These tests are a standalone script; `pytest` does not discover them as pytest test functions.

## Deploy to Render

The repository-root `render.yaml` defines a Render Blueprint:

- Root directory: `source`
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`
- SQLite path: `/var/data/university_records.db`
- Persistent disk mount: `/var/data`

Create or update a Blueprint in Render using the branch containing `render.yaml`. A regular Web Service does not automatically adopt Blueprint settings; review/apply the Blueprint configuration in Render. The SQLite disk keeps database data across deploys, but local database contents and local password changes are not copied to Render. A newly initialized Render database uses the demo accounts from `database/seed-data.sql`.

## Project layout

```text
source/       Flask application, database helpers, audit logger, dependencies
 database/    SQLite schema and seed data
 tests/       Security test plan and executable security tests
 render.yaml  Render Blueprint configuration
```
