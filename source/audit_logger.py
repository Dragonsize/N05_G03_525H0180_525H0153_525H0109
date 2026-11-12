#!/usr/bin/env python3
"""
Append-Only Security Audit Logging Module
File: source/audit_logger.py
Primary Responsibility: STUDENT C (Database Security, Testing & Audit Logging)
Enforces Section 3.3 & Task 3 Required Audit Events:
  - Logs: Successful login, Failed login, Logout, User creation/disabling,
    Role assignment/removal, Successful grade creation/modification,
    Rejected grade modification, Rejected access to another user's record.
  - Scrubs sensitive data: Passwords, session tokens, and DB secrets NEVER appear in logs.
"""

import re
from typing import Optional

try:
    from .db import safe_execute, safe_query_all
except ImportError:
    from db import safe_execute, safe_query_all

# Biểu thức chính quy tự động phát hiện và che (mask) mật khẩu, token, secret
SENSITIVE_PATTERNS = [
    re.compile(r"(password\s*[=:]\s*)([^\s,;]+)", re.IGNORECASE),
    re.compile(r"(passwd\s*[=:]\s*)([^\s,;]+)", re.IGNORECASE),
    re.compile(r"(session_token\s*[=:]\s*)([^\s,;]+)", re.IGNORECASE),
    re.compile(r"(token\s*[=:]\s*)([^\s,;]+)", re.IGNORECASE),
    re.compile(r"(secret\s*[=:]\s*)([^\s,;]+)", re.IGNORECASE),
    re.compile(r"(\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53})"),
]


def sanitize_log_details(details: Optional[str]) -> str:
    """
    Ensure passwords, password hashes, session tokens, and database credentials
    never appear in audit logs (Task 3 requirement).
    """
    if not details:
        return ""
    sanitized = str(details)
    for pattern in SENSITIVE_PATTERNS:
        if pattern.groups == 2:
            sanitized = pattern.sub(r"\1[REDACTED]", sanitized)
        else:
            sanitized = pattern.sub("[REDACTED_HASH]", sanitized)
    return sanitized


def log_security_event(
    conn,
    acting_user_id: Optional[int],
    acting_username: str,
    event_type: str,
    target_resource: str,
    result: str,
    details: str = "",
    ip_address: str = "127.0.0.1",
) -> bool:
    """
    Insert an immutable security event into the append-only audit_logs table.
    """
    clean_username = (acting_username or "anonymous").strip()[:50]
    clean_event = (event_type or "UNKNOWN_EVENT").strip()[:80]
    clean_target = (target_resource or "system").strip()[:150]
    clean_result = result if result in ("SUCCESS", "FAILURE", "REJECTED") else "FAILURE"
    clean_details = sanitize_log_details(details)

    sql = """
        INSERT INTO audit_logs (
            acting_user_id, acting_username, event_type,
            target_resource, result, details, ip_address
        )
        VALUES (?, ?, ?, ?, ?, ?, ?);
    """
    res = safe_execute(
        conn,
        sql,
        (
            acting_user_id,
            clean_username,
            clean_event,
            clean_target,
            clean_result,
            clean_details,
            ip_address,
        ),
    )
    return res["ok"]


def read_audit_logs(conn, acting_user_id: int, acting_username: str, user_roles: list):
    """
    Read audit logs. Strictly restricted to users holding the 'Security Auditor' role.
    Logs unauthorized attempts if another role tries to read audit logs.
    """
    if "Security Auditor" not in user_roles:
        log_security_event(
            conn=conn,
            acting_user_id=acting_user_id,
            acting_username=acting_username,
            event_type="UNAUTHORIZED_ACCESS_REJECTED",
            target_resource="audit_logs",
            result="REJECTED",
            details="Access denied: Only Security Auditor role can read audit logs",
        )
        return {"authorized": False, "error": "403 Forbidden: Security Auditor role required.", "logs": []}

    logs = safe_query_all(
        conn,
        """
        SELECT id, timestamp, acting_user_id, acting_username,
               event_type, target_resource, result, details, ip_address
        FROM audit_logs
        ORDER BY id ASC;
        """,
    )
    return {"authorized": True, "logs": logs}