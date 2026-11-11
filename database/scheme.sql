-- ============================================================================
-- UNIVERSITY RECORDS SYSTEM - DATABASE SCHEMA (TASK 3: DATABASE SECURITY)
-- File: database/schema.sql
-- Primary Responsibility: STUDENT C (Database Security, Testing & Audit Logging)
-- ============================================================================
PRAGMA foreign_keys = ON;
DROP TRIGGER IF EXISTS trg_audit_logs_no_update;
DROP TRIGGER IF EXISTS trg_audit_logs_no_delete;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS grades;
DROP TABLE IF EXISTS enrollments;
DROP TABLE IF EXISTS courses;
DROP TABLE IF EXISTS student_profiles;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;
-- ============================================================================
-- 1. BẢNG USERS (Phục vụ mục 3.1 Authentication & Test T01, T02, T03, T05)
-- - password_hash: Lưu chuỗi băm Bcrypt/Argon2/PBKDF2 (cấm lưu plaintext).
-- - is_active: 1 = Hoạt động, 0 = Bị vô hiệu hóa (chặn đăng nhập ở Test T03).
-- ============================================================================
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- ============================================================================
-- 2. BẢNG ROLES (Đúng 5 vai trò bắt buộc trong mục 2 System Scenario)
-- ============================================================================
CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name VARCHAR(50) NOT NULL UNIQUE CHECK (
        role_name IN (
            'Student',
            'Lecturer',
            'Registrar',
            'Security Auditor',
            'System Administrator'
        )
    ),
    description VARCHAR(255) NOT NULL
);
-- ============================================================================
-- 3. BẢNG USER_ROLES (Hỗ trợ Multi-Role: 1 user có thể giữ nhiều vai trò)
-- ============================================================================
CREATE TABLE user_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    assigned_by INTEGER,
    assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE
    SET NULL
);
-- ============================================================================
-- 4. BẢNG USER_SESSIONS (Hỗ trợ quản lý phiên & Test T04: Hủy session khi Logout)
-- - Lưu mã băm của session/token (session_token_hash), KHÔNG lưu token rõ.
-- - Khi user nhấn Logout, cập nhật is_revoked = 1 để chặn dùng lại session cũ.
-- ============================================================================
CREATE TABLE user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token_hash VARCHAR(255) NOT NULL UNIQUE,
    is_revoked INTEGER NOT NULL DEFAULT 0 CHECK (is_revoked IN (0, 1)),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
-- ============================================================================
-- 5. BẢNG STUDENT_PROFILES (Hồ sơ sinh viên - Kiểm tra Ownership ở T06, T07)
-- - Liên kết 1-1 với bảng users qua cột user_id.
-- - Student chỉ được sửa phone, address của chính mình; Registrar tạo/sửa hồ sơ.
-- ============================================================================
CREATE TABLE student_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    student_code VARCHAR(20) NOT NULL UNIQUE,
    date_of_birth DATE NOT NULL,
    major VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    address VARCHAR(255),
    enrollment_year INTEGER NOT NULL CHECK (
        enrollment_year >= 2000
        AND enrollment_year <= 2100
    ),
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
-- ============================================================================
-- 6. BẢNG COURSES (Khóa học - Kiểm tra Assigned Course của Lecturer ở T09-T11)
-- - lecturer_id liên kết tới users(id) của giảng viên phụ trách môn đó.
-- ============================================================================
CREATE TABLE courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_code VARCHAR(20) NOT NULL UNIQUE,
    course_name VARCHAR(150) NOT NULL,
    credits INTEGER NOT NULL CHECK (
        credits > 0
        AND credits <= 10
    ),
    semester VARCHAR(30) NOT NULL,
    lecturer_id INTEGER,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (lecturer_id) REFERENCES users(id) ON DELETE
    SET NULL
);
-- ============================================================================
-- 7. BẢNG ENROLLMENTS (Đăng ký môn học - Phục vụ Registrar ở Test T12)
-- ============================================================================
CREATE TABLE enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    enrolled_by INTEGER,
    status VARCHAR(20) NOT NULL DEFAULT 'ENROLLED' CHECK (
        status IN ('ENROLLED', 'DROPPED', 'COMPLETED')
    ),
    enrolled_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (student_id, course_id),
    FOREIGN KEY (student_id) REFERENCES student_profiles(id) ON DELETE CASCADE,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
    FOREIGN KEY (enrolled_by) REFERENCES users(id) ON DELETE
    SET NULL
);
-- ============================================================================
-- 8. BẢNG GRADES (Điểm số - Phục vụ Test T06, T08, T10, T11, T13, T17)
-- ============================================================================
CREATE TABLE grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enrollment_id INTEGER NOT NULL UNIQUE,
    midterm_score REAL CHECK (
        midterm_score IS NULL
        OR (
            midterm_score >= 0.0
            AND midterm_score <= 10.0
        )
    ),
    final_score REAL CHECK (
        final_score IS NULL
        OR (
            final_score >= 0.0
            AND final_score <= 10.0
        )
    ),
    total_score REAL CHECK (
        total_score IS NULL
        OR (
            total_score >= 0.0
            AND total_score <= 10.0
        )
    ),
    letter_grade VARCHAR(5) CHECK (
        letter_grade IS NULL
        OR letter_grade IN ('A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'F')
    ),
    updated_by INTEGER,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (enrollment_id) REFERENCES enrollments(id) ON DELETE CASCADE,
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE
    SET NULL
);
-- ============================================================================
-- 9. BẢNG AUDIT_LOGS (Nhật ký kiểm toán bảo mật - APPEND-ONLY)
-- Có đủ 6 trường bắt buộc của Task 3:
--   1. timestamp        (Thời gian)
--   2. acting_username  (Người thực hiện - kèm acting_user_id)
--   3. event_type       (Loại sự kiện: LOGIN_SUCCESS, GRADE_MODIFIED, v.v.)
--   4. target_resource  (Tài nguyên bị tác động)
--   5. result           (Kết quả: SUCCESS, FAILURE, REJECTED)
--   6. details          (Chi tiết phi nhạy cảm)
-- ============================================================================
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acting_user_id INTEGER,
    acting_username VARCHAR(50) NOT NULL,
    event_type VARCHAR(80) NOT NULL CHECK (length(trim(event_type)) > 0),
    target_resource VARCHAR(150) NOT NULL,
    result VARCHAR(20) NOT NULL CHECK (
        result IN ('SUCCESS', 'FAILURE', 'REJECTED')
    ),
    details TEXT,
    ip_address VARCHAR(45),
    FOREIGN KEY (acting_user_id) REFERENCES users(id) ON DELETE
    SET NULL
);
-- ============================================================================
-- 10. TRIGGER BẢO VỆ APPEND-ONLY CHO AUDIT_LOGS (Chống sửa/xóa nhật ký)
-- ============================================================================
CREATE TRIGGER trg_audit_logs_no_update BEFORE
UPDATE ON audit_logs BEGIN
SELECT RAISE(
        ABORT,
        'SECURITY VIOLATION: audit_logs is append-only. UPDATE is strictly prohibited.'
    );
END;
CREATE TRIGGER trg_audit_logs_no_delete BEFORE DELETE ON audit_logs BEGIN
SELECT RAISE(
        ABORT,
        'SECURITY VIOLATION: audit_logs is append-only. DELETE is strictly prohibited.'
    );
END;
-- ============================================================================
-- 11. INDEX TỐI ƯU TRUY VẤN
-- ============================================================================
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_courses_lecturer_id ON courses(lecturer_id);
CREATE INDEX idx_enrollments_student_id ON enrollments(student_id);
CREATE INDEX idx_enrollments_course_id ON enrollments(course_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);