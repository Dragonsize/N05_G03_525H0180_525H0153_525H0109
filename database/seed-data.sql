-- ============================================================================
-- UNIVERSITY RECORDS SYSTEM - SEED DATA (TASK 3 & TASK 4 TEST FIXTURES)
-- File: database/seed-data.sql
-- Primary Responsibility: STUDENT C (Database Security, Testing & Audit Logging)
--
-- MẬT KHẨU ĐĂNG NHẬP CHO TẤT CẢ TÀI KHOẢN DƯỚI ĐÂY LÀ: password
-- Chuỗi băm Bcrypt chuẩn (cost=10):
-- $2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
-- ============================================================================
PRAGMA foreign_keys = ON;
-- 1. KHỞI TẠO 5 VAI TRÒ (ROLES)
INSERT INTO roles (id, role_name, description)
VALUES (
        1,
        'Student',
        'View own profile, enrollment, and grades; update own contact information'
    ),
    (
        2,
        'Lecturer',
        'View students enrolled in assigned courses; create and update grades for assigned courses'
    ),
    (
        3,
        'Registrar',
        'Create and update student records; manage enrollment; view grades; cannot modify grades'
    ),
    (
        4,
        'Security Auditor',
        'Read audit logs and access-control configuration; cannot modify academic data'
    ),
    (
        5,
        'System Administrator',
        'Manage user accounts and role assignments; cannot view or modify grades unless separately authorized'
    );
-- 2. KHỞI TẠO 10 TÀI KHOẢN NGƯỜI DÙNG (USERS)
-- Mật khẩu chung khi đăng nhập web: password
INSERT INTO users (
        id,
        username,
        password_hash,
        full_name,
        email,
        is_active
    )
VALUES (
        1,
        'admin1',
        '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
        'System Admin One',
        'admin1@tdtu.edu.vn',
        1
    ),
    (
        2,
        'auditor1',
        '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
        'Security Auditor One',
        'auditor1@tdtu.edu.vn',
        1
    ),
    (
        3,
        'registrar1',
        '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
        'Academic Registrar One',
        'registrar1@tdtu.edu.vn',
        1
    ),
    (
        4,
        'lecturer_tu',
        '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
        'TS. Huynh Ngoc Tu',
        'huynhngoctu@tdtu.edu.vn',
        1
    ),
    (
        5,
        'lecturer_other',
        '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
        'ThS. Nguyen Van B',
        'nguyenvanb@tdtu.edu.vn',
        1
    ),
    (
        6,
        'student_an',
        '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
        'Huynh Thien An',
        '525h0109@student.tdtu.edu.vn',
        1
    ),
    (
        7,
        'student_khoi',
        '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
        'Nguyen Minh Khoi',
        '525h0153@student.tdtu.edu.vn',
        1
    ),
    (
        8,
        'student_phat',
        '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
        'Tran Thanh Phat',
        '525h0180@student.tdtu.edu.vn',
        1
    ),
    (
        9,
        'student_disabled',
        '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
        'Disabled Student Acc',
        'disabled@student.tdtu.edu.vn',
        0
    ),
    (
        10,
        'lecturer_auditor',
        '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
        'Multi Role Lecturer',
        'multirole@tdtu.edu.vn',
        1
    );
-- 3. GÁN VAI TRÒ (USER_ROLES)
INSERT INTO user_roles (user_id, role_id, assigned_by)
VALUES (1, 5, 1),
    -- admin1 -> System Administrator
    (2, 4, 1),
    -- auditor1 -> Security Auditor
    (3, 3, 1),
    -- registrar1 -> Registrar
    (4, 2, 1),
    -- lecturer_tu -> Lecturer
    (5, 2, 1),
    -- lecturer_other -> Lecturer
    (6, 1, 1),
    -- student_an -> Student
    (7, 1, 1),
    -- student_khoi -> Student
    (8, 1, 1),
    -- student_phat -> Student
    (9, 1, 1),
    -- student_disabled -> Student (is_active = 0 -> Test T03)
    (10, 2, 1),
    -- lecturer_auditor -> Lecturer (Role 1)
    (10, 4, 1);
-- lecturer_auditor -> Security Auditor (Role 2 - Multi-role)
-- 4. HỒ SƠ SINH VIÊN (STUDENT_PROFILES)
INSERT INTO student_profiles (
        id,
        user_id,
        student_code,
        date_of_birth,
        major,
        phone,
        address,
        enrollment_year
    )
VALUES (
        1,
        6,
        '525H0109',
        '2007-05-15',
        'Information Technology',
        '0901234109',
        'District 7, Ho Chi Minh City',
        2025
    ),
    (
        2,
        7,
        '525H0153',
        '2007-08-20',
        'Information Technology',
        '0901234153',
        'District 4, Ho Chi Minh City',
        2025
    ),
    (
        3,
        8,
        '525H0180',
        '2007-11-10',
        'Information Technology',
        '0901234180',
        'District 1, Ho Chi Minh City',
        2025
    ),
    (
        4,
        9,
        '525H0999',
        '2007-01-01',
        'Information Technology',
        '0900000999',
        'Ho Chi Minh City',
        2025
    );
-- 5. KHÓA HỌC (COURSES)
-- Khóa 1 & 2 do lecturer_tu (user_id=4) dạy; Khóa 3 do lecturer_other (user_id=5) dạy.
INSERT INTO courses (
        id,
        course_code,
        course_name,
        credits,
        semester,
        lecturer_id
    )
VALUES (
        1,
        '504070',
        'Information Security',
        3,
        'HK1_2026_2027',
        4
    ),
    (
        2,
        '503045',
        'Operating Systems',
        4,
        'HK1_2026_2027',
        4
    ),
    (
        3,
        '502030',
        'Object-Oriented Programming',
        4,
        'HK1_2026_2027',
        5
    );
-- 6. ĐĂNG KÝ HỌC PHẦN (ENROLLMENTS)
-- Lưu ý:
-- - enrollment_id 1..5 đã có điểm trong bảng grades.
-- - enrollment_id 6 (student_phat học môn Operating Systems) CHƯA có điểm -> Dùng để test Tạo điểm mới (Create Grade).
-- - student_phat chưa đăng ký môn OOP (course_id=3) -> Dùng để Registrar test Tạo đăng ký mới (Test T12).
INSERT INTO enrollments (id, student_id, course_id, enrolled_by, status)
VALUES (1, 1, 1, 3, 'ENROLLED'),
    -- An học InfoSec (lecturer_tu)
    (2, 1, 3, 3, 'ENROLLED'),
    -- An học OOP (lecturer_other)
    (3, 2, 1, 3, 'ENROLLED'),
    -- Khôi học InfoSec (lecturer_tu)
    (4, 2, 2, 3, 'ENROLLED'),
    -- Khôi học OS (lecturer_tu)
    (5, 3, 1, 3, 'ENROLLED'),
    -- Phát học InfoSec (lecturer_tu)
    (6, 3, 2, 3, 'ENROLLED');
-- Phát học OS (lecturer_tu) - Chưa có điểm
-- 7. ĐIỂM SỐ (GRADES)
INSERT INTO grades (
        id,
        enrollment_id,
        midterm_score,
        final_score,
        total_score,
        letter_grade,
        updated_by
    )
VALUES (1, 1, 8.5, 9.0, 8.8, 'A', 4),
    -- Điểm InfoSec của An (lecturer_tu được phép sửa - Test T10)
    (2, 2, 7.5, 8.0, 7.8, 'B+', 5),
    -- Điểm OOP của An (lecturer_tu KHÔNG được sửa vì của lecturer_other - Test T11)
    (3, 3, 8.0, 8.5, 8.3, 'A', 4),
    -- Điểm InfoSec của Khôi
    (4, 4, 9.0, 9.0, 9.0, 'A+', 4),
    -- Điểm OS của Khôi
    (5, 5, 8.5, 8.5, 8.5, 'A', 4);
-- Điểm InfoSec của Phát
-- 8. DỮ LIỆU MẪU AUDIT LOGS (Phục vụ Test T14 & T20)
INSERT INTO audit_logs (
        acting_user_id,
        acting_username,
        event_type,
        target_resource,
        result,
        details,
        ip_address
    )
VALUES (
        1,
        'admin1',
        'LOGIN_SUCCESS',
        'auth/login',
        'SUCCESS',
        'System administrator logged in successfully',
        '127.0.0.1'
    ),
    (
        1,
        'admin1',
        'ROLE_ASSIGNED',
        'user:6 (student_an)',
        'SUCCESS',
        'Assigned role Student to user student_an',
        '127.0.0.1'
    ),
    (
        9,
        'student_disabled',
        'LOGIN_FAILED',
        'auth/login',
        'REJECTED',
        'Login rejected: account is disabled',
        '127.0.0.1'
    ),
    (
        6,
        'student_an',
        'UNAUTHORIZED_ACCESS_REJECTED',
        'student_profile:2',
        'REJECTED',
        'IDOR attempt blocked: Student tried to view another student record',
        '127.0.0.1'
    ),
    (
        3,
        'registrar1',
        'GRADE_MODIFY_REJECTED',
        'grade:1 (enrollment_id=1)',
        'REJECTED',
        'RBAC violation: Registrar role is not permitted to modify grades',
        '127.0.0.1'
    ),
    (
        4,
        'lecturer_tu',
        'GRADE_MODIFIED',
        'grade:1 (enrollment_id=1)',
        'SUCCESS',
        'Updated final_score from 8.5 to 9.0 for assigned course 504070',
        '127.0.0.1'
    );