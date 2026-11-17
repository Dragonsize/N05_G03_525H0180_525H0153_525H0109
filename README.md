# Hệ thống quản lý hồ sơ đại học

Ứng dụng Flask quản lý hồ sơ sinh viên, đăng ký môn học, điểm số, tài khoản và nhật ký kiểm toán bảo mật. Dự án minh họa kiểm soát truy cập theo vai trò và theo từng bản ghi.

## Yêu cầu

- Python 3.12 trở lên
- Các thư viện trong `source/requirements.txt`

## Chạy ứng dụng trên máy cá nhân

Tại thư mục gốc dự án, tạo và kích hoạt môi trường ảo, sau đó cài thư viện:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r source/requirements.txt
```

Đặt khóa bí mật Flask cục bộ rồi khởi chạy:

```powershell
$env:SECRET_KEY = "replace-with-a-long-random-local-secret"
python source/app.py
```

Mở <http://127.0.0.1:5000>. Ứng dụng tự khởi tạo SQLite và dữ liệu mẫu nếu cơ sở dữ liệu chưa có bảng `users`. Mặc định, dữ liệu cục bộ nằm tại `database/university_records.db`. Đặt biến `URS_DB_PATH` trước khi chạy nếu muốn dùng tệp cơ sở dữ liệu khác.

> `database/schema.sql` xóa và tạo lại các bảng. Không khởi tạo schema trên cơ sở dữ liệu đang chứa dữ liệu cần giữ.

## Tài khoản mẫu

Các tài khoản được tạo từ seed dùng chung mật khẩu `password`. Hãy đổi mật khẩu mẫu trước khi đưa ứng dụng lên môi trường công khai. Một tài khoản bị vô hiệu hóa có chủ đích để kiểm thử kiểm soát truy cập.

| Tên đăng nhập | Vai trò | Trạng thái |
|---|---|---|
| `admin1` | Quản trị hệ thống | Hoạt động |
| `auditor1` | Kiểm toán bảo mật | Hoạt động |
| `registrar1` | Giáo vụ | Hoạt động |
| `lecturer_tu` | Giảng viên | Hoạt động |
| `lecturer_other` | Giảng viên | Hoạt động |
| `student_an` | Sinh viên | Hoạt động |
| `student_khoi` | Sinh viên | Hoạt động |
| `student_phat` | Sinh viên | Hoạt động |
| `student_disabled` | Sinh viên | Vô hiệu hóa |
| `lecturer_auditor` | Giảng viên, Kiểm toán bảo mật | Hoạt động |

Người dùng có thể đổi mật khẩu của mình trên bảng điều khiển. Mật khẩu được lưu dưới dạng bcrypt hash và không thể khôi phục thành văn bản gốc.

## Vai trò và chức năng

- **Sinh viên:** xem điểm của mình và cập nhật thông tin liên hệ của mình.
- **Giảng viên:** xem danh sách lớp được phân công và cập nhật điểm của các lớp đó.
- **Giáo vụ:** xem hồ sơ sinh viên và tạo đăng ký môn học.
- **Kiểm toán bảo mật:** đọc nhật ký kiểm toán.
- **Quản trị hệ thống:** vô hiệu hóa hoặc kích hoạt lại tài khoản.

Các route được bảo vệ quyền ở phía máy chủ. Biểu mẫu dùng CSRF token; truy vấn cơ sở dữ liệu dùng tham số; nội dung HTML được escape; các sự kiện bảo mật liên quan được ghi vào audit log.

## Kiểm thử

Chạy bộ kiểm thử bảo mật từ thư mục gốc:

```powershell
python tests/test_security.py
```

Script thực hiện 30 kiểm tra về xác thực, phân quyền, quyền sở hữu dữ liệu, injection, kiểm tra đầu vào và bảo vệ audit log. Đây là script độc lập; `pytest` không tự phát hiện các hàm kiểm thử này.

## Triển khai lên Render

Tệp Blueprint `source/render.yaml` cấu hình:

- Thư mục gốc dịch vụ: `source`
- Lệnh build: `pip install -r requirements.txt`
- Lệnh chạy: `gunicorn app:app`
- Đường dẫn SQLite: `/var/data/university_records.db`
- Persistent disk mount: `/var/data`

Trong Render, cấu hình **Blueprint Spec Path** là `source/render.yaml` và chọn nhánh có chứa tệp này. Web Service thông thường không tự áp dụng cấu hình trong Blueprint; hãy kiểm tra và áp dụng cấu hình Blueprint trong Render. Persistent disk giữ dữ liệu qua các lần deploy, nhưng dữ liệu cơ sở dữ liệu và mật khẩu đã đổi trên máy cá nhân không được sao chép lên Render. Cơ sở dữ liệu Render mới sẽ lấy tài khoản mẫu từ `database/seed-data.sql`.

## Cấu trúc dự án

```text
source/       Ứng dụng Flask, tiện ích cơ sở dữ liệu, audit logger, dependencies
 database/    Schema SQLite và dữ liệu mẫu
 tests/       Kế hoạch kiểm thử và script kiểm thử bảo mật
 source/render.yaml  Cấu hình Render Blueprint
```
