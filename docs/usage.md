# Hướng dẫn sử dụng ProcessGuard

Tài liệu này cung cấp hướng dẫn chi tiết về cách sử dụng ProcessGuard để phát hiện và ngăn chặn kỹ thuật Process Doppelgänging cũng như các kỹ thuật tấn công tiến trình tương tự.

## Các tùy chọn dòng lệnh

ProcessGuard cung cấp nhiều tùy chọn dòng lệnh để tùy chỉnh hoạt động của ứng dụng:

```
usage: ProcessGuard.exe [-h] [--scan] [--monitor] [-s] [-k] [-Q]
                        [--min-threat-level {LOW,MEDIUM,HIGH}]
                        [--stealth] [--log LOG] [--json JSON] [--admin] [--debug]
                        [--no-watchdog]
```

### Tùy chọn cơ bản

| Tùy chọn | Mô tả |
|----------|-------|
| `-h, --help` | Hiển thị thông báo trợ giúp và thoát |
| `--scan` | Quét tất cả các tiến trình đang chạy |
| `--monitor` | Giám sát tiến trình mới được tạo |
| `-s, --service` | Chạy như một dịch vụ Windows/ứng dụng khởi động |
| `-k, --kill` | Tự động kết thúc tiến trình với mức độ nguy hiểm CAO |
| `-Q, --quit` | Hoàn toàn kết thúc ProcessGuard và bỏ qua cơ chế bảo vệ |

### Tùy chọn nâng cao

| Tùy chọn | Mô tả |
|----------|-------|
| `--min-threat-level {LOW,MEDIUM,HIGH}` | Mức độ nguy hiểm tối thiểu để ghi nhật ký (THẤP, TRUNG BÌNH, CAO) |
| `--stealth` | Chạy ở chế độ thầm lặng (không có cửa sổ console) |
| `--log LOG` | Đường dẫn file ghi nhật ký |
| `--json JSON` | Đường dẫn file kết quả JSON |
| `--admin` | Bắt buộc yêu cầu quyền quản trị |
| `--debug` | Bật ghi nhật ký gỡ lỗi |
| `--no-watchdog` | Sử dụng nội bộ - không khởi động watchdog (được sử dụng trong quá trình khởi động lại) |

## Kịch bản sử dụng

### 1. Quét nhanh hệ thống

Để thực hiện quét nhanh tất cả các tiến trình đang chạy và hiển thị kết quả:

```powershell
ProcessGuard.exe --scan
```

Lệnh này sẽ:
- Quét tất cả các tiến trình đang chạy
- Hiển thị kết quả trên màn hình
- Lưu kết quả vào file JSON mặc định
- Thoát sau khi hoàn thành

### 2. Giám sát liên tục

Để theo dõi liên tục các tiến trình mới được tạo:

```powershell
ProcessGuard.exe --monitor
```

Lệnh này sẽ:
- Chạy ở chế độ giám sát liên tục
- Theo dõi các tiến trình mới được tạo
- Quét mỗi tiến trình mới để phát hiện dấu hiệu của Process Doppelgänging
- Tiếp tục chạy cho đến khi được kết thúc bằng Ctrl+C hoặc `-Q`

### 3. Giám sát và tự động kết thúc tiến trình đáng ngờ

```powershell
ProcessGuard.exe --monitor -k
```

Lệnh này sẽ:
- Chạy ở chế độ giám sát liên tục
- Tự động kết thúc tiến trình được xác định có mức độ nguy hiểm CAO

### 4. Chạy như một dịch vụ

```powershell
ProcessGuard.exe -s
```

Lệnh này sẽ:
- Cài đặt ProcessGuard như một dịch vụ khởi động cùng Windows
- Chạy với quyền quản trị
- Thiết lập cơ chế watchdog để đảm bảo dịch vụ luôn hoạt động

### 5. Chạy ở chế độ thầm lặng

```powershell
ProcessGuard.exe --scan --monitor --stealth
```

Lệnh này sẽ:
- Chạy quét ban đầu
- Chuyển sang chế độ giám sát
- Không hiển thị cửa sổ console
- Chạy ẩn trong nền

### 6. Tùy chỉnh ghi nhật ký và đầu ra

```powershell
ProcessGuard.exe --scan --monitor --log C:\Logs\processguard.log --json C:\Results\findings.json
```

Lệnh này sẽ:
- Chỉ định vị trí tệp nhật ký
- Chỉ định vị trí tệp kết quả JSON

### 7. Gỡ bỏ hoàn toàn và kết thúc

```powershell
ProcessGuard.exe -Q
```

Lệnh này sẽ:
- Kết thúc tất cả các tiến trình ProcessGuard đang chạy
- Gỡ bỏ tất cả các tác vụ watchdog từ Task Scheduler
- Xóa tất cả các tệp batch tạm thời
- Kết thúc hoàn toàn ứng dụng

## Đọc kết quả

Kết quả quét được lưu dưới dạng JSON với cấu trúc sau:

```json
{
  "suspicious_processes": [
    {
      "pid": 1234,
      "name": "example.exe",
      "path": "C:\\Path\\To\\example.exe",
      "threat_level": "HIGH",
      "indicators": [
        "Memory section with no associated file",
        "PAGE_EXECUTE_READWRITE memory region",
        "NTFS transaction handle detected"
      ]
    }
  ],
  "scan_time": "2025-06-01T21:44:21",
  "admin_rights": true
}
```

## Giải quyết sự cố

### Lỗi quyền truy cập

Nếu bạn nhận được lỗi quyền truy cập, hãy đảm bảo bạn đang chạy ProcessGuard với quyền quản trị. Nhấp chuột phải vào ProcessGuard.exe và chọn "Run as administrator".

### ProcessGuard không phát hiện các tiến trình đáng ngờ

- Đảm bảo bạn đang chạy với quyền quản trị (`--admin`)
- Bật chế độ gỡ lỗi để có thêm thông tin (`--debug`)
- Kiểm tra tệp nhật ký để biết thêm chi tiết

### Xung đột với phần mềm bảo mật khác

ProcessGuard có thể xung đột với một số phần mềm bảo mật. Nếu bạn gặp vấn đề, hãy thử:

1. Tạm thời tắt phần mềm diệt virus hoặc EDR
2. Thêm ProcessGuard vào danh sách ngoại lệ của phần mềm bảo mật
3. Chạy ProcessGuard ở chế độ gỡ lỗi để xác định xung đột cụ thể
