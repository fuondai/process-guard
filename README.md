# ProcessGuard: Công cụ phát hiện kỹ thuật Process Doppelgänging

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-brightgreen.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)
![Version](https://img.shields.io/badge/version-1.0.0-success)

<p align="center">
  <img src="docs/images/logo.png" alt="ProcessGuard Logo" width="200"/>
  <br>
  <em>Giải pháp bảo mật nâng cao cho việc phát hiện và ngăn chặn các kỹ thuật tiêm nhiễm tiến trình</em>
</p>

## Tổng quan

ProcessGuard là công cụ bảo mật mạnh mẽ được thiết kế để phát hiện và ngăn chặn kỹ thuật tấn công Process Doppelgänging tiên tiến trên hệ thống Windows. Với khả năng giám sát mạnh mẽ và cơ chế tự bảo vệ, ProcessGuard cung cấp bảo mật toàn diện cho môi trường mạng an toàn.

### Tính năng chính

- **Phát hiện thời gian thực**: Quét ngay lập tức tất cả các tiến trình đang chạy để tìm dấu hiệu của Process Doppelgänging
- **Giám sát liên tục**: Thủ thế theo dõi việc tạo tiến trình mới và tự động quét chúng
- **Tự bảo vệ**: Sử dụng Task Scheduler để tạo cơ chế watchdog đảm bảo dịch vụ luôn hoạt động
- **Tự động diệt**: Tự động kết thúc các tiến trình được xác định có mức độ nguy hiểm CAO
- **Chế độ thầm lặng**: Hoạt động ẩn trong nền mà không có dấu hiệu giao diện
- **Ghi nhật ký chi tiết**: Hệ thống ghi nhật ký toàn diện với các mức độ chi tiết có thể cấu hình

## Hiểu về kỹ thuật Process Doppelgänging

Process Doppelgänging là một kỹ thuật tiêm nhiễm mã không cần tệp tiên tiến, sử dụng giao dịch NTFS để thực thi mã độc trong khi tránh các giải pháp bảo mật. Kỹ thuật này đặc biệt nguy hiểm vì:

- Không để lại dấu vết của tệp độc hại trên ổ đĩa
- Vượt qua hầu hết các giải pháp antivirus và EDR
- Tạo ra các tiến trình trông hợp pháp với các công cụ bảo mật
- Không kích hoạt các phương pháp phát hiện trong bộ nhớ thông thường

### Cách hoạt động của Process Doppelgänging

1. Tạo một giao dịch NTFS
2. Mở một tệp hợp pháp trong giao dịch
3. Ghi mã độc vào tệp bên trong giao dịch
4. Tạo một section bộ nhớ từ tệp đã sửa đổi (sử dụng NtCreateSection với SEC_IMAGE)
5. Hoàn tác giao dịch để xóa tất cả dấu vết của tệp đã sửa đổi trên ổ đĩa
6. Tạo một tiến trình từ section (sử dụng NtCreateProcessEx)
7. Tạo luồng chính để bắt đầu thực thi (sử dụng NtCreateThreadEx)

Xem thêm thông tin chi tiết về kỹ thuật này và cách ProcessGuard phát hiện nó tại [tài liệu kỹ thuật](docs/technical_details.md).

## Bắt đầu nhanh

### Yêu cầu hệ thống
- Windows 10/11 (khuyến nghị)
- Python 3.7 trở lên
- Quyền quản trị (khuyến nghị để sử dụng đầy đủ tính năng phát hiện)

### Cài đặt

#### Tệp thực thi biên dịch sẵn
Tải phiên bản mới nhất từ trang [Releases](https://github.com/fuondai/process-guard/releases/tag/v1.0.0).

#### Cài đặt từ mã nguồn

```bash
# Sao chép kho lưu trữ
git clone https://github.com/fuondai/process-guard.git
cd process-guard

# Cài đặt các gói phụ thuộc
pip install -r requirements.txt

# Biên dịch thành tệp thực thi
python build.py
```

Script biên dịch sẽ tạo ra tệp `ProcessGuard.exe` trong thư mục gốc của dự án.

### Biên dịch từ mã nguồn

ProcessGuard sử dụng PyInstaller để tạo các tệp thực thi độc lập. Quá trình biên dịch đã được đơn giản hóa với script `build.py` đính kèm:

```bash
python build.py
```

Script này sẽ tự động:
1. Dọn dẹp các tệp biên dịch cũ
2. Cài đặt các gói phụ thuộc cần thiết
3. Tạo tệp thực thi độc lập với tất cả các thành phần cần thiết
4. Tạo `ProcessGuard.exe` trong thư mục gốc của dự án

## Hướng dẫn sử dụng

ProcessGuard có thể chạy trong nhiều chế độ khác nhau để phù hợp với nhu cầu bảo mật của bạn:

### Sử dụng cơ bản

```powershell
# Quét đơn giản tất cả các tiến trình đang chạy
ProcessGuard.exe --scan

# Chạy như một trình giám sát liên tục cho các tiến trình mới
ProcessGuard.exe --monitor

# Quét rồi bắt đầu giám sát (khuyến nghị)
ProcessGuard.exe --scan --monitor

# Xem tất cả các tùy chọn có sẵn
ProcessGuard.exe --help
```

### Tùy chọn nâng cao

```powershell
# Chạy ở chế độ thầm lặng (không có cửa sổ console)
ProcessGuard.exe --stealth --monitor

# Cấu hình ghi nhật ký và đầu ra
ProcessGuard.exe --monitor --log C:\Logs\processguard.log --json C:\Results\findings.json

# Tự động diệt các tiến trình có mức độ nguy hiểm CAO
ProcessGuard.exe --monitor -k

# Đặt mức độ nguy hiểm tối thiểu để báo cáo (THẤP, TRUNG BÌNH, CAO)
ProcessGuard.exe --monitor --min-threat-level MEDIUM

# Chạy như dịch vụ Windows khi khởi động
ProcessGuard.exe -s

# Hoàn toàn kết thúc ProcessGuard và gỡ bỏ bảo vệ watchdog
ProcessGuard.exe -Q
```

Xem thêm các tùy chọn dòng lệnh chi tiết và các kịch bản sử dụng tại [Hướng dẫn sử dụng](docs/usage.md).

## Khả năng phát hiện

ProcessGuard sử dụng phương pháp nhiều lớp để phát hiện Process Doppelgänging và các kỹ thuật tương tự:

### Phân tích bộ nhớ
- Các vùng bộ nhớ thực thi được đánh dấu là có thể ghi (PAGE_EXECUTE_READWRITE)
- Các phần bộ nhớ được tạo từ SEC_IMAGE nhưng không có tệp liên kết
- Các phần bộ nhớ tiến trình bị rỗng với nội dung đã được sửa đổi

### Phân tích hệ thống tệp
- Ánh xạ bộ nhớ từ các tệp không tồn tại hoặc đã bị xóa
- Ánh xạ bộ nhớ từ pagefile.sys
- Sự khác biệt giữa nội dung ảnh trên đĩa và trong bộ nhớ

### Phân tích handle và giao dịch
- Các handle giao dịch NTFS (TmTx)
- Các handle section không liên kết với tệp
- Các mẫu thừa kế handle đáng ngờ

### Giám sát tạo tiến trình
- Mối quan hệ tiến trình cha-con bất thường
- Tham số dòng lệnh đáng ngờ
- Cờ tạo tiến trình bất thường

Mỗi phát hiện tạo ra điểm mức độ nguy hiểm phân loại các phát hiện thành THẤP, TRUNG BÌNH, hoặc CAO dựa trên mức độ tin cậy và tác động tiềm ẩn.

Để biết thêm thông tin về các phương pháp phát hiện, xem [Cơ chế phát hiện](docs/detection.md).

## Cơ chế tự bảo vệ

ProcessGuard tích hợp cơ chế tự bảo vệ mạnh mẽ để đảm bảo hoạt động liên tục, ngay cả khi kẻ tấn công cố gắng kết thúc nó:

- **Tích hợp Task Scheduler**: Sử dụng Windows Task Scheduler để tạo tác vụ giám sát chạy mỗi phút
- **Giám sát tiến trình**: Tác vụ giám sát kiểm tra xem ProcessGuard có đang chạy không và khởi động lại nếu bị kết thúc
- **Nâng cao đặc quyền**: Chạy với đặc quyền cao nhất để ngăn người dùng thông thường vô hiệu hóa bảo vệ
- **Gỡ bỏ sạch sẽ**: Gỡ bỏ đúng cách tất cả cơ chế bảo vệ khi sử dụng cờ `-Q`

Phương pháp bảo vệ này đảm bảo ProcessGuard duy trì khả năng giám sát liên tục trong môi trường doanh nghiệp.

## Cấu trúc dự án

```
ProcessGuard/
├── build.py                # Script biên dịch tạo tệp thực thi
├── main.py                 # Điểm vào chính
├── requirements.txt        # Các gói phụ thuộc Python
├── modules/                # Các module chức năng cốt lõi
│   ├── scanner.py          # Động cơ quét tiến trình
│   ├── monitor.py          # Giám sát tiến trình thời gian thực
│   ├── protection.py       # Cơ chế tự bảo vệ
│   ├── logger.py           # Chức năng ghi nhật ký
│   └── utils.py            # Các hàm tiện ích
├── docs/                   # Tài liệu
│   ├── installation.md     # Hướng dẫn cài đặt chi tiết
│   ├── usage.md            # Ví dụ và kịch bản sử dụng
│   ├── detection.md        # Phương pháp và chỉ báo phát hiện
│   ├── technical_details.md # Thông tin kỹ thuật về tấn công
│   └── images/             # Hình ảnh tài liệu
└── tests/                  # Module kiểm thử
```

## License

This project is licensed under the MIT License 

## Ghi chú bổ sung

- Công cụ này hoạt động tốt nhất với quyền quản trị (admin) để có thể truy cập vào thông tin bộ nhớ và handle
- Kết quả được lưu dưới dạng JSON có thể được phân tích thêm
- Điểm đáng ngờ được tính toán dựa trên sự kết hợp của nhiều yếu tố, càng cao càng đáng ngờ

