# Kịch bản kiểm thử Dương tính giả cho ProcessGuard (Test Harness)

## Tổng quan

`Test Harness` là một kịch bản tự động hóa được thiết kế để kiểm tra khả năng của công cụ `ProcessGuard` trong việc phân biệt giữa các hành vi lành tính và độc hại. Mục tiêu chính là phát hiện các trường hợp **dương tính giả (False Positive)**, tức là khi `ProcessGuard` nhận diện nhầm một ứng dụng hoặc hành động hợp pháp là mối đe dọa.

Kịch bản này mô phỏng một môi trường làm việc bằng cách liên tục chạy các ứng dụng hệ thống phổ biến, các kịch bản thực thi tác vụ tệp, và các mẫu phần mềm độc hại (nếu có) trong một khoảng thời gian dài.

## Tính năng chính

- **Tự động hóa hoàn toàn**: Chạy liên tục trong một khoảng thời gian được định cấu hình (mặc định là 1 giờ).
- **Kiểm tra đa dạng**: Thực thi một loạt các ứng dụng lành tính (`notepad.exe`, `calc.exe`) và các kịch bản phức tạp hơn (sử dụng PowerShell để thao tác tệp).
- **Tối ưu cho việc tìm False Positive**: Ưu tiên chạy các hành động lành tính (90% thời gian) để tăng tối đa cơ hội phát hiện cảnh báo nhầm.
- **Tự động xác minh kết quả**: Kịch bản tự động đọc tệp `detector.log` của `ProcessGuard` sau mỗi hành động lành tính. Nếu phát hiện tiến trình lành tính bị gắn cờ, nó sẽ ghi một cảnh báo **"!!! FALSE POSITIVE DETECTED !!!"** vào tệp `test_harness.log`.
- **Đóng gói độc lập**: Cung cấp kịch bản `build.py` để biên dịch toàn bộ công cụ kiểm thử thành một tệp `TestHarness.exe` duy nhất, không cần cài đặt Python trên máy đích.
- **Ghi nhật ký chi tiết**: Mọi hành động, PID của tiến trình và kết quả kiểm tra đều được ghi lại trong tệp `test_harness.log`.

## Yêu cầu

- **Để chạy từ mã nguồn**: Python 3.10+
- **Hệ điều hành**: Windows

## Hướng dẫn sử dụng

**QUAN TRỌNG**: Trước khi chạy `Test Harness`, bạn phải khởi động `ProcessGuard` ở chế độ giám sát trong một cửa sổ dòng lệnh (terminal) khác.

```powershell
# Di chuyển đến thư mục của ProcessGuard
cd ..\process-guard

# Chạy ProcessGuard ở chế độ giám sát
py -3.10 main.py --monitor
```

### 1. Chạy từ mã nguồn

Sau khi `ProcessGuard` đang chạy, bạn có thể khởi động kịch bản kiểm thử:

```powershell
# Trong thư mục test_falsepositive
py -3.10 test_harness.py
```

### 2. Biên dịch ra tệp thực thi (.exe)

Kịch bản `build.py` sẽ tự động cài đặt `PyInstaller` và đóng gói `test_harness.py` cùng các tệp cần thiết (`benign_script.ps1`) vào một tệp `exe`.

```powershell
# Trong thư mục test_falsepositive
py -3.10 build.py
```

Quá trình này sẽ tạo ra thư mục `dist` chứa tệp `TestHarness.exe`.

### 3. Chạy tệp thực thi đã biên dịch

Sau khi `ProcessGuard` đang chạy, bạn chỉ cần thực thi tệp `exe`.

```powershell
# Di chuyển đến thư mục dist mới được tạo
cd dist

# Chạy tệp thực thi
.\TestHarness.exe
```

## Theo dõi kết quả

- **Nhật ký của Test Harness**: Mở tệp `test_harness.log` (được tạo trong cùng thư mục với nơi bạn chạy kịch bản/exe) để xem chi tiết các hành động đã thực hiện.
- **Phát hiện Dương tính giả**: Tìm kiếm chuỗi `"!!! FALSE POSITIVE DETECTED !!!"` trong `test_harness.log` để nhanh chóng xác định các vấn đề.
- **Nhật ký của ProcessGuard**: Tệp `detector.log` trong thư mục `process-guard` sẽ chứa các báo cáo gốc từ công cụ bảo mật.
