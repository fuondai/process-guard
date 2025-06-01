# Cơ chế phát hiện của ProcessGuard

Tài liệu này mô tả chi tiết về các cơ chế phát hiện mà ProcessGuard sử dụng để xác định các tiến trình đáng ngờ sử dụng kỹ thuật Process Doppelgänging và các kỹ thuật tiêm nhiễm tiến trình tương tự.

## Tổng quan về phương pháp phát hiện

ProcessGuard sử dụng phương pháp phát hiện đa lớp, kết hợp phân tích bộ nhớ, hệ thống tệp, handle hệ thống và hành vi tiến trình để xác định các dấu hiệu của Process Doppelgänging. Mỗi chỉ báo đều được gán một điểm số mức độ nghiêm trọng, và tổng điểm xác định mức độ nguy hiểm tổng thể của tiến trình (THẤP, TRUNG BÌNH, CAO).

## Các loại chỉ báo phát hiện

### 1. Chỉ báo phân tích bộ nhớ

| Chỉ báo | Mô tả | Mức độ nghiêm trọng |
|---------|-------|-------------------|
| **PAGE_EXECUTE_READWRITE** | Vùng bộ nhớ được đánh dấu là thực thi và có thể ghi | TRUNG BÌNH |
| **Bộ nhớ hình ảnh không có tệp liên kết** | Section bộ nhớ được tạo từ SEC_IMAGE nhưng không có tệp liên kết | CAO |
| **Vùng bộ nhớ đã bị rỗng** | Phần bộ nhớ tiến trình bị rỗng với nội dung đã sửa đổi | CAO |
| **Sự không khớp nội dung bộ nhớ** | Nội dung bộ nhớ khác với tệp gốc trên đĩa | CAO |

### 2. Chỉ báo phân tích hệ thống tệp

| Chỉ báo | Mô tả | Mức độ nghiêm trọng |
|---------|-------|-------------------|
| **Ánh xạ bộ nhớ từ tệp không tồn tại** | Ánh xạ bộ nhớ từ tệp đã bị xóa hoặc không tồn tại | CAO |
| **Ánh xạ bộ nhớ từ pagefile.sys** | Ánh xạ bộ nhớ từ tệp trang | TRUNG BÌNH |
| **Đường dẫn tệp bất thường** | Đường dẫn tệp thực thi nằm trong thư mục tạm thời hoặc không thường dùng | THẤP |
| **Sai lệch thời gian** | Thời gian tạo tệp bất thường gần với thời gian thực thi | THẤP |

### 3. Chỉ báo phân tích handle và giao dịch

| Chỉ báo | Mô tả | Mức độ nghiêm trọng |
|---------|-------|-------------------|
| **Handle giao dịch NTFS (TmTx)** | Tiến trình có handle đến Trình quản lý giao dịch NTFS | CAO |
| **Handle section không liên kết với tệp** | Handle section không có tệp liên kết | TRUNG BÌNH |
| **Mẫu thừa kế handle đáng ngờ** | Các mẫu thừa kế handle bất thường giữa các tiến trình | TRUNG BÌNH |
| **Handle giao dịch có đường dẫn tệp đã xóa** | Handle giao dịch liên kết với tệp không còn tồn tại | CAO |

### 4. Chỉ báo giám sát tạo tiến trình

| Chỉ báo | Mô tả | Mức độ nghiêm trọng |
|---------|-------|-------------------|
| **Mối quan hệ tiến trình cha-con bất thường** | Tiến trình cha không phải là trình quản lý tiến trình thông thường | THẤP |
| **Tham số dòng lệnh đáng ngờ** | Tham số dòng lệnh chứa các ký tự ẩn hoặc mã hóa | TRUNG BÌNH |
| **Cờ tạo tiến trình bất thường** | Sử dụng các cờ tạo tiến trình không thông thường | TRUNG BÌNH |
| **Tiến trình cha đã kết thúc** | Tiến trình cha đã kết thúc nhưng tiến trình con vẫn đang chạy | THẤP |

## Tính toán mức độ nguy hiểm

ProcessGuard tính toán điểm nguy hiểm tổng thể cho mỗi tiến trình dựa trên sự kết hợp của các chỉ báo phát hiện được. Mức độ nguy hiểm được phân loại như sau:

- **THẤP**: 1-3 điểm hoặc chỉ có các chỉ báo mức độ THẤP
- **TRUNG BÌNH**: 4-7 điểm hoặc ít nhất một chỉ báo mức độ TRUNG BÌNH
- **CAO**: 8+ điểm hoặc ít nhất một chỉ báo mức độ CAO

## Phát hiện cụ thể Process Doppelgänging

Kỹ thuật Process Doppelgänging thường được xác định bởi sự kết hợp của các chỉ báo sau:

1. Tiến trình có section bộ nhớ được tạo từ SEC_IMAGE nhưng không có tệp liên kết
2. Phát hiện handle giao dịch NTFS
3. Ánh xạ bộ nhớ từ tệp không tồn tại
4. Sự không khớp giữa nội dung bộ nhớ và tệp gốc

Khi ProcessGuard phát hiện ít nhất ba trong số các chỉ báo này, tiến trình sẽ được đánh dấu với mức độ nguy hiểm CAO và được gắn nhãn là tiến trình sử dụng kỹ thuật Process Doppelgänging.

## Giảm thiểu cảnh báo sai

Để giảm thiểu cảnh báo sai, ProcessGuard áp dụng các kỹ thuật sau:

1. **Danh sách trắng**: Các tiến trình hệ thống và ứng dụng đáng tin cậy được đưa vào danh sách trắng
2. **Phân tích ngữ cảnh**: Xem xét ngữ cảnh của tiến trình (ví dụ: thời gian chạy, tiến trình cha, v.v.)
3. **Loại trừ mẫu đã biết**: Loại trừ các mẫu đã biết tạo ra cảnh báo sai
4. **Phân tích tần suất**: Xem xét tần suất xuất hiện của các chỉ báo

## Hành động sau phát hiện

Tùy thuộc vào cấu hình, ProcessGuard có thể thực hiện các hành động sau khi phát hiện tiến trình đáng ngờ:

1. **Ghi nhật ký**: Ghi lại thông tin chi tiết về tiến trình đáng ngờ
2. **Cảnh báo**: Hiển thị cảnh báo cho người dùng
3. **Tự động kết thúc**: Kết thúc tiến trình đáng ngờ (chỉ khi được cấu hình với tùy chọn `-k`)
4. **Báo cáo**: Tạo báo cáo chi tiết về tiến trình đáng ngờ và các chỉ báo phát hiện

## Nâng cao và tùy chỉnh

Người dùng có thể tùy chỉnh cơ chế phát hiện thông qua các tùy chọn dòng lệnh:

- `--min-threat-level`: Thiết lập mức độ nguy hiểm tối thiểu để báo cáo (THẤP, TRUNG BÌNH, CAO)
- `--debug`: Bật ghi nhật ký gỡ lỗi chi tiết để phân tích sâu hơn
- `--admin`: Chạy với quyền quản trị để truy cập nhiều thông tin hệ thống hơn
