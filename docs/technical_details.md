# Chi tiết kỹ thuật về Process Doppelgänging

Tài liệu này cung cấp thông tin chi tiết về kỹ thuật Process Doppelgänging, cách thức hoạt động của nó và những thách thức trong việc phát hiện kỹ thuật này.

## Tổng quan

Process Doppelgänging là một kỹ thuật chèn mã nâng cao được công bố vào năm 2017 bởi các nhà nghiên cứu bảo mật Tal Liberman và Eugene Kogan. Kỹ thuật này lợi dụng cơ chế giao dịch NTFS và các API tạo tiến trình của Windows để tạo ra các tiến trình ẩn mình chứa mã độc mà không để lại dấu vết trên đĩa, từ đó có thể vượt qua nhiều giải pháp bảo mật.

## Cơ chế hoạt động

Process Doppelgänging hoạt động thông qua bốn bước chính:

### 1. Tạo giao dịch NTFS

Kỹ thuật này bắt đầu bằng việc tạo một giao dịch NTFS (NTFS Transaction) thông qua API `NtCreateTransaction`. Giao dịch NTFS cho phép thực hiện các thay đổi đối với hệ thống tệp mà không ảnh hưởng đến trạng thái thực tế của hệ thống tệp cho đến khi giao dịch được xác nhận.

```c
HANDLE hTransaction = CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);
```

### 2. Thay thế nội dung tệp hợp pháp

Trong ngữ cảnh của giao dịch NTFS, kẻ tấn công mở một tệp thực thi hợp pháp đã tồn tại và thay thế nội dung của nó bằng mã độc thông qua API `NtCreateSection` và `NtWriteFile`. Tuy nhiên, những thay đổi này chỉ nhìn thấy được trong giao dịch và không được thực hiện trên đĩa.

```c
HANDLE hFile = CreateFileTransacted(
    L"C:\\Windows\\System32\\notepad.exe",
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL,
    hTransaction,
    NULL,
    NULL);

WriteFile(hFile, maliciousCode, maliciousCodeSize, &bytesWritten, NULL);
```

### 3. Tạo section

Sau khi thay thế nội dung tệp, kẻ tấn công tạo một section trong không gian bộ nhớ ảo thông qua API `NtCreateSection`. Section này trỏ đến phiên bản đã sửa đổi của tệp trong giao dịch.

```c
HANDLE hSection;
NtCreateSection(
    &hSection,
    SECTION_ALL_ACCESS,
    NULL,
    0,
    PAGE_READONLY,
    SEC_IMAGE,
    hFile);
```

### 4. Tạo tiến trình từ section

Cuối cùng, kẻ tấn công tạo một tiến trình mới từ section đã tạo bằng cách sử dụng API `NtCreateProcessEx`. Tiến trình mới này chứa mã độc nhưng vẫn giữ đường dẫn và thông tin của tệp hợp pháp ban đầu.

```c
HANDLE hProcess;
NtCreateProcessEx(
    &hProcess,
    PROCESS_ALL_ACCESS,
    NULL,
    NtCurrentProcess(),
    PS_INHERIT_HANDLES,
    hSection,
    NULL,
    NULL,
    0);
```

Sau đó, kẻ tấn công hủy giao dịch NTFS mà không xác nhận thay đổi, điều này có nghĩa là tệp thực thi gốc trên đĩa vẫn không thay đổi.

```c
RollbackTransaction(hTransaction);
```

## Vòng đời của Process Doppelgänging

```
+----------------+     +------------------+     +------------------+     +-------------------+
| Tạo giao dịch  | --> | Thay thế nội    | --> | Tạo section từ   | --> | Tạo tiến trình    |
| NTFS           |     | dung tệp        |     | tệp đã sửa đổi   |     | từ section        |
+----------------+     +------------------+     +------------------+     +-------------------+
                                                                                |
                                                                                v
+----------------+     +------------------+     +------------------+
| Hủy giao dịch  | <-- | Khởi tạo luồng  | <-- | Thiết lập ngữ    |
| (không xác nhận)|     | và tiếp tục     |     | cảnh tiến trình  |
+----------------+     +------------------+     +------------------+
```

## Khó khăn trong việc phát hiện

Process Doppelgänging đặc biệt khó phát hiện vì những lý do sau:

1. **Không có dấu vết trên đĩa**: Kỹ thuật này không để lại tệp độc hại trên đĩa, nên các giải pháp bảo mật dựa trên quét tệp không hiệu quả.

2. **Sử dụng tệp hợp pháp**: Tiến trình được tạo ra có vẻ như đến từ một tệp thực thi hợp pháp, làm cho việc phát hiện dựa trên danh sách trắng trở nên vô hiệu.

3. **Không sửa đổi tệp PE**: Kỹ thuật này không sửa đổi cấu trúc tệp PE trên đĩa, nên các phương pháp phát hiện dựa trên tính toàn vẹn tệp sẽ không phát hiện được sự thay đổi.

4. **Ẩn mình trong API hệ thống**: Kỹ thuật này sử dụng các API hệ thống hợp pháp, làm cho việc phát hiện dựa trên hành vi trở nên khó khăn.

## Phương pháp phát hiện

ProcessGuard sử dụng nhiều phương pháp phát hiện kết hợp để nhận diện Process Doppelgänging:

1. **Phát hiện giao dịch NTFS**: Theo dõi việc sử dụng API tạo giao dịch NTFS và các hoạt động tệp trong giao dịch.

2. **Phân tích không khớp nội dung**: So sánh nội dung bộ nhớ của tiến trình với nội dung thực tế của tệp trên đĩa.

3. **Theo dõi handle section**: Phát hiện các section được tạo với cờ SEC_IMAGE nhưng không có tệp liên kết hoặc có tệp liên kết đã bị xóa.

4. **Giám sát quá trình tạo tiến trình**: Phân tích các thông số và ngữ cảnh khi tiến trình được tạo.

## Sự khác biệt với các kỹ thuật tương tự

### Process Hollowing vs Process Doppelgänging

| Process Hollowing | Process Doppelgänging |
|-------------------|----------------------|
| Tạo tiến trình hợp pháp trước, sau đó "rỗng" bộ nhớ và tiêm mã | Tạo tiến trình trực tiếp từ section với mã đã sửa đổi |
| Dễ phát hiện hơn do có dấu hiệu rõ ràng của việc sửa đổi bộ nhớ | Khó phát hiện hơn do không có giai đoạn "làm rỗng" |
| Không sử dụng giao dịch NTFS | Sử dụng giao dịch NTFS để che giấu sửa đổi |
| Có thể phát hiện bằng cách kiểm tra bộ nhớ tiến trình | Cần phương pháp phức tạp hơn để phát hiện |

### Process Herpaderping vs Process Doppelgänging

| Process Herpaderping | Process Doppelgänging |
|----------------------|----------------------|
| Sửa đổi tệp trên đĩa sau khi tạo section nhưng trước khi tiến trình hoàn tất | Sử dụng giao dịch NTFS, không sửa đổi tệp thực tế trên đĩa |
| Cần ghi tệp độc hại tạm thời lên đĩa | Không cần ghi tệp độc hại lên đĩa |
| Có thể phát hiện bằng cách theo dõi thay đổi tệp | Khó phát hiện hơn do không có thay đổi tệp thực tế |

## Các biến thể và cải tiến

Kể từ khi được công bố, Process Doppelgänging đã phát triển với một số biến thể:

1. **Kết hợp với kỹ thuật khác**: Kẻ tấn công có thể kết hợp Process Doppelgänging với các kỹ thuật khác như DLL Sideloading hoặc AMSI Bypass.

2. **Sử dụng nhiều giao dịch lồng nhau**: Một số biến thể sử dụng nhiều giao dịch NTFS lồng nhau để làm phức tạp hóa việc phát hiện.

3. **Tiêm vào tiến trình đã tồn tại**: Thay vì tạo tiến trình mới, một số biến thể tiêm section đã sửa đổi vào tiến trình đang chạy.

## Phòng ngừa và giảm thiểu

Các phương pháp phòng ngừa và giảm thiểu hiệu quả bao gồm:

1. **Giám sát giao dịch NTFS**: Theo dõi và giám sát việc sử dụng API giao dịch NTFS.

2. **Theo dõi hành vi tiến trình**: Giám sát hành vi tiến trình để phát hiện các hoạt động đáng ngờ.

3. **Hạn chế quyền truy cập**: Thực hiện kiểm soát truy cập để giảm khả năng kẻ tấn công sử dụng các API quan trọng.

4. **Sử dụng EDR hiện đại**: Triển khai các giải pháp phát hiện và phản hồi điểm cuối (EDR) có khả năng phát hiện sự không khớp giữa bộ nhớ và nội dung tệp.

## Kết luận

Process Doppelgänging là một kỹ thuật nâng cao và tinh vi để chèn mã độc mà không để lại dấu vết trên đĩa. Mặc dù phát hiện nó là một thách thức, nhưng với phương pháp phát hiện đa lớp, giám sát hành vi và phân tích sâu vào các cơ chế hoạt động của Windows, các công cụ như ProcessGuard có thể phát hiện và ngăn chặn hiệu quả kỹ thuật này và các biến thể của nó.
