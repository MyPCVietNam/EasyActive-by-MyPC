# DeActive by MyPC

Phiên bản: `1.3.0`

## Công cụ này dùng để làm gì?

DeActive by MyPC hỗ trợ dọn trạng thái kích hoạt cũ của Windows và Microsoft Office để người dùng có thể chuyển sang key bản quyền chính hãng hoặc đăng nhập tài khoản Microsoft/Microsoft 365 hợp lệ.

Công cụ không kích hoạt lậu, không bypass bản quyền, không cài KMS, không gọi server kích hoạt không chính thống và không xóa Event Log hệ thống.

## Tính năng chính

- Kiểm tra thử bằng Dry-run, không thay đổi hệ thống
- Tạo Restore Point trước khi xử lý
- Gỡ key Windows/Office cũ
- Xóa cấu hình KMS/MAS còn sót lại
- Xóa lịch tự kích hoạt
- Dọn cache license Office
- Hỗ trợ xử lý Ohook
- Đọc key Windows OEM đi theo main / BIOS / UEFI
- Có log, backup registry và report rõ ràng

## Hướng dẫn sử dụng nhanh

1. Giải nén tool.
2. Chuột phải `DeActive-by-MyPC.bat`.
3. Chọn Run as administrator.
4. Chọn ngôn ngữ. Nếu không chọn sau vài giây, công cụ mặc định dùng tiếng Việt.
5. Chọn mục cần chạy:
   - 1 = Kiểm tra thử, không thay đổi hệ thống
   - 2 = Dọn cả Windows và Office
   - 3 = Chỉ dọn Office
   - 4 = Chỉ dọn Windows
   - 5 = Đọc key Windows OEM đi theo main / BIOS / UEFI
   - 6 = Mở thư mục log và báo cáo
6. Chạy xong restart máy nếu vừa dọn Windows/Office.
7. Nhập key bản quyền hoặc đăng nhập Microsoft/Microsoft 365.

## Log, backup và report

Sau khi chạy, dữ liệu nằm tại:

```text
C:\ProgramData\LegitActivationCleaner
```

Gồm:

- Logs
- Backups
- Reports

## Lưu ý về Digital License / HWID

Nếu máy từng được active bằng MAS dạng HWID/Digital License, công cụ chỉ có thể dọn key và cấu hình local trên máy. Digital license đã gắn với phần cứng trên server Microsoft có thể vẫn khiến Windows tự kích hoạt lại khi online.

Đây không phải lỗi của công cụ.

## Lưu ý về key OEM theo main

Một số máy có key Windows OEM được nhúng trong BIOS/UEFI. Key này thường chỉ dùng đúng phiên bản Windows gốc theo máy, ví dụ Home, Pro hoặc Home Single Language.

Tính năng đọc key OEM chỉ đọc thông tin, không kích hoạt Windows và không thay đổi hệ thống.

## Cam kết an toàn

DeActive by MyPC:

- Không kích hoạt lậu
- Không bypass bản quyền
- Không cài KMS
- Không gọi server kích hoạt không chính thống
- Không xóa Event Log hệ thống
- Không xóa Defender history, Prefetch, Amcache, ShimCache, SRUM
- Không gửi dữ liệu ra ngoài

## File trong dự án

- `DeActive-by-MyPC.bat` - launcher thương hiệu public.
- `Clean-MAS-Activation.cmd` - menu chạy tool, hỗ trợ tiếng Việt/English.
- `Clean-MAS-Activation.ps1` - script PowerShell chính.
- `README.en.md` - tài liệu tiếng Anh.
- `CHECKSUMS.sha256` - danh sách SHA256 của các file phát hành.

## SHA256

Checksum đầy đủ nằm trong `CHECKSUMS.sha256`.
