# DeActive by MyPC

Phiên bản: `1.8.3`

## Thay đổi trong v1.8.3 (quay lại menu + rõ nghĩa nút hủy)

- **Quay lại menu chính sau khi xong tác vụ:** trước đây chạy xong một việc là tool thoát; nay sau mỗi tác vụ sẽ hỏi *"Nhấn Enter để quay lại menu chính, hoặc N/0 để thoát"*. Nhờ đó làm được cả chuỗi trong **một lần chạy**, ví dụ: Đánh giá (menu 7) → Dọn (menu 2) → Đánh giá lại (menu 7) để xác nhận sạch.
- **Mỗi tác vụ một RunId/log/báo cáo riêng:** khi quay lại menu, tool tạo RunId mới và báo cáo mới, không trộn lẫn kết quả giữa các lần.
- **Nhắc khởi động lại:** nếu vừa dọn bản quyền, tool nhắc nên restart máy trước khi làm thao tác tiếp theo.
- **Rõ nghĩa lựa chọn ở bước xác nhận:** các prompt cảnh báo (dọn Windows / đóng Office) nay ghi rõ **"N = quay lại menu"** thay vì chỉ "N/Hủy", tránh hiểu nhầm là thoát.

*Không thêm nút "Quay Lại" ở menu gốc* vì menu gốc đã là cấp trên cùng (đã có "0 = Thoát" và menu tự lặp lại).

## Thay đổi trong v1.8.2 (dọn crack triệt để hơn)

Bổ sung 3 bước dọn (chạy trong pha dọn Windows, tôn trọng `-SkipWindows`) để gỡ nốt các can thiệp *chặn Windows tự kiểm tra chính hãng* mà trước đây chỉ phát hiện chứ chưa xóa — nhờ đó sau khi cài key hợp lệ, máy sạch thật, không còn cặn crack:

- **Xóa khóa registry chặn genuine:** gỡ `NoGenTicket` / `NoAcquireGT` (quét các vị trí khả dĩ, chỉ xóa nơi thật sự có). Trả lại khả năng tạo genuine ticket cho Windows.
- **Bật lại dịch vụ bảo vệ bị tắt:** nếu `sppsvc` / `ClipSVC` / `osppsvc` bị đặt Disabled (Start=4) do crack, đưa về Manual (Start=3). Máy bình thường không bị đụng.
- **Dọn file hosts chặn máy chủ kích hoạt:** gỡ đúng những dòng trỏ tên miền kích hoạt Microsoft về `0.0.0.0/127.x`, giữ nguyên phần còn lại.

Tất cả đều theo cơ chế an toàn sẵn có: **`-DryRun` chỉ liệt kê không sửa**, **backup trước khi đổi** (export registry + copy file hosts vào thư mục Backups theo RunId), có log và ghi vào báo cáo. Backup fail thì bỏ qua bước đó (trừ khi `-Force`).

*Lưu ý:* KMS38 không cần bước riêng — khi đã gỡ key + xóa cấu hình rồi cài key hợp lệ và kích hoạt lại thì hạn kích hoạt bị ghi đè, tự sạch qua luồng re-license.

## Thay đổi trong v1.8.1 (hoàn thiện đánh giá crack - Phase 2)

- **Thêm kiểm tra tính chính hãng vào kết luận:** Chế độ đánh giá (menu 7) giờ dùng `SLIsGenuineLocal` để bắt **license giả kiểu HWID/KMS** — trường hợp máy báo "đã kích hoạt" ở mức WMI nhưng kiểm tra genuine lại nói *Invalid/Tampered*. Đây là dấu hiệu mạnh và chính xác hơn nhiều so với chỉ đọc `LicenseStatus`. Máy chưa kích hoạt (invalid nhưng không phải crack) không bị quy chụp.
- **HWID nhận diện thông minh hơn:** Trước đây HWID chỉ để tham khảo. Nay chỉ nâng thành tín hiệu tính điểm khi **có đủ bằng chứng đi kèm** (digital license + không có key OEM + genuine không sạch). Nếu genuine báo chính hãng thì digital license vẫn coi là hợp lệ — tránh báo nhầm máy dùng digital license thật.
- **Kết luận kèm độ tin cậy + lý do:** Mỗi lần đánh giá giờ cho thêm **Độ tin cậy** (Cao/Trung bình/Thấp) và liệt kê **Lý do chính** (các tín hiệu nặng ký nhất dẫn tới kết luận), để anh hiểu vì sao ra kết quả đó thay vì chỉ một dòng phán.
- **Báo cáo HTML/TXT bổ sung:** thêm cột "Độ tin cậy" trong bảng checklist, dòng độ tin cậy tổng thể, và mục "Lý do chính".

## Thay đổi trong v1.8.0

- **Thêm chế độ "Đánh giá dấu vết crack / bản quyền" (menu 7, chỉ đọc):** Soi toàn diện dấu vết bẻ khóa kích hoạt trên máy rồi cho một **KẾT LUẬN** kèm bằng chứng, tương tự công cụ kiểm tra bản quyền của cơ quan chức năng nhưng **thận trọng hơn để tránh kết tội oan**. Không dọn, không sửa gì; chỉ đọc và báo cáo.
- **Các hạng mục được kiểm tra:** ngày cài Windows; trạng thái kích hoạt (WMI); key client KMS (GVLK); **cấu hình máy chủ KMS** (cờ đỏ khi trỏ về `127.0.0.1/127.0.0.2/0.0.0.0/localhost` = dấu hiệu KMS_VL_ALL/MAS); **KMS38** (hạn kích hoạt bị đẩy tới ~2038 qua `slmgr /xpr`); đối chiếu kênh license với **key OEM/BIOS**; HWID/digital license (chỉ tham khảo, không quy chụp); **thư mục/file tool lậu**; **tác vụ lịch lậu**; **dịch vụ lậu**; crack Office (**Ohook**); **can thiệp Registry** (`NoGenTicket`, `NoAcquireGT`); **dịch vụ bảo vệ bị tắt** (`sppsvc`/`ClipSVC`/`osppsvc` Start=4); và **file hosts chặn máy chủ kích hoạt Microsoft**.
- **Kết luận có chấm điểm theo trọng số:** gom các tín hiệu thành 4 mức — *Không phát hiện crack / Nghi ngờ / Nhiều khả năng crack / Phát hiện crack*. Một tín hiệu yếu đơn lẻ (ví dụ chỉ có `NoGenTicket`) chỉ xếp mức "Nghi ngờ", không phán ngay là crack.
- **Mở rộng thư viện nhận diện tool lậu:** thêm KMSpico, KMSTools, Ratiborus, HWIDGEN, Microsoft-Activation-Scripts/MAS_AIO, Re-Loader, Microsoft Toolkit, AAct, W10 Digital Activation, SppExtComObjHook… cho cả bước quét/dọn lẫn bước đánh giá.
- **Kết quả đánh giá vào cả báo cáo HTML và TXT:** thêm bảng checklist theo hạng mục + banner kết luận (xanh/vàng/đỏ).
- Tham số dòng lệnh mới: `-AssessCrack` (chạy chế độ đánh giá chỉ đọc).

## Thay đổi trong v1.7.1

- **Sửa lỗi:** Ở chế độ kiểm tra license (menu 6), báo cáo hiển thị mục "Thông tin key OEM nhúng" là rỗng (KeyFound=False) dù máy có key OEM. Nguyên nhân: chế độ này không đọc key OEM. Nay chế độ kiểm tra license đọc luôn key OEM, nên báo cáo hiển thị đầy đủ (MaskedKey, KeyDescription, DetectedKeyEdition, Compatibility…).
- **Báo cáo gọn hơn:** Mỗi mục trong báo cáo (Windows / Office / key OEM) chỉ hiển thị khi chế độ đó thực sự có đọc dữ liệu. Ví dụ chế độ "Đọc key OEM" (menu 5) sẽ không còn hiện mục Windows/Office rỗng gây hiểu nhầm.
- **Genuine dễ chẩn đoán hơn:** Khi `SLIsGenuineLocal` không chạy được, báo cáo hiện kèm lý do ("Không khả dụng: ...") thay vì chỉ "Không khả dụng", để dễ tìm nguyên nhân.

## Thay đổi trong v1.7.0

- **Đổi tên/branding cho bớt nhạy cảm:** File `Clean-MAS-Activation.ps1` → `DeActive-Engine.ps1`, `Clean-MAS-Activation.cmd` → `DeActive-Menu.cmd`. Thư mục dữ liệu `C:\ProgramData\LegitActivationCleaner` → `C:\ProgramData\DeActiveByMyPC` (log, report, backup, tên file report đều theo tên mới). File `DeActive-by-MyPC.bat` giữ nguyên là điểm chạy chính.
- **Kiểm tra mạng trước khi kích hoạt:** Trước khi chạy `slmgr /ato` (bước kích hoạt sau khi cài lại key OEM), tool kiểm tra kết nối Internet. Nếu máy offline thì báo trước và bỏ qua kích hoạt (key vẫn được cài), thay vì để lệnh thất bại rồi mới biết.
- **Kiểm tra Genuine sâu hơn:** Chế độ kiểm tra license (mục 6) giờ gọi API `SLIsGenuineLocal` (qua P/Invoke) để lấy trạng thái Genuine thật của Windows (Genuine / Invalid license / Tampered / Offline), chính xác hơn so với chỉ đọc `LicenseStatus`.
- **Báo cáo HTML + tự dọn log cũ:** Ngoài JSON/TXT/CSV, tool tạo thêm báo cáo `.html` dễ đọc. Sau khi chạy xong (khi mở từ menu), có tùy chọn mở file HTML hoặc mở thư mục báo cáo. Tool cũng tự giữ lại 30 report/log gần nhất và xóa bớt file cũ hơn (không đụng tới thư mục backup).

## Thay đổi trong v1.6.0

- **Tính năng mới — Kiểm tra trạng thái license/kích hoạt (chỉ đọc):** Thêm mục menu 6 và tham số `-CheckLicenseOnly`. Chế độ này chỉ đọc và hiển thị Windows/Office đang kích hoạt hay chưa, dạng license gì, mà không thay đổi bất cứ thứ gì.
  - Windows: đọc từ `SoftwareLicensingProduct` (WMI) — hiện phiên bản, kênh key (OEM / Retail / Volume:MAK / Volume:GVLK cho KMS), trạng thái (Licensed / Notification / Grace / Unlicensed), 5 ký tự cuối của key, và hạn dùng qua `slmgr /xpr`.
  - Office: đọc từ `ospp.vbs /dstatusall` — tên license, trạng thái (`---LICENSED---`…), 5 ký tự cuối.
- Báo cáo dạng text giờ liệt kê rõ trạng thái kích hoạt Windows và Office (trước đây chỉ nằm trong file JSON). Áp dụng cho **mọi** lần chạy, không riêng chế độ kiểm tra.
- Menu: mục "Mở thư mục log" chuyển từ 6 sang 7.

Lưu ý: công cụ đọc *trạng thái kích hoạt thực tế* mà Windows/Office báo cáo (đã kích hoạt/genuine hay chưa, dạng license gì). Công cụ không thể — và không nên — "kiểm tra offline một chuỗi key bất kỳ có thật hay không"; chỉ server Microsoft mới xác nhận được một key.

## Thay đổi trong v1.5.0

- **Tính năng mới — Tự động cài lại key OEM:** Sau khi dọn key Windows, công cụ có thể tự động cài lại key Windows OEM chính hãng nhúng trong BIOS/UEFI của máy (`slmgr /ipk`) rồi kích hoạt online (`slmgr /ato`) và kiểm tra lại (`slmgr /dlv`). Trước đây bạn phải đọc log để lấy key rồi tự nhập tay; giờ công cụ làm giúp toàn bộ.
- Khi chạy qua menu, chọn 2 (dọn cả Windows và Office) hoặc 4 (chỉ dọn Windows) sẽ có thêm câu hỏi Y/N: có tự động cài lại và kích hoạt key OEM sau khi dọn hay không. Bạn chủ động đồng ý, không bị làm ngầm.
- Bước cài lại chỉ chạy khi máy thực sự có key OEM nhúng **khớp** với phiên bản Windows đang cài. Nếu key OEM thuộc phiên bản khác, bước này tự bỏ qua để tránh chắc chắn lỗi (có thể ép bằng `-Force`).
- Product key luôn được che (masked) trong log, report và output; key đầy đủ không bao giờ bị ghi ra file kể cả khi cài lại.
- Thêm tham số PowerShell: `-ReinstallOEMKey` (bật cài lại key OEM) và `-SkipOEMActivation` (chỉ cài key, bỏ qua bước kích hoạt online).

## Thay đổi trong v1.4.0

- **Fix N.N 1:** Registry backup thất bại không còn chặn quá trình dọn dẹp khi chạy với tùy chọn đầy đủ (option 2/3/4). Trước đây nếu ổ C gần đầy hoặc không ghi được backup, registry KMS bị bỏ qua im lặng.
- **Fix N.N 2:** Bổ sung đầy đủ các đường dẫn registry Click-to-Run (`ClickToRun\Configuration`, `Policies\...\OfficePolicies`) vào `Clear-OfficeKMSConfiguration`. Đây là nguyên nhân chính khiến Office tự kích hoạt lại KMS sau khi dọn, vì C2R lưu cấu hình KMS riêng.
- **Fix N.N 2:** `Restart-LicensingServices` nay bao gồm `ClickToRunSvc` và `OfficeSvcMgr` để C2R renewal service được reset đúng.
- **Fix N.N 3:** `Stop-OfficeProcessesSafe` được thêm mới và tự động chạy trước bước dọn Ohook. Force-kill toàn bộ tiến trình Office và dừng service ClickToRunSvc để giải phóng file lock trên `sppc.dll` / `OSPPC.DLL`.
- **Fix N.N 3:** `Get-OhookDirectories` bổ sung thêm đường dẫn MSI (`Office16`, `Office15`, `Office14`, `Office19`) để phát hiện Ohook trong cả bản MSI lẫn C2R.
- **Fix N.N 3:** Launcher tự phát hiện tiến trình Office đang chạy và đề nghị force-close thay vì chỉ hỏi người dùng.

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
- Tùy chọn tự động cài lại key OEM tìm thấy và kích hoạt, thay vì nhập tay
- Kiểm tra trạng thái license / kích hoạt Windows và Office (chỉ đọc)
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
   - 6 = Kiểm tra trạng thái license / kích hoạt Windows và Office (chỉ đọc)
   - 7 = Mở thư mục log và báo cáo
6. Chạy xong restart máy nếu vừa dọn Windows/Office.
7. Nhập key bản quyền hoặc đăng nhập Microsoft/Microsoft 365.

## Log, backup và report

Sau khi chạy, dữ liệu nằm tại:

```text
C:\ProgramData\DeActiveByMyPC
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

Có hai chế độ liên quan tới key OEM, tách biệt rõ ràng:

- **Mục 5 (Đọc key OEM) — chỉ đọc.** Chỉ hiển thị thông tin key, không kích hoạt Windows và không thay đổi hệ thống. Chế độ này giữ nguyên như cũ.
- **Cài lại key OEM (mục 2 hoặc 4).** Sau khi dọn key cũ, công cụ dùng chính key OEM chính hãng đã nhúng trong máy để `slmgr /ipk` rồi kích hoạt online. Đây là kích hoạt hợp lệ bằng đúng license gắn theo phần cứng của máy, không phải bypass, không phải KMS. Bước này chỉ chạy khi bạn đồng ý ở câu hỏi Y/N và khi key OEM khớp phiên bản Windows đang cài.

## Tham số PowerShell cho key OEM

- `-ReadOEMKeyOnly` — chỉ đọc key OEM, không thay đổi gì.
- `-ShowFullKeys` — hiện key đầy đủ trên console (log vẫn che).
- `-ExportSensitiveKeys` — cho phép ghi key đầy đủ vào report (chỉ dùng khi giữ report riêng tư).
- `-ReinstallOEMKey` — sau khi dọn Windows, tự động cài lại key OEM nhúng và kích hoạt.
- `-SkipOEMActivation` — dùng kèm `-ReinstallOEMKey`: chỉ cài key, không tự chạy `slmgr /ato`.

Ví dụ chỉ dọn Windows rồi tự cài lại và kích hoạt key OEM:

```text
DeActive-Engine.ps1 -SkipOffice -ForceWindowsProductKeyRemoval -ReinstallOEMKey
```

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
- `DeActive-Menu.cmd` - menu chạy tool, hỗ trợ tiếng Việt/English.
- `DeActive-Engine.ps1` - script PowerShell chính.
- `README.en.md` - tài liệu tiếng Anh.
- `CHECKSUMS.sha256` - danh sách SHA256 của các file phát hành.

## SHA256

Checksum đầy đủ nằm trong `CHECKSUMS.sha256`.
