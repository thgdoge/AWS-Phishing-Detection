# Hướng dẫn sử dụng: AWS Phishing Detection Engine

Hệ thống kiểm tra một **link**, **email** hoặc **file** có dấu hiệu lừa đảo / mã độc hay không, và trả về
**điểm tin cậy 0 đến 100** kèm lý do giải thích bằng tiếng Việt.

**Mục lục**
1. [Đọc kết quả](#1-đọc-kết-quả)
2. [Dùng trên web](#2-dùng-trên-web)
3. [Dùng qua API](#3-dùng-qua-api)
4. [Chạy thử trên máy, không cần AWS](#4-chạy-thử-trên-máy-không-cần-aws)
5. [Cài đặt API key](#5-cài-đặt-api-key)
6. [Cập nhật Lambda](#6-cập-nhật-lambda)
7. [Xử lý sự cố](#7-xử-lý-sự-cố)
8. [Giới hạn đã biết](#8-giới-hạn-đã-biết)

---

## 1. Đọc kết quả

| Điểm | `risk_level` | Ý nghĩa |
|---|---|---|
| từ 80 trở lên | `SAFE` | Không phát hiện dấu hiệu bất thường |
| 50 đến 79 | `SUSPICIOUS` | Có dấu hiệu rủi ro, nên cẩn thận |
| dưới 50 | `DANGEROUS` | Nhiều khả năng là lừa đảo hoặc mã độc |
| (không có điểm) | `SCAN ERROR` | Quét lỗi, giao diện hiện "Chưa kiểm tra được" |

Ngoài điểm, kết quả còn có:

| Trường | Nội dung |
|---|---|
| `reasons` | Danh sách lý do vì sao điểm thấp (tiếng Việt) |
| `signals` | Từng điểm trừ, kèm mã và nhóm |
| `confidence` | `HIGH` (từ 2 nguồn uy tín trả lời), `MEDIUM` (1 nguồn, hoặc email chỉ có chữ), `LOW` (chưa có nguồn nào, kết quả chỉ dựa phân tích kỹ thuật) |
| `details` | Số liệu kỹ thuật chi tiết (tên miền, hash file, SPF/DKIM...) |

> `SAFE` với `confidence: LOW` **không có nghĩa là chắc chắn an toàn**, chỉ là chưa thấy dấu hiệu xấu
> và chưa đối chiếu được với nguồn bên ngoài.

---

## 2. Dùng trên web

1. Mở trang giao diện (file `frontend/index.html`).
2. Chọn tab **Link**, **Email** hoặc **File**.
3. Dán nội dung (hoặc chọn file) rồi bấm quét.
4. Đợi vài giây đến khoảng 1 phút. Kết quả hiện gồm điểm, mức rủi ro và các lý do.

| Loại | Giới hạn |
|---|---|
| Link | tối đa 2048 ký tự |
| Email | tối đa 20.000 ký tự. Nên dán **cả phần header** để kiểm tra được SPF/DKIM/DMARC |
| File | tối đa 10 MB |

**Chạy giao diện trên máy:** mở terminal trong thư mục `frontend` rồi chạy
```
python -m http.server 8000
```
Vào trình duyệt, mở `http://localhost:8000/index.html`. Địa chỉ API mà giao diện gọi nằm trong
`frontend/js/config.js` (`API_BASE`).

---

## 3. Dùng qua API

Địa chỉ gốc: `https://kp3je8ijff.execute-api.ap-southeast-1.amazonaws.com`

### Quét link (PowerShell)

```powershell
$base = "https://kp3je8ijff.execute-api.ap-southeast-1.amazonaws.com"
$job  = Invoke-RestMethod -Uri "$base/scan" -Method Post -ContentType "application/json" `
        -Body (@{type="link"; payload="http://paypal-security-update-fake.com/login"} | ConvertTo-Json)
$job                      # có job_id, status = PENDING
Start-Sleep 20
$r = Invoke-RestMethod -Uri "$base/scan/$($job.job_id)"
$r.status
$r.result.risk_level
$r.result.confidence
$r.result.reasons
```
Nếu `$r.status` còn `PENDING` hoặc `PROCESSING` thì đợi thêm 10 giây rồi chạy lại hai dòng `$r = ...` và `$r.status`.

### Quét email

Thay `type` thành `email` và `payload` là toàn bộ nội dung email (nên có header). Với email nhiều dòng, nên đọc từ file:
```powershell
$text = Get-Content -Raw -Encoding UTF8 .\email.txt
$job  = Invoke-RestMethod -Uri "$base/scan" -Method Post -ContentType "application/json; charset=utf-8" `
        -Body (@{type="email"; payload=$text} | ConvertTo-Json)
```

### Quét file (hai bước)

`payload` là **tên file**. Hệ thống trả về `upload_url` (địa chỉ tạm, sống **5 phút**). Bạn phải tải file lên đó
**ngay**, rồi hỏi kết quả như bình thường.
```powershell
$path = "C:\duong\dan\tep.pdf"
$job  = Invoke-RestMethod -Uri "$base/scan" -Method Post -ContentType "application/json" `
        -Body (@{type="file"; payload=(Split-Path $path -Leaf)} | ConvertTo-Json)
Invoke-RestMethod -Uri $job.upload_url -Method Put -InFile $path -ContentType "application/octet-stream"
Start-Sleep 30
Invoke-RestMethod -Uri "$base/scan/$($job.job_id)"
```
Worker chờ file xuất hiện trên S3 tối đa 30 giây. Quá 5 phút kể từ lúc tạo job thì phải tạo job mới.

### Trạng thái job

`PENDING` (đã nhận) → `PROCESSING` (đang quét) → `COMPLETED` (xong, có `result`).

---

## 4. Chạy thử trên máy, không cần AWS

Cần Python 3.10 trở lên. Mở terminal trong thư mục `backend`.

**Chạy bộ test:**
```
python -m unittest discover -s tests -t .
```
Kết quả đúng kết thúc bằng `OK`. Vài dòng chữ đỏ hoặc `Traceback` ở giữa là log của các ca lỗi được test cố ý.

**Quét thử:**
```
python scan_local.py link  "http://paypal-security-update-fake.com/login" --offline
python scan_local.py email samples\email_lua_dao.txt --offline
python scan_local.py file  duong\dan\tep.pdf --offline
```
- `--offline`: chỉ phân tích tĩnh, không gọi dịch vụ nào trên mạng.
- Bỏ `--offline` để tra cứu thật (xem mục 5 để đặt key).
- Thêm `--json` để in toàn bộ kết quả.
- Chế độ quét file chỉ tra theo **mã băm**, không upload tệp lên VirusTotal.

> Khi bỏ `--offline`, công cụ **truy cập thật vào link** để theo dõi redirect và đọc trang đích, nên link độc hại
> sẽ thấy IP máy bạn. Chỉ thử với link bạn thấy yên tâm.

---

## 5. Cài đặt API key

Có 3 loại key (đều miễn phí, đều không bắt buộc, có key nào dùng nguồn đó):

| Tên | Lấy ở đâu | Dùng cho |
|---|---|---|
| `VT_API_KEY` | virustotal.com → avatar → API key | VirusTotal (link, file). Gói free: 4 lượt/phút, 500 lượt/ngày |
| `GSB_API_KEY` | Google Cloud Console: bật **Safe Browsing API**, rồi tạo API key | Safe Browsing (link) |
| `ABUSECH_AUTH_KEY` | auth.abuse.ch | URLhaus (link), MalwareBazaar (file) |

Thiếu key thì nguồn đó bị bỏ qua và `confidence` giảm, hệ thống vẫn chạy.

> **Không bao giờ** dán key vào code, README, GitHub hay chat. Repo đang để Public.

### Trên máy (PowerShell)

Đặt key trong **cùng cửa sổ** sẽ chạy lệnh. Đóng cửa sổ là mất.
```powershell
$env:VT_API_KEY="dán_key_vào_đây"
$env:GSB_API_KEY="dán_key_vào_đây"
$env:ABUSECH_AUTH_KEY="dán_key_vào_đây"
python scan_local.py link "https://example.com"
```

### Trên AWS: cách 1, biến môi trường Lambda (đơn giản)

Lambda → hàm → **Configuration → Environment variables → Edit**, thêm key dưới dạng biến cùng tên ở bảng trên.
Dán key **trần**, không có dấu ngoặc kép. Không cần `SSM_PREFIX`.

| Hàm | Biến key cần thêm |
|---|---|
| `FastDetectWorker` | `VT_API_KEY`, `GSB_API_KEY`, `ABUSECH_AUTH_KEY` |
| `FileDetectWorker` | `VT_API_KEY`, `ABUSECH_AUTH_KEY` |

### Trên AWS: cách 2, SSM Parameter Store (an toàn hơn)

Key được cất mã hóa ở một chỗ, Lambda tự đọc khi chạy. Làm theo thứ tự:

1. **Tạo parameter.** Systems Manager → **Parameter Store → Create parameter**, vùng **Singapore**.
   Tier **Standard**, type **SecureString**, ô **Value** dán chuỗi key thật:

   | Name | Value |
   |---|---|
   | `/phishing/VT_API_KEY` | key VirusTotal |
   | `/phishing/GSB_API_KEY` | key Safe Browsing |
   | `/phishing/ABUSECH_AUTH_KEY` | key abuse.ch |
   | `/phishing/VT_BACKUP_API_KEYS` (tùy chọn) | các key VT dự phòng, ngăn cách bằng dấu phẩy |

2. **Cấp quyền cho role của Lambda.** Lambda → hàm → **Configuration → Permissions** → bấm tên role →
   **Add permissions → Create inline policy → tab JSON**, dán (thay `ACCOUNT_ID` bằng số tài khoản 12 chữ số):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": "ssm:GetParameter",
       "Resource": "arn:aws:ssm:ap-southeast-1:ACCOUNT_ID:parameter/phishing/*"
     }]
   }
   ```
   Đặt tên `ReadPhishingKeys`. Nếu hai hàm dùng chung một role thì chỉ cần tạo một lần.
   Nếu dùng khóa KMS tự tạo thì thêm quyền `kms:Decrypt`.

3. **Chỉnh biến môi trường của cả hai worker.** Thêm `SSM_PREFIX` = `/phishing`, và **xóa** các biến chứa key cũ
   (`VT_API_KEY`, `GSB_API_KEY`, `ABUSECH_AUTH_KEY`, `VT_BACKUP_API_KEYS`). Phải xóa vì code luôn ưu tiên biến môi trường.

Code lấy key theo thứ tự: **biến môi trường → SSM → bỏ qua nguồn đó**. Key đọc từ SSM được nhớ suốt vòng đời của
Lambda, nên đổi key trên SSM chỉ có hiệu lực khi Lambda khởi động lại (container mới).

---

## 6. Cập nhật Lambda

Chỉ có **hai hàm worker** chạy code của phần phát hiện. `IngestLambda` và `StatusLambda` không thay đổi.

1. Đóng gói (tùy chọn, nếu bạn sửa code): trong thư mục `backend` chạy `python build_zip.py`, tạo ra `dist/detect-workers.zip`.
2. Với **từng** hàm `FastDetectWorker` và `FileDetectWorker`: tab **Code → Upload from → .zip file** → chọn
   `detect-workers.zip` → **Save**. Cả hai hàm dùng **cùng một file zip**.
3. Kiểm tra **Handler** (Code → Runtime settings → Edit):

   | Hàm | Handler |
   |---|---|
   | `FastDetectWorker` | `fast_detect_worker.lambda_handler` |
   | `FileDetectWorker` | `file_detect_worker.lambda_handler` |

4. Chỉnh **Configuration → General configuration → Edit**:

   | | FastDetectWorker | FileDetectWorker |
   |---|---|---|
   | Timeout | 45 giây | 90 giây |
   | Memory | 512 MB | 1024 MB |
   | Ephemeral storage | mặc định | 1024 MB |

5. Biến môi trường cần có:

   | Biến | Ghi chú |
   |---|---|
   | `JOBS_TABLE` | tên bảng DynamoDB lưu job (vd. `PhishingScanJobs`) |
   | `CACHE_TABLE` | tên bảng cache (vd. `PhishingScanCache`) |
   | `REPORTS_BUCKET` | (tùy chọn) bucket S3 lưu log JSON. Không đặt thì bỏ qua việc ghi log |
   | `SSM_PREFIX` | (nếu dùng SSM) `/phishing` |
   | `VT_UPLOAD_UNKNOWN_FILES` | (tùy chọn, chỉ file worker) mặc định `true`: file chưa có trên VirusTotal sẽ **được upload lên VirusTotal**. Đặt `false` nếu lo ngại riêng tư |

6. Quét thử (mục 3). Bản mới chạy đúng khi kết quả có trường `confidence` và `reasons`.

**Chi tiết kỹ thuật và bảng luật chấm điểm đầy đủ** nằm trong `backend/README.md`.

---

## 7. Xử lý sự cố

Xem log: Lambda → hàm → tab **Monitor → View CloudWatch logs** → mở log stream mới nhất.

| Hiện tượng | Nguyên nhân thường gặp | Cách xử lý |
|---|---|---|
| Kết quả **không có** `confidence`, `reasons` | Lambda vẫn chạy bản cũ | Upload lại `detect-workers.zip`, kiểm tra Handler |
| Lỗi `Unable to import module` trong log | Sai Handler, hoặc zip upload sai cấu trúc | Sửa Handler như mục 6; zip phải có `fast_detect_worker.py` ở **gốc** |
| `Task timed out` | Timeout quá thấp | Tăng Timeout như mục 6 |
| `virustotal_report.status` = `NO_API_KEY` | Chưa có key, hoặc đặt sai tên biến/tên parameter | Xem mục 5; tên phải đúng từng chữ, phân biệt hoa thường |
| Log: `[api_keys] ... AccessDeniedException` | Chưa gắn policy, hoặc sai vùng/số tài khoản trong policy | Kiểm tra lại policy `ReadPhishingKeys` |
| Log: `[api_keys] ... ParameterNotFound` | Sai tên parameter hoặc tạo ở vùng khác | Tạo lại đúng vùng Singapore. Riêng `VT_BACKUP_API_KEYS` báo dòng này là **bình thường** |
| `virustotal_report.status` = `SCAN_PENDING` | VirusTotal quét link mới chưa xong | Quét lại sau ít phút |
| `virustotal_report` có `notes` chứa `HTTP 429` | Hết hạn mức VirusTotal (4 lượt/phút, 500 lượt/ngày) | Đợi, hoặc thêm key dự phòng |
| `risk_level` = `SCAN ERROR` | Lỗi trong lúc phân tích | Xem log, tìm dòng `Lỗi phân tích job` |
| File báo lỗi "Không nhận được tệp tải lên" | Chưa tải file lên `upload_url`, hoặc quá 5 phút | Tạo job mới rồi tải file lên ngay |
| Mãi ở `PENDING` | Worker chưa nhận được việc hoặc đang lỗi | Xem log của worker tương ứng, kiểm tra SQS |
| Quét lại **cùng một link** trong 24 giờ ra **HTTP 500** | Lỗi cũ ở `IngestLambda`: nhánh cache dùng `json.dumps(body)` thiếu `default=str` | Nhờ người phụ trách `IngestLambda` đổi thành `json.dumps(body, default=str)` |
| Trình duyệt báo lỗi CORS khi chạy giao diện ở `localhost` | API Gateway hoặc bucket S3 chưa cho phép nguồn `localhost` | Nhờ người phụ trách cấu hình CORS |

---

## 8. Giới hạn đã biết

- **ClamAV** chỉ chạy khi môi trường có chương trình `clamscan`. Lambda thường không có, nên trạng thái thực tế là `SKIPPED`.
- **YARA** hiện là bộ luật chuỗi byte tự viết (`YARA-lite`), chưa phải thư viện YARA thật.
- **NLP** của email là bộ luật ngôn ngữ Anh–Việt, không phải mô hình học máy.
- **WHOIS** thực hiện qua **RDAP**. Nhiều đuôi tên miền không có RDAP công khai; khi không có dữ liệu thì **không bị trừ điểm**.
- **SPF/DKIM/DMARC** được đọc từ kết quả có sẵn trong header email, hệ thống **không tự tra DNS**. Email dán thiếu header thì bỏ qua phần này.
- Danh sách tên miền uy tín chỉ bỏ qua các luật từ khóa/thương hiệu, **không** bỏ qua kết quả VirusTotal hay Safe Browsing.
- RAR và 7z chưa được mở ra để kiểm tra bên trong.
- Hạn mức gói miễn phí của VirusTotal rất thấp, nên đặt giới hạn đồng thời thấp cho worker khi cần.
