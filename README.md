# AWS Phishing Detection Engine

Hệ thống phát hiện và cảnh báo tấn công giả mạo (Phishing Detection) đa kênh dành cho **Đường link (URL)**, **Nội dung Email** và **Tệp đính kèm (File)**, xây dựng hoàn toàn trên kiến trúc **100% Serverless** hướng sự kiện (Event-driven) trên nền tảng điện toán đám mây Amazon Web Services (AWS) với chi phí vận hành xấp xỉ **$0** (nằm trọn trong gói AWS Free Tier).

Kết quả là một **điểm tin cậy từ 0 đến 100** kèm lý do giải thích bằng tiếng Việt.

**Tài liệu liên quan**

| Tài liệu | Nội dung |
| :--- | :--- |
| [`HUONG_DAN_SU_DUNG.md`](HUONG_DAN_SU_DUNG.md) | Hướng dẫn sử dụng từng bước: web, API, chạy thử, cài API key / SSM, cập nhật Lambda, xử lý sự cố |
| [`backend/README.md`](backend/README.md) | Chi tiết Detect Worker & Scoring Engine, bảng luật chấm điểm đầy đủ, cấu hình Lambda |
| [`frontend/README.md`](frontend/README.md) | Giao diện web |

---

## 1. Kiến trúc Tổng quan (Architecture & Workflow)

Hệ thống hoạt động theo mô hình xử lý bất đồng bộ (Asynchronous Event-driven Architecture) gồm 6 tầng độc lập:

```text
[User Input: Link / Email / File]
       │
       ▼
[Frontend: frontend/index.html]
  • Link/Email ──► POST /scan (API Gateway HTTP API)
  • File       ──► Nhận Presigned URL ──► Upload trực tiếp lên S3
       │
       ▼
[Backend: IngestLambda]
  • Hash SHA-256 ──► Tra cứu bộ đệm PhishingScanCache (DynamoDB)
  • Nếu chưa có: Tạo Job ID ──► Lưu trạng thái PENDING vào PhishingScanJobs
  • Phân loại và đẩy message vào hàng đợi (Amazon SQS)
       │
       ├──────────────────────────────┬──────────────────────────────┐
       ▼                              ▼                              ▼
 [phishing-fast-queue]      [phishing-file-queue]            [phishing-dlq]
  (Visibility: 60s)          (Visibility: 300s)             (Hàng đợi lỗi DLQ)
       │                              │
       ▼                              ▼
 [FastDetectWorker]          [FileDetectWorker]
  • Phân tích Link            • Chờ S3 upload hoàn tất
  • Phân tích Email           • Hash SHA-256 & MD5
                              • Magic Bytes, luật kiểu YARA
                              • Macro / PDF / file nén, Entropy
                              • VirusTotal, MalwareBazaar, ClamAV (*)
       │                              │
       └──────────────┬───────────────┘
                      ▼
            [Scoring Engine]
              • Tổng hợp trọng số ──► Tính Trust Score (0 - 100)
                      │
                      ▼
            [DB & Storage]
              • Cập nhật trạng thái COMPLETED vào DynamoDB
              • Ghi đệm vào PhishingScanCache (TTL 24 giờ)
              • Lưu trữ Audit Log JSON lên S3 (nếu đặt REPORTS_BUCKET)
                      │
                      ▼
            [Frontend + StatusLambda]
              • Frontend hỏi kết quả mỗi 2 giây cho tới khi COMPLETED
```

(*) ClamAV chỉ chạy khi môi trường có sẵn chương trình `clamscan`. Lambda thông thường không có, nên mặc định bị bỏ qua.

> **Xuất báo cáo PDF** chưa có trong mã hiện tại (chỉ còn trong thư mục `BackUp/`).

### Detect Worker kiểm tra những gì

| Loại | Các kiểm tra chính |
| :--- | :--- |
| **Link** | Tuổi tên miền (qua RDAP), chuỗi chuyển hướng, chứng chỉ SSL, trang đích có ô mật khẩu, từ khóa nhạy cảm, giả mạo thương hiệu, cấu trúc URL bất thường; tra cứu VirusTotal, Google Safe Browsing, URLhaus |
| **Email** | SPF / DKIM / DMARC đọc từ header, Reply-To / tên hiển thị giả mạo, cụm từ hối thúc và đòi thông tin nhạy cảm (tiếng Việt có dấu lẫn không dấu), chữ link khác địa chỉ thật; chấm điểm riêng từng link và tệp đính kèm |
| **File** | Hash SHA-256 và MD5, đuôi tệp giả mạo, magic bytes, luật kiểu YARA, macro và template từ xa trong Office, mã chủ động trong PDF, tệp thực thi trong file nén, biểu mẫu mật khẩu trong HTML, Shannon Entropy; tra cứu VirusTotal, MalwareBazaar |

---

## 2. Bảng Ánh xạ Dịch vụ AWS & Chiến lược Tối ưu Chi phí

| Tầng chức năng | Dịch vụ AWS sử dụng | Giải pháp kỹ thuật & Tối ưu chi phí |
| :--- | :--- | :--- |
| **Cổng API (API Gateway)** | Amazon API Gateway (HTTP API) | Chọn HTTP API thay vì REST API để giảm ~70% chi phí gọi cổng API. Bật CORS đầy đủ cho phép gọi từ mọi client. |
| **Xử lý tác vụ (Compute)** | AWS Lambda (Python 3.12, arm64) | Chạy trên kiến trúc chip Graviton2 (`arm64`) giúp tiết kiệm ~20% chi phí. Tận dụng 1 triệu request và 400.000 GB-giây miễn phí/tháng. |
| **Hàng đợi đệm (Queues)** | Amazon SQS (Standard Queue) | Tách riêng luồng xử lý nhanh (`fast-queue`) và luồng quét file nặng (`file-queue`). Gắn Dead-Letter Queue (`dlq`) ngăn lặp vô tận. |
| **Cơ sở dữ liệu (Database)** | Amazon DynamoDB | Chọn chế độ Provisioned (5 RCU / 5 WCU) để nằm trọn trong hạn mức miễn phí vĩnh viễn (25 RCU/WCU). Bật TTL tự dọn dữ liệu cũ. |
| **Lưu trữ đối tượng (Storage)** | Amazon Simple Storage Service (S3) | Dùng S3 Presigned URL để upload file trực tiếp từ trình duyệt. Bật Lifecycle Rules xóa file rác sau 1–7 ngày. |
| **Cất API key (tùy chọn)** | AWS Systems Manager Parameter Store | Lưu key dạng `SecureString` (mã hóa) ở một chỗ, hai worker cùng đọc. Loại Standard không tính phí lưu. Có thể thay bằng biến môi trường Lambda. |

**Nguồn bên ngoài AWS** (gọi qua internet, dùng gói miễn phí): VirusTotal, Google Safe Browsing, URLhaus và MalwareBazaar (abuse.ch), RDAP. Hạn mức miễn phí của VirusTotal khá thấp (4 lượt/phút, 500 lượt/ngày).

---

## 3. Cấu trúc Thư mục Dự án

```text
phishing-detection-aws/
├── frontend/
│   ├── index.html                # Giao diện web SPA (Link, Email, File)
│   ├── css/
│   └── js/                       # config.js chứa địa chỉ API (API_BASE)
├── backend/
│   ├── ingest_lambda.py          # Lambda tiếp nhận request, check cache, điều phối SQS
│   ├── status_lambda.py          # Lambda tra cứu trạng thái & kết quả
│   ├── fast_detect_worker.py     # Handler Detect Worker cho Link & Email
│   ├── file_detect_worker.py     # Handler Detect Worker cho File
│   ├── common/                   # Scoring Engine (scoring.py), pipeline, lưu trữ, mạng, nguồn uy tín, api_keys
│   ├── detectors/                # Detector Link / Email / File
│   ├── tests/                    # 113 unit test, không cần mạng hay AWS
│   ├── samples/                  # Email mẫu để chạy thử
│   ├── scan_local.py             # Quét thử link/email/file ngay trên máy
│   ├── build_zip.py              # Đóng gói dist/detect-workers.zip cho Lambda
│   └── README.md                 # Tài liệu chi tiết Detect Worker & Scoring Engine
├── BackUp/                       # Bản lưu cũ, KHÔNG phải mã đang chạy
├── HUONG_DAN_SU_DUNG.md          # Hướng dẫn sử dụng chi tiết
├── .gitignore
└── README.md                     # Tài liệu tổng quan hệ thống
```

---

## 4. Đặc tả Giao diện Lập trình (API Specifications)

* **Base URL:** `https://kp3je8ijff.execute-api.ap-southeast-1.amazonaws.com`

### 4.1. Gửi yêu cầu phân tích (POST `/scan`)
* **Headers:** `Content-Type: application/json`
* **Request Body (Quét Link):**
  ```json
  {
    "type": "link",
    "payload": "http://paypal-security-update-fake.com"
  }
  ```
* **Request Body (Quét Email):**
  ```json
  {
    "type": "email",
    "payload": "Urgent: Your account will be suspended within 24 hours. Click here to verify."
  }
  ```
* **Request Body (Quét File):**
  ```json
  {
    "type": "file",
    "payload": "invoice_malware.exe"
  }
  ```
* **Response:**
  ```json
  {
    "job_id": "e786a5b8-fcec-4f4b-beb4-e53c3eb1f68e",
    "status": "PENDING",
    "upload_url": "https://phishing-raw-uploads-....s3.amazonaws.com/..." // (chỉ có khi type=file)
  }
  ```
  Với file, `upload_url` chỉ có hiệu lực **5 phút**: phải tải file lên địa chỉ đó (`PUT`) ngay sau khi nhận được.

### 4.2. Tra cứu trạng thái & Kết quả (GET `/scan/{job_id}`)
* **Response (Đang xử lý):**
  ```json
  {
    "job_id": "e786a5b8-fcec-4f4b-beb4-e53c3eb1f68e",
    "status": "PROCESSING"
  }
  ```
* **Response (Đã hoàn tất):**
  ```json
  {
    "job_id": "e786a5b8-fcec-4f4b-beb4-e53c3eb1f68e",
    "status": "COMPLETED",
    "type": "link",
    "trust_score": 10,
    "result": {
      "trust_score": 10,
      "risk_level": "DANGEROUS",
      "confidence": "HIGH",
      "reasons": [
        "Tên miền mới đăng ký cách đây 3 ngày",
        "Tên miền chứa tên \"paypal\" nhưng không phải trang chính thức",
        "Chứa từ khóa nhạy cảm: login, update, security"
      ],
      "signals": [
        {"code": "DOMAIN_NEW", "category": "domain", "penalty": 35, "reason": "Tên miền mới đăng ký cách đây 3 ngày"}
      ],
      "details": {
        "domain": "paypal-security-update-fake.com",
        "uses_https": false,
        "suspicious_keywords": ["login", "update", "security"],
        "domain_age_days": 3,
        "redirection_count": 0
      },
      "scoring_version": "2.0",
      "scanned_at": 1792123838
    }
  }
  ```
  * `status`: `PENDING` → `PROCESSING` → `COMPLETED`.
  * `risk_level` nhận `SAFE`, `SUSPICIOUS`, `DANGEROUS`, hoặc `SCAN ERROR` khi quét lỗi (frontend hiển thị "Chưa kiểm tra được").
  * `confidence` (`HIGH` / `MEDIUM` / `LOW`) cho biết kết luận dựa trên bao nhiêu nguồn uy tín bên ngoài đã trả lời được.
    `SAFE` kèm `LOW` chỉ có nghĩa là chưa thấy dấu hiệu xấu, **không** phải đã được xác nhận an toàn.
  * **Lưu ý:** `StatusLambda` hiện trả các giá trị số dưới dạng chuỗi (ví dụ `"10"`). Hãy ép kiểu (`Number()`, `[int]`...) khi dùng.

---

## 5. Quy tắc Đánh giá & Chấm điểm (Scoring Engine)

Thang điểm **0 đến 100** (khởi điểm 100 - an toàn tuyệt đối). Logic nằm ở `backend/common/scoring.py`:
detector chỉ phát hiện, còn **bảng luật `RULES`** quyết định điểm trừ, lý do hiển thị và mức trần.

* **Thang phân loại rủi ro:**
  * **$\ge 80$ điểm:** `SAFE` - Không phát hiện dấu hiệu bất thường.
  * **$50 - 79$ điểm:** `SUSPICIOUS` - Có dấu hiệu rủi ro tiềm ẩn.
  * **$< 50$ điểm:** `DANGEROUS` - Phát hiện hành vi lừa đảo hoặc mã độc rõ rệt.

* **Cơ chế chống trừ điểm quá tay:** mỗi `code` chỉ tính một lần; mỗi nhóm tín hiệu (URL, tên miền, người gửi,
  nội dung, tệp...) có mức trừ tối đa riêng; tín hiệu nghiêm trọng đặt *trần điểm* (ClamAV/MalwareBazaar phát hiện
  => 0 điểm, Google Safe Browsing/URLhaus báo => tối đa 20 điểm, từ 5 engine VirusTotal báo mã độc cho file => 0 điểm).

* **Không biến "không hỏi được" thành "sạch":** nguồn nào thiếu key, hết hạn mức hoặc lỗi mạng sẽ bị bỏ qua và làm
  `confidence` giảm, chứ không được tính là an toàn. Kết quả `LOW` hoặc `SCAN ERROR` không được ghi vào bộ đệm.

* **Các nhóm kiểm tra chính** (số điểm cụ thể xem bảng trong `backend/README.md`):
  * **Link:** HTTPS, IP thay domain (kể cả IP dạng số/hex), TLD rủi ro, từ khóa nhạy cảm (so khớp theo token),
    giả mạo thương hiệu (kể cả `paypa1`, `rnicrosoft`), ký tự `@`, Punycode, link rút gọn, tuổi tên miền (RDAP),
    chuỗi chuyển hướng, chứng chỉ SSL, trang đích có ô mật khẩu, VirusTotal / Safe Browsing / URLhaus.
  * **Email:** SPF/DKIM/DMARC từ header thật, Reply-To / Return-Path / tên hiển thị giả mạo, cụm từ hối thúc và đòi
    thông tin nhạy cảm (tiếng Việt có dấu lẫn không dấu), văn bản link khác địa chỉ thật, điểm của từng link và tệp đính kèm.
  * **File:** đuôi kép / ký tự RLO, magic bytes so với đuôi, luật kiểu YARA, macro và template từ xa trong Office,
    mã chủ động trong PDF, tệp thực thi trong file nén, biểu mẫu mật khẩu trong HTML, Shannon Entropy $> 7.5$
    (chỉ với tệp thực thi/script), VirusTotal, MalwareBazaar, ClamAV (nếu có).

---

## 6. Hướng dẫn Khởi chạy Nhanh (Quick Start)

Hướng dẫn đầy đủ từng bước nằm trong [`HUONG_DAN_SU_DUNG.md`](HUONG_DAN_SU_DUNG.md). Dưới đây là phần tóm tắt.

### 6.1. Chạy giao diện Web cục bộ (Frontend)
1. Đảm bảo máy tính đã cài đặt Python 3.
2. Mở terminal tại thư mục `frontend` (chứa file `index.html`) và chạy:
   ```bash
   python -m http.server 8000
   ```
3. Truy cập vào trình duyệt: `http://localhost:8000/index.html`.

Địa chỉ API mà giao diện gọi nằm trong `frontend/js/config.js` (`API_BASE`).

### 6.2. Kiểm thử bằng PowerShell
```powershell
$base = "https://kp3je8ijff.execute-api.ap-southeast-1.amazonaws.com"
$job  = Invoke-RestMethod -Uri "$base/scan" -Method Post -ContentType "application/json" `
        -Body '{"type": "link", "payload": "http://paypal-security-update-fake.com"}'
$job
Start-Sleep 20
Invoke-RestMethod -Uri "$base/scan/$($job.job_id)"
```
Nếu `status` còn `PENDING` hoặc `PROCESSING`, đợi thêm vài giây rồi chạy lại dòng cuối.

### 6.3. Chạy thử phần backend trên máy (không cần AWS)
Cần Python 3.10 trở lên. Trong thư mục `backend`:
```bash
python -m unittest discover -s tests -t .
python scan_local.py link  "http://paypal-security-update-fake.com/login" --offline
python scan_local.py email samples/email_lua_dao.txt --offline
python scan_local.py file  duong/dan/tep.pdf --offline
```
Bỏ `--offline` để tra cứu thật (cần API key, xem mục 6.4).

### 6.4. API key

| Biến / tên parameter | Dùng cho | Lấy ở đâu |
| :--- | :--- | :--- |
| `VT_API_KEY` | VirusTotal | virustotal.com |
| `GSB_API_KEY` | Google Safe Browsing | Google Cloud Console (bật Safe Browsing API) |
| `ABUSECH_AUTH_KEY` | URLhaus, MalwareBazaar | auth.abuse.ch |

Code lấy key theo thứ tự: **biến môi trường → AWS SSM Parameter Store → bỏ qua nguồn đó**.
Trên Lambda có hai cách: đặt biến môi trường, hoặc tạo parameter `/phishing/<TÊN_KEY>` kiểu `SecureString`, đặt
biến `SSM_PREFIX=/phishing` và cấp quyền `ssm:GetParameter` cho role. Chi tiết trong `HUONG_DAN_SU_DUNG.md`.

> **Tuyệt đối không dán API key vào code, README hay commit lên GitHub.** Repo ở chế độ Public và lịch sử commit
> luôn được lưu lại.

### 6.5. Triển khai worker lên Lambda
1. Trong thư mục `backend`: `python build_zip.py` (tạo `dist/detect-workers.zip`).
2. Upload **cùng một file zip** vào hai hàm `FastDetectWorker` và `FileDetectWorker`.
3. Đặt Handler: `fast_detect_worker.lambda_handler` và `file_detect_worker.lambda_handler`.
4. Timeout / Memory gợi ý: Fast 45 giây / 512 MB, File 90 giây / 1024 MB.

`IngestLambda` và `StatusLambda` không thuộc phần detect nên không cần upload lại.

---

## 7. Giới hạn đã biết

* **ClamAV** chỉ chạy khi môi trường có `clamscan` (cần Lambda container image). Mặc định bị bỏ qua.
* **YARA** hiện là bộ luật chuỗi byte tự viết (`YARA-lite`), chưa phải thư viện YARA thật.
* **NLP** của email là bộ luật ngôn ngữ Anh–Việt, không phải mô hình học máy.
* **WHOIS** thực hiện qua **RDAP**; nhiều đuôi tên miền không có RDAP công khai, khi đó không bị trừ điểm.
* **SPF/DKIM/DMARC** đọc từ kết quả có sẵn trong header email, hệ thống không tự tra DNS.
* **Xuất báo cáo PDF** chưa có trong mã hiện tại.
* Hạn mức miễn phí của VirusTotal rất thấp; nên đặt giới hạn đồng thời thấp cho worker.
* Quét lại **cùng một link/email** trong vòng 24 giờ có thể trả lỗi 500 do `IngestLambda` serialize `Decimal`
  thiếu `default=str` ở nhánh bộ đệm; cần sửa trong `ingest_lambda.py`.

Danh sách đầy đủ ở `backend/README.md`.

---

## 8. Giấy phép & Đóng góp (License)

Dự án được phát triển phục vụ mục đích nghiên cứu học thuật, đồ án an toàn thông tin và ứng dụng điện toán đám mây. Mọi thành viên trong nhóm có toàn quyền kế thừa, mở rộng và triển khai phi thương mại.
