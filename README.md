# AWS Phishing Detection Engine

Hệ thống phát hiện và cảnh báo tấn công giả mạo (Phishing Detection) đa kênh dành cho **Đường link (URL)**, **Nội dung Email** và **Tệp đính kèm (File)**, xây dựng hoàn toàn trên kiến trúc **100% Serverless** hướng sự kiện (Event-driven) trên nền tảng điện toán đám mây Amazon Web Services (AWS) với chi phí vận hành xấp xỉ **$0** (nằm trọn trong gói AWS Free Tier).

---

## 1. Kiến trúc Tổng quan (Architecture & Workflow)

Hệ thống hoạt động theo mô hình xử lý bất đồng bộ (Asynchronous Event-driven Architecture) gồm 6 tầng độc lập:

```text
[User Input: Link / Email / File]
       │
       ▼
[Frontend: index.html]
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
  • Phân tích Link:           • Chờ S3 upload hoàn tất
    WHOIS, SSL, Redirect,      • Hash SHA-256 & MD5
    Suspicious Keywords        • Magic Bytes vs Extension
  • Phân tích Email:          • Static YARA Signatures
    SPF/DKIM/DMARC, NLP        • Shannon Entropy & ClamAV
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
              • Lưu trữ Audit Log JSON lên S3
                      │
                      ▼
            [Reports & Delivery]
              • Frontend Poll kết quả thời gian thực
              • Xuất báo cáo PDF bảo mật qua S3 Presigned URL
```

---

## 2. Bảng Ánh xạ Dịch vụ AWS & Chiến lược Tối ưu Chi phí

| Tầng chức năng | Dịch vụ AWS sử dụng | Giải pháp kỹ thuật & Tối ưu chi phí |
| :--- | :--- | :--- |
| **Cổng API (API Gateway)** | Amazon API Gateway (HTTP API) | Chọn HTTP API thay vì REST API để giảm ~70% chi phí gọi cổng API. Bật CORS đầy đủ cho phép gọi từ mọi client. |
| **Xử lý tác vụ (Compute)** | AWS Lambda (Python 3.12, arm64) | Chạy trên kiến trúc chip Graviton2 (`arm64`) giúp tiết kiệm ~20% chi phí. Tận dụng 1 triệu request và 400.000 GB-giây miễn phí/tháng. |
| **Hàng đợi đệm (Queues)** | Amazon SQS (Standard Queue) | Tách riêng luồng xử lý nhanh (`fast-queue`) và luồng quét file nặng (`file-queue`). Gắn Dead-Letter Queue (`dlq`) ngăn lặp vô tận. |
| **Cơ sở dữ liệu (Database)** | Amazon DynamoDB | Chọn chế độ Provisioned (5 RCU / 5 WCU) để nằm trọn trong hạn mức miễn phí vĩnh viễn (25 RCU/WCU). Bật TTL tự dọn dữ liệu cũ. |
| **Lưu trữ đối tượng (Storage)** | Amazon Simple Storage Service (S3) | Dùng S3 Presigned URL để upload/download file trực tiếp từ trình duyệt. Bật Lifecycle Rules xóa file rác sau 1–7 ngày. |

---

## 3. Cấu trúc Thư mục Dự án

```text
phishing-detection-aws/
├── frontend/
│   └── index.html                # Giao diện web SPA (hỗ trợ Link, Email, File, PDF)
├── backend/
│   ├── ingest_lambda.py          # Lambda tiếp nhận request, check cache, điều phối SQS
│   ├── status_lambda.py          # Lambda tra cứu kết quả quét & xuất file PDF lên S3
│   ├── fast_detect_worker.py     # Worker phân tích Link, Email & tính điểm Trust Score
│   └── file_detect_worker.py     # Worker phân tích File (Hash, Magic Bytes, YARA, Entropy)
└── README.md                     # Tài liệu hướng dẫn hệ thống
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
    "trust_score": 25,
    "result": {
      "trust_score": 25,
      "risk_level": "DANGEROUS (PHISHING CAO)",
      "details": {
        "domain": "paypal-security-update-fake.com",
        "uses_https": false,
        "suspicious_keywords": ["paypal", "security", "update"],
        "redirection_count": 0
      },
      "scanned_at": 1792123838
    }
  }
  ```

### 4.3. Xuất Báo cáo PDF Bảo mật (GET `/scan/{job_id}?export=pdf`)
* **Response:**
  ```json
  {
    "job_id": "e786a5b8-fcec-4f4b-beb4-e53c3eb1f68e",
    "status": "COMPLETED",
    "download_url": "https://phishing-reports-logs-....s3.amazonaws.com/reports/.../phishing_report.pdf?X-Amz-Expires=900"
  }
  ```

---

## 5. Quy tắc Đánh giá & Chấm điểm (Scoring Engine)

Hệ thống áp dụng thang điểm từ **0 đến 100** (khởi điểm 100 điểm - an toàn tuyệt đối):

* **Thang phân loại rủi ro:**
  * **$\ge 80$ điểm:** `SAFE (AN TOÀN)` - Không phát hiện dấu hiệu bất thường.
  * **$50 - 79$ điểm:** `SUSPICIOUS (CẢNH BÁO / ĐÁNG NGỜ)` - Có dấu hiệu rủi ro tiềm ẩn.
  * **$< 50$ điểm:** `DANGEROUS (NGUY HIỂM / PHISHING)` - Phát hiện hành vi lừa đảo hoặc mã độc rõ rệt.

* **Tiêu chí trừ điểm:**
  * **Link:** Không dùng HTTPS (-15), dùng IP thay vì domain (-35), TLD rủi ro cao (-20), chứa từ khóa giả mạo nhạy cảm (-20/từ), tên miền nhiều dấu gạch ngang (-15), phát hiện chuỗi chuyển hướng ẩn (-15).
  * **Email:** Thất bại kiểm thực SPF/DKIM (-30), vi phạm DMARC (-20), cụm từ hối thúc khẩn cấp (-20/cụm), đòi hỏi mật khẩu/OTP/thẻ ngân hàng (-25).
  * **File:** Double Extension (-45), Magic Bytes không khớp với đuôi file (-45), khớp chữ ký mã độc YARA tĩnh (-25/chữ ký), Shannon Entropy $> 7.5$ (-35), ClamAV phát hiện virus (về thẳng 0 điểm).

---

## 6. Hướng dẫn Khởi chạy Nhanh (Quick Start)

### 6.1. Chạy giao diện Web cục bộ (Frontend)
1. Đảm bảo máy tính đã cài đặt Python 3.
2. Mở terminal tại thư mục chứa file `index.html` và chạy:
   ```bash
   python -m http.server 8000
   ```
3. Truy cập vào trình duyệt: `http://localhost:8000/index.html`.

### 6.2. Kiểm thử bằng lệnh cURL / PowerShell
* **Gửi quét một đường link:**
  ```powershell
  $job = Invoke-RestMethod -Uri "https://kp3je8ijff.execute-api.ap-southeast-1.amazonaws.com/scan" -Method Post -ContentType "application/json" -Body '{"type": "link", "payload": "http://paypal-security-update-fake.com"}'
  $job
  ```
* **Kiểm tra kết quả sau 3 giây:**
  ```powershell
  Invoke-RestMethod -Uri "https://kp3je8ijff.execute-api.ap-southeast-1.amazonaws.com/scan/$($job.job_id)"
  ```
* **Lấy link tải báo cáo PDF:**
  ```powershell
  $pdf = Invoke-RestMethod -Uri "https://kp3je8ijff.execute-api.ap-southeast-1.amazonaws.com/scan/$($job.job_id)?export=pdf"
  Start-Process $pdf.download_url
  ```

---

## 7. Giấy phép & Đóng góp (License)

Dự án được phát triển phục vụ mục đích nghiên cứu học thuật, đồ án an toàn thông tin và ứng dụng điện toán đám mây. Mọi thành viên trong nhóm có toàn quyền kế thừa, mở rộng và triển khai phi thương mại.
