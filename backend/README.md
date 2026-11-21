# Backend: Detect Worker & Scoring Engine

Tài liệu cho hai khối **Detect Worker** (Link / Email / File) và **Scoring Engine**.
`ingest_lambda.py` và `status_lambda.py` không thuộc phạm vi tài liệu này.

```text
SQS message ──► pipeline.process_event ──► detector ──► Scoring Engine ──► DynamoDB + S3 log
                (common/pipeline.py)       (detectors/)   (common/scoring.py)
```

## Cấu trúc mã

```text
backend/
├── fast_detect_worker.py      # Lambda handler: Link + Email  (phishing-fast-queue)
├── file_detect_worker.py      # Lambda handler: File          (phishing-file-queue)
├── common/
│   ├── scoring.py             # SCORING ENGINE: bảng luật RULES, tính điểm, lý do, confidence
│   ├── pipeline.py            # đọc SQS, idempotency, xử lý lỗi, lưu kết quả
│   ├── store.py               # DynamoDB / S3 (có chuyển float -> Decimal)
│   ├── net.py                 # ngân sách thời gian, gọi API, theo dõi redirect an toàn (chống SSRF)
│   ├── api_keys.py            # lấy API key: biến môi trường trước, rồi SSM Parameter Store
│   ├── reputation.py          # VirusTotal, Safe Browsing, URLhaus, MalwareBazaar, RDAP
│   └── textnorm.py            # bỏ dấu tiếng Việt, so khớp theo ranh giới từ
├── detectors/
│   ├── link.py                # URL: cấu trúc, WHOIS(RDAP), blacklist, redirect chain, trang đích
│   ├── email_msg.py           # Email: header SPF/DKIM/DMARC, giả mạo người gửi, NLP luật, URL, đính kèm
│   ├── file.py                # File: hash, magic bytes, YARA-lite, Office/PDF/ZIP/HTML, entropy, ClamAV
│   ├── domains.py             # registrable domain, danh sách brand, allowlist, TLD rủi ro
│   └── base.py                # kiểu Analysis mà detector trả về
├── tests/                     # 113 unit test, không cần mạng/AWS
├── scan_local.py              # quét thử link/email/file ngay trên máy
├── samples/                   # email mẫu để thử
└── build_zip.py               # đóng gói dist/detect-workers.zip
```

## Nguyên tắc của Scoring Engine

* **Detector chỉ phát hiện, Engine mới quyết định điểm.** Detector trả về `Finding(code, value, detail)`;
  mọi trọng số, lý do và mức trần nằm ở một chỗ: bảng `RULES` trong `common/scoring.py`.
  Muốn chỉnh độ nhạy chỉ cần sửa số ở đó.
* **Không cộng trùng.** Mỗi `code` chỉ tính một lần, và mỗi nhóm có mức trừ tối đa (`CATEGORY_CAPS`).
* **Trần điểm cho tín hiệu nghiêm trọng.** Ví dụ ClamAV/MalwareBazaar => 0, Safe Browsing/URLhaus => ≤ 20.
* **Giải thích được.** Kết quả có `reasons` (tiếng Việt, frontend hiển thị sẵn) và `signals`
  (từng điểm trừ kèm nhóm), nên người dùng thấy *vì sao* điểm thấp.
* **Không biến "không hỏi được" thành "sạch".** `confidence` = `HIGH` (≥2 nguồn uy tín trả lời),
  `MEDIUM` (1 nguồn, hoặc email chỉ có chữ), `LOW` (0 nguồn; kết quả chỉ dựa phân tích kỹ thuật).
  Kết quả `LOW` có thêm một dòng cảnh báo trong `reasons` và **không** được ghi cache.
* Thang điểm: `≥ 80` SAFE · `50–79` SUSPICIOUS · `< 50` DANGEROUS. Quét lỗi => `risk_level = "SCAN ERROR"`.

### Bảng luật hiện tại (sinh tự động từ `RULES`)

**Uy tín bên ngoài** (`reputation`, trừ tối đa **100** điểm)

| Mã | Điểm trừ | Trần điểm cuối | Lý do hiển thị |
|---|---|---|---|
| `VT_MALICIOUS` | ≥5: -85 / ≥2: -60 / ≥1: -35 |  | N công cụ bảo mật (VirusTotal) báo link độc hại |
| `VT_SUSPICIOUS` | -15/đơn vị (tối đa -30) |  | N công cụ bảo mật (VirusTotal) báo đáng ngờ |
| `GSB_MATCH` | -80 | ≤ 20 | Google Safe Browsing xếp vào danh sách nguy hiểm (…) |
| `URLHAUS_LISTED` | -80 | ≤ 20 | URLhaus ghi nhận link đang phát tán mã độc (…) |
| `FILE_VT_MALICIOUS` | ≥5: -100 / ≥2: -70 / ≥1: -40 | khi ≥5: ≤ 0 | N công cụ diệt virus (VirusTotal) phát hiện mã độc |
| `FILE_VT_SUSPICIOUS` | -15/đơn vị (tối đa -30) |  | N công cụ diệt virus báo tệp đáng ngờ |
| `MALWAREBAZAAR_HIT` | -100 | ≤ 0 | Mã băm tệp có trong cơ sở dữ liệu mã độc MalwareBazaar (…) |
| `CLAMAV_INFECTED` | -100 | ≤ 0 | ClamAV phát hiện mã độc (…) |

**Cấu trúc URL** (`url`, trừ tối đa **55** điểm)

| Mã | Điểm trừ | Trần điểm cuối | Lý do hiển thị |
|---|---|---|---|
| `NO_HTTPS` | -10 |  | Không dùng kết nối bảo mật (HTTPS) |
| `IP_HOST` | -30 |  | Dùng địa chỉ IP thay cho tên miền |
| `SUSPICIOUS_TLD` | -15 |  | Đuôi tên miền hay bị lạm dụng (…) |
| `URL_KEYWORDS` | -8/đơn vị (tối đa -24) |  | Chứa từ khóa nhạy cảm: … |
| `BRAND_IMPERSONATION` | -30 |  | Tên miền chứa tên "…" nhưng không phải trang chính thức |
| `PUNYCODE_IDN` | -20 |  | Tên miền dùng ký tự quốc tế dễ gây nhầm lẫn (…) |
| `USERINFO_AT` | -25 |  | Link chứa ký tự "@" để đánh lừa tên miền thật |
| `MANY_HYPHENS` | -12 |  | Tên miền có quá nhiều dấu gạch ngang |
| `MANY_SUBDOMAINS` | -10 |  | Tên miền có quá nhiều tầng tên miền con |
| `URL_SHORTENER` | -10 |  | Link rút gọn che giấu địa chỉ thật (…) |
| `NONSTANDARD_PORT` | -8 |  | Link dùng cổng kết nối bất thường (:…) |
| `FREE_HOSTING` | -8 |  | Trang nằm trên dịch vụ lưu trữ miễn phí (…) |

**Tên miền / redirect / trang đích** (`domain`, trừ tối đa **40** điểm)

| Mã | Điểm trừ | Trần điểm cuối | Lý do hiển thị |
|---|---|---|---|
| `DOMAIN_NEW` | ≤7: -35 / ≤30: -25 / ≤90: -10 |  | Tên miền mới đăng ký cách đây N ngày |
| `REDIRECT_CHAIN` | ≥4: -20 / ≥3: -15 / ≥2: -8 |  | Link chuyển hướng qua N bước |
| `REDIRECT_CROSS_DOMAIN` | -12 |  | Link chuyển hướng sang tên miền khác (…) |
| `SSL_INVALID` | -15 |  | Chứng chỉ bảo mật (SSL) không hợp lệ |
| `LANDING_PASSWORD_FORM` | -15 |  | Trang đích có ô nhập mật khẩu |
| `FORM_ACTION_EXTERNAL` | -15 |  | Biểu mẫu trên trang gửi dữ liệu sang tên miền khác (…) |

**Người gửi email** (`sender`, trừ tối đa **45** điểm)

| Mã | Điểm trừ | Trần điểm cuối | Lý do hiển thị |
|---|---|---|---|
| `SPF_FAIL` | -15 |  | Email không vượt qua kiểm tra SPF |
| `SPF_SOFTFAIL` | -8 |  | Email bị đánh dấu SPF softfail |
| `DKIM_FAIL` | -15 |  | Email không vượt qua kiểm tra chữ ký DKIM |
| `DMARC_FAIL` | -20 |  | Email vi phạm chính sách xác thực DMARC |
| `REPLYTO_MISMATCH` | -15 |  | Địa chỉ trả lời khác tên miền người gửi (…) |
| `RETURNPATH_MISMATCH` | -10 |  | Return-Path khác tên miền người gửi (…) |
| `DISPLAY_NAME_SPOOF` | -20 |  | Tên hiển thị giả danh nơi khác (…) |
| `SENDER_BRAND_MISMATCH` | -25 |  | Tên miền người gửi giả mạo thương hiệu "…" |

**Nội dung email** (`content`, trừ tối đa **60** điểm)

| Mã | Điểm trừ | Trần điểm cuối | Lý do hiển thị |
|---|---|---|---|
| `URGENT_PHRASES` | -10/đơn vị (tối đa -30) |  | Có cụm từ gây áp lực, hối thúc: … |
| `CREDENTIAL_REQUEST` | -25 |  | Yêu cầu cung cấp thông tin nhạy cảm (mật khẩu, OTP, thẻ) |
| `LURE_PHRASES` | -15 |  | Có cụm từ dụ dỗ trúng thưởng/hoàn tiền: … |
| `LINK_TEXT_MISMATCH` | -25 |  | Văn bản link hiển thị tên miền khác với địa chỉ thật (…) |

**Link trong email** (`links`, trừ tối đa **70** điểm)

| Mã | Điểm trừ | Trần điểm cuối | Lý do hiển thị |
|---|---|---|---|
| `EMAIL_LINK_RISK` | -0.7/đơn vị (tối đa -70) |  | Link trong email có độ tin cậy thấp (…) |

**Tệp đính kèm email** (`attachment`, trừ tối đa **90** điểm)

| Mã | Điểm trừ | Trần điểm cuối | Lý do hiển thị |
|---|---|---|---|
| `EMAIL_ATTACHMENT_RISK` | -0.9/đơn vị (tối đa -90) |  | Tệp đính kèm có độ tin cậy thấp (…) |

**Phân tích tĩnh tệp** (`file`, trừ tối đa **80** điểm)

| Mã | Điểm trừ | Trần điểm cuối | Lý do hiển thị |
|---|---|---|---|
| `HIGH_RISK_EXT` | -25 |  | Đuôi tệp thực thi/script rủi ro cao (…) |
| `DOUBLE_EXTENSION` | -45 |  | Tên tệp có đuôi kép giả mạo (…) |
| `RLO_FILENAME` | -45 |  | Tên tệp chứa ký tự đảo chiều để che đuôi thật |
| `EXEC_DISGUISED` | -45 |  | Tệp mang đuôi … nhưng thực chất là chương trình thực thi |
| `MAGIC_MISMATCH` | -25 |  | Nội dung tệp không khớp với đuôi tệp (…) |
| `YARA_MATCH` | -20/đơn vị (tối đa -50) |  | Khớp N mẫu chữ ký mã độc: … |
| `OFFICE_MACRO` | -25 |  | Tệp Office chứa macro VBA |
| `OFFICE_REMOTE_TEMPLATE` | -30 |  | Tệp Office tải mẫu/đối tượng từ máy chủ bên ngoài |
| `PDF_ACTIVE_CONTENT` | -25 |  | Tệp PDF chứa mã chủ động (…) |
| `ARCHIVE_CONTAINS_EXECUTABLE` | -30 |  | Tệp nén chứa chương trình thực thi (…) |
| `ARCHIVE_ENCRYPTED` | -15 |  | Tệp nén đặt mật khẩu nên không thể quét nội dung |
| `HTML_CREDENTIAL_FORM` | -35 |  | Tệp HTML có biểu mẫu thu thập mật khẩu |
| `HIGH_ENTROPY` | -35 |  | Entropy rất cao (…/8.0), dấu hiệu tệp bị nén/mã hóa (packed) |

## Cấu hình Lambda

| | FastDetectWorker | FileDetectWorker |
|---|---|---|
| Handler | `fast_detect_worker.lambda_handler` | `file_detect_worker.lambda_handler` |
| Runtime | Python 3.12 (x86_64 hoặc arm64, thuần Python) | giống nhau |
| Gói mã | `dist/detect-workers.zip` (cùng một file) | giống nhau |
| Timeout gợi ý | 45 s (frontend chờ tối đa ~60 s) | 90 s (frontend chờ tối đa ~90 s) |
| Memory | 512 MB | 1024 MB, ephemeral storage ≥ 1024 MB |
| SQS | Batch size **1**, visibility timeout ≥ 6 × timeout | giống nhau |

Worker tự đọc `context.get_remaining_time_in_millis()` và chừa 6 giây để ghi kết quả,
nên đổi timeout Lambda không cần sửa code.

**Quyền IAM tối thiểu:** SQS `ReceiveMessage/DeleteMessage/GetQueueAttributes`; DynamoDB `GetItem/UpdateItem/PutItem`
trên bảng jobs và cache; S3 `GetObject` + `s3:ListBucket` (để `HeadObject` trả 404 thay vì 403) trên `RAW_BUCKET`;
S3 `PutObject` trên `REPORTS_BUCKET`.

### Biến môi trường

| Biến | Dùng cho | Ghi chú |
|---|---|---|
| `JOBS_TABLE`, `CACHE_TABLE`, `REPORTS_BUCKET` | cả hai | như cũ |
| `SSM_PREFIX` | cả hai | (tùy chọn) ví dụ `/phishing`: đọc key từ SSM Parameter Store, xem mục bên dưới |
| `VT_API_KEY`, `VT_BACKUP_API_KEYS` | VirusTotal | free: 4 request/phút, 500/ngày |
| `GSB_API_KEY` | Google Safe Browsing (Lookup v4) | free ~10.000 truy vấn/ngày |
| `ABUSECH_AUTH_KEY` | URLhaus + MalwareBazaar | **bắt buộc** từ khi abuse.ch yêu cầu Auth-Key (đăng ký miễn phí ở auth.abuse.ch) |
| `VT_UPLOAD_UNKNOWN_FILES` | file | `true` (mặc định) sẽ upload tệp chưa có trên VT. **Tệp của người dùng sẽ trở nên truy cập được với khách hàng VT**; đặt `false` nếu lo ngại riêng tư |
| `VT_POLL_MAX_WAIT`, `VT_POLL_INTERVAL` | VirusTotal | giây chờ kết quả quét mới (mặc định 12 / 4) |
| `MAX_FILE_BYTES`, `S3_WAIT_SECONDS` | file | mặc định 32 MB / 30 s |

Thiếu key nào thì nguồn đó được ghi `NO_API_KEY`, **không** tính là "sạch" và làm `confidence` giảm.
VT free rất chặt: nên đặt *reserved concurrency* 1–2 cho worker và dùng `VT_BACKUP_API_KEYS`.

## Cất API key ở SSM Parameter Store (tùy chọn)

Code lấy key theo thứ tự: **biến môi trường -> SSM -> bỏ qua nguồn đó** (`common/api_keys.py`).
Muốn dùng SSM, đặt biến `SSM_PREFIX=/phishing` cho hai worker và xóa các biến chứa key cũ
(biến môi trường luôn được ưu tiên). Tạo parameter kiểu **SecureString**:

| Parameter | Worker cần |
|---|---|
| `/phishing/VT_API_KEY` | Fast + File |
| `/phishing/VT_BACKUP_API_KEYS` (tùy chọn, ngăn cách bằng dấu phẩy) | Fast + File |
| `/phishing/GSB_API_KEY` | Fast |
| `/phishing/ABUSECH_AUTH_KEY` | Fast + File |

Role IAM của worker cần quyền:
```json
{"Effect": "Allow", "Action": "ssm:GetParameter",
 "Resource": "arn:aws:ssm:<region>:<account-id>:parameter/phishing/*"}
```
(Nếu dùng khóa KMS tự tạo thì thêm `kms:Decrypt`.) Key được nhớ suốt vòng đời container nên chỉ đọc SSM một lần
mỗi lần khởi động lạnh; đổi key trên SSM có hiệu lực khi container mới được tạo. Lỗi SSM không làm hỏng job:
nguồn đó bị bỏ qua, `confidence` giảm và log ghi `[api_keys] không đọc được <tên>: <mã lỗi>`.

## Chạy thử trên máy (không cần AWS)

```bash
cd backend
python scan_local.py link  "http://paypal-security-update-fake.com/login" --offline
python scan_local.py email samples/email_lua_dao.txt --offline
python scan_local.py file  duong/dan/tep.pdf --offline
```
Bỏ `--offline` để tra cứu thật (đặt `VT_API_KEY`, `GSB_API_KEY`, `ABUSECH_AUTH_KEY` trước). Thêm `--json` để xem toàn bộ kết quả.

## Chạy test và đóng gói

```bash
cd backend
python -m unittest discover -s tests -t .      # 113 test, ~1 giây, không cần mạng/AWS
python build_zip.py                            # -> dist/detect-workers.zip
```

## Giới hạn đã biết

* **ClamAV**: runtime Lambda mặc định không có binary `clamscan` nên trạng thái luôn là `SKIPPED`.
  Muốn dùng cần Lambda container image có ClamAV + cơ sở dữ liệu chữ ký.
* **YARA-lite** là bộ luật chuỗi byte tự viết (`YARA_LITE_RULES` trong `detectors/file.py`), chưa phải YARA thật.
  Có thể thay bằng `yara-python` nếu đóng gói được cho Lambda.
* **"NLP"** của email là luật ngôn ngữ song ngữ Anh–Việt, không phải mô hình học máy.
  Hàm `analyze_text` tách riêng để sau này thay bằng Amazon Comprehend hoặc mô hình riêng.
* **RDAP** không phủ mọi TLD (nhiều ccTLD không công khai); khi không có dữ liệu tuổi domain thì **không bị trừ điểm**.
* **Registrable domain** dùng danh sách hậu tố 2 tầng rút gọn, không phải Public Suffix List đầy đủ.
* Allowlist tên miền uy tín chỉ bỏ qua heuristic từ khóa/brand, **không** bỏ qua VirusTotal/Safe Browsing. Các dịch vụ cho
  đăng nội dung tự do (Google Sites, github.io...) không được coi là uy tín.
* RAR/7z chưa được mở ra kiểm tra; PDF bị làm rối tên đối tượng (`#4A#53`) có thể lọt.
* Chống SSRF: chặn IP nội bộ, chỉ cổng 80/443/8080/8443, nối thẳng tới IP đã kiểm tra (chống DNS rebinding).
