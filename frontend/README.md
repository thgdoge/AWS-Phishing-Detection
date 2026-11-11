# Trust Check - Frontend

Giao diện web để kiểm tra link, email và file đáng ngờ. Trang tĩnh (HTML, CSS, JavaScript thuần), gọi API quét của nhóm qua API Gateway.

## Chạy trên máy

1. Mở thư mục dự án bằng VS Code, cài extension **Live Server**.
2. Chuột phải `frontend/index.html`, chọn **Open with Live Server**.
3. Dán một link hoặc email vào ô nhập rồi bấm **Kiểm tra**.

Không cần cài thêm gì và không cần mạng riêng, nhưng cần kết nối tới API của nhóm.

## Cấu trúc

| Đường dẫn | Vai trò |
|---|---|
| `index.html` | Bố cục trang và các biểu mẫu |
| `css/style.css` | Toàn bộ giao diện (màu, chữ, thẻ, khung kết quả) |
| `js/config.js` | Cấu hình công khai: địa chỉ API, giới hạn dung lượng, số lần chờ |
| `js/api.js` | Mọi lệnh gọi mạng: gửi yêu cầu quét, hỏi kết quả, tải file lên S3 |
| `js/ui.js` | Dịch kết quả của máy chủ sang giao diện tiếng Việt |
| `js/main.js` | Chuyển tab, kiểm tra đầu vào, điều phối luồng quét |

## Luồng hoạt động

1. Người dùng nhập link, email hoặc chọn file.
2. `main.js` kiểm tra đầu vào rồi gọi `submitScan` trong `api.js` (POST `/scan`).
3. Với file: tải thẳng lên S3 bằng địa chỉ tạm do máy chủ cấp.
4. `waitForResult` hỏi `GET /scan/{job_id}` mỗi 2 giây cho đến khi xong hoặc hết thời gian.
5. `ui.js` hiển thị mức rủi ro, điểm, lý do và lời khuyên.

## Đổi địa chỉ API

Sửa `API_BASE` trong `js/config.js`.

## Quy tắc bảo mật

- Nội dung do người dùng nhập và dữ liệu từ máy chủ chỉ được đưa vào trang bằng `textContent`, không dùng `innerHTML`.
- Không đặt khóa AWS, API key hay mật khẩu vào bất kỳ file nào trong `frontend/`. Mọi file ở đây ai cũng xem được.
- Kiểm tra đầu vào ở trình duyệt chỉ để báo lỗi sớm; backend vẫn phải kiểm tra lại.

## Việc chưa làm

- Đăng nhập, trang Lịch sử, trang quản trị: chờ backend và cấu hình Cognito.
- Triển khai lên S3 và cấu hình CORS: làm cùng người phụ trách hạ tầng.