/* Cấu hình chung. Chỉ đặt thông tin CÔNG KHAI ở đây.
   Tuyệt đối không đặt khóa AWS, API key hay mật khẩu vào file này. */
const CONFIG = {
  // Địa chỉ API Gateway của nhóm (đổi nếu nhóm dựng API mới)
  API_BASE: "https://kp3je8ijff.execute-api.ap-southeast-1.amazonaws.com",

  POLL_INTERVAL_MS: 2000,                                // hỏi kết quả mỗi 2 giây
  POLL_MAX_ATTEMPTS: { link: 30, email: 30, file: 45 }, // số lần hỏi tối đa trước khi bỏ cuộc

  MAX_FILE_MB: 10,
  MAX_URL_CHARS: 2048,
  MAX_EMAIL_CHARS: 20000,
};