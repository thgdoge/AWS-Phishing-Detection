

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function messageFor(status) {
  if (status === 400) return "Nội dung không hợp lệ. Vui lòng kiểm tra lại.";
  if (status === 404) return "Không tìm thấy phiên kiểm tra. Vui lòng thử lại.";
  if (status === 429) return "Bạn gửi quá nhanh. Vui lòng thử lại sau ít phút.";
  if (status >= 500) return "Máy chủ đang gặp sự cố. Vui lòng thử lại sau.";
  return "Có lỗi xảy ra (mã " + status + "). Vui lòng thử lại.";
}

async function request(path, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(CONFIG.API_BASE + path, { ...options, signal: controller.signal });
    let data = null;
    try { data = await res.json(); } catch (_) { /* phản hồi không phải JSON */ }
    if (!res.ok) throw new ApiError(messageFor(res.status), res.status);
    return data;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err.name === "AbortError") throw new ApiError("Máy chủ phản hồi quá chậm. Vui lòng thử lại.");
    throw new ApiError("Không kết nối được máy chủ. Kiểm tra mạng rồi thử lại.");
  } finally {
    clearTimeout(timer);
  }
}


function submitScan(type, payload) {
  return request("/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type, payload }),
  });
}

function getScan(jobId) {
  return request("/scan/" + encodeURIComponent(jobId));
}


async function uploadToS3(uploadUrl, file) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60000);
  try {
    const res = await fetch(uploadUrl, { method: "PUT", body: file, signal: controller.signal });
    if (!res.ok) throw new ApiError("Tải tệp lên thất bại. Vui lòng thử lại.");
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError("Tải tệp lên thất bại. Vui lòng thử lại.");
  } finally {
    clearTimeout(timer);
  }
}

/* Hỏi kết quả theo chu kỳ, có giới hạn số lần. */
async function waitForResult(jobId, type) {
  const maxAttempts = CONFIG.POLL_MAX_ATTEMPTS[type] || 30;
  for (let i = 0; i < maxAttempts; i++) {
    await sleep(CONFIG.POLL_INTERVAL_MS);
    const data = await getScan(jobId);
    if (data && data.status === "COMPLETED") return data;
  }
  throw new ApiError("Quá thời gian chờ. Vui lòng thử lại sau ít phút.");
}