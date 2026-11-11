

const $ = (id) => document.getElementById(id);

const LEVELS = {
  safe:    { icon: "✓", label: "An toàn",             title: "Chưa thấy dấu hiệu lừa đảo",
             sum: "Các kiểm tra hiện có không phát hiện dấu hiệu bất thường.",
             advice: () => "Hãy luôn cẩn thận với mọi yêu cầu nhập mật khẩu hoặc mã OTP bất ngờ." },
  warn:    { icon: "!", label: "Đáng ngờ",            title: "Có vài dấu hiệu cần cẩn thận",
             sum: "Có một số dấu hiệu thường gặp ở nội dung lừa đảo, nhưng chưa đủ để kết luận chắc chắn.",
             advice: () => "Đừng nhập thông tin cá nhân. Hãy xác minh với nguồn chính thức bằng cách tự gõ địa chỉ của họ." },
  danger:  { icon: "✕", label: "Nguy hiểm",           title: "Nhiều khả năng là lừa đảo hoặc độc hại",
             sum: "Có nhiều dấu hiệu lừa đảo hoặc độc hại rõ ràng.",
             advice: (noun) => "Không mở " + noun + " và không trả lời. Nếu đã nhập thông tin, hãy đổi mật khẩu ngay." },
  unknown: { icon: "?", label: "Chưa kiểm tra được",  title: "Chưa có đủ dữ liệu để kết luận",
             sum: "Hệ thống chưa lấy được kết quả. Điều này không có nghĩa là nội dung an toàn.",
             advice: () => "Hãy thử lại sau ít phút. Trong lúc chờ, đừng mở nội dung đó." },
};
const NOUN = { link: "link", email: "email", file: "tệp" };

function levelOf(score) {
  if (score >= 80) return "safe";
  if (score >= 50) return "warn";
  return "danger";
}


function vtReasons(vt, out) {
  if (!vt) return;
  const bad = Number(vt.malicious) || 0;
  const sus = Number(vt.suspicious) || 0;
  if (bad > 0) out.push("Có " + bad + " công cụ bảo mật báo độc hại");
  else if (sus > 0) out.push("Có " + sus + " công cụ bảo mật báo đáng ngờ");
}

function deriveReasons(type, d) {
  const out = [];
  if (type === "link") {
    if (d.uses_https === false) out.push("Không dùng kết nối bảo mật (HTTPS)");
    if (d.is_ip_address) out.push("Dùng địa chỉ IP thay cho tên miền");
    if (d.suspicious_tld) out.push("Đuôi tên miền hay bị lạm dụng");
    if (Array.isArray(d.suspicious_keywords) && d.suspicious_keywords.length) {
      out.push("Chứa từ khóa nhạy cảm: " + d.suspicious_keywords.join(", "));
    }
    vtReasons(d.virustotal_report, out);
  } else if (type === "email") {
    if ((Number(d.max_malicious_detections) || 0) > 0) out.push("Có link trong email bị công cụ bảo mật báo độc hại");
    else if ((Number(d.max_suspicious_detections) || 0) > 0) out.push("Có link trong email bị báo đáng ngờ");
    if (d.spf_fail_detected || d.dkim_fail_detected) out.push("Email không vượt qua kiểm tra người gửi (SPF/DKIM)");
    if (d.dmarc_fail_detected) out.push("Email vi phạm chính sách xác thực (DMARC)");
    if (Array.isArray(d.urgent_phrases_found) && d.urgent_phrases_found.length) {
      out.push("Có cụm từ gây áp lực: " + d.urgent_phrases_found.slice(0, 3).join(", "));
    }
    if (d.asks_sensitive_credentials) out.push("Yêu cầu thông tin nhạy cảm (mật khẩu, OTP, thẻ)");
  } else if (type === "file") {
    if (Array.isArray(d.suspicious_flags)) d.suspicious_flags.slice(0, 4).forEach((f) => out.push(String(f)));
    if (d.clamav_scan === "INFECTED") out.push("Trình quét virus phát hiện mã độc");
    vtReasons(d.virustotal_report, out);
  }
  return out;
}


function techRows(type, d, errorText) {
  const rows = [];
  const add = (k, v) => { if (v !== undefined && v !== null && v !== "") rows.push(k.padEnd(12) + v); };
  if (errorText) add("error", String(errorText).slice(0, 120));
  if (type === "link") {
    add("domain", d.domain);
    add("https", d.uses_https === undefined ? undefined : (d.uses_https ? "có" : "không"));
    add("keywords", Array.isArray(d.suspicious_keywords) && d.suspicious_keywords.length ? d.suspicious_keywords.join(", ") : undefined);
    if (d.virustotal_report) add("virustotal", (d.virustotal_report.status || "") + " malicious=" + (d.virustotal_report.malicious ?? 0));
  } else if (type === "email") {
    add("urls", d.extracted_urls_count);
        add("urgent", Array.isArray(d.urgent_phrases_found) ? d.urgent_phrases_found.length : undefined);
    add("credentials", d.asks_sensitive_credentials === undefined ? undefined : (d.asks_sensitive_credentials ? "yêu cầu" : "không"));
    add("vt_malicious", d.max_malicious_detections);
    add("spf/dkim", (d.spf_fail_detected || d.dkim_fail_detected) ? "fail" : undefined);
  } else if (type === "file") {
    add("filename", d.filename);
    add("size", d.file_size_bytes !== undefined ? d.file_size_bytes + " bytes" : undefined);
    add("format", d.detected_format);
    add("sha256", d.sha256);
    add("entropy", d.shannon_entropy);
    add("clamav", d.clamav_scan);
  }
  return rows;
}


function paint(vm) {
  const L = LEVELS[vm.level];
  const result = $("result");
  result.hidden = false;
  result.className = "card result level--" + (vm.scanning ? "scan" : vm.level) + (vm.scanning ? " is-scanning" : "");
  $("badge-icon").textContent = vm.scanning ? "…" : L.icon;
  $("badge-label").textContent = vm.scanning ? "Đang quét" : L.label;
  $("code").textContent = vm.code ? "Mã kiểm tra " + vm.code : "";
  $("score").textContent = vm.score === null ? "?" : String(vm.score);
  $("score-max").hidden = vm.score === null;
  $("ring").style.setProperty("--p", vm.score === null ? 0 : vm.score / 100);
  $("title").textContent = vm.title;
  $("sum").textContent = vm.sum;
  $("reasons-title").textContent = vm.scanning ? "Đang thực hiện" : "Vì sao có kết luận này";
  $("advice-text").textContent = vm.advice;
  const ul = $("reasons");
  ul.replaceChildren();
  vm.reasons.forEach((text) => {
    const li = document.createElement("li");
    li.textContent = text;
    ul.appendChild(li);
  });
  $("term").textContent = ["$ trustcheck --scan", ...vm.tech].join("\n");
  $("tech").hidden = vm.scanning;
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  result.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "nearest" });
}

function renderScanning() {
  paint({
    scanning: true, level: "unknown", score: null, code: "",
    title: "Đang phân tích…", sum: "Thường mất vài giây. Bạn có thể giữ nguyên trang này.",
    reasons: ["Kiểm tra cấu trúc nội dung", "Đối chiếu nguồn dữ liệu bảo mật", "Tổng hợp kết luận"],
    advice: "", tech: [],
  });
}

function renderUnknown(message, code) {
  const L = LEVELS.unknown;
  paint({
    scanning: false, level: "unknown", score: null, code: code || "",
    title: L.title, sum: L.sum, reasons: [message], advice: L.advice(), tech: [],
  });
}


function renderResult(data, type, jobId) {
  const r = data.result || {};
  const d = r.details || {};
  const code = jobId ? "#" + String(jobId).slice(0, 8).toUpperCase() : "";
  const score = Number(data.trust_score ?? r.trust_score);
  const failed = String(r.risk_level || "").startsWith("SCAN ERROR") || !Number.isFinite(score);

  if (failed) {
    const L = LEVELS.unknown;
    paint({
      scanning: false, level: "unknown", score: null, code,
      title: L.title, sum: L.sum, reasons: ["Quá trình phân tích gặp lỗi."],
      advice: L.advice(), tech: techRows(type, d, d.error),
    });
    return;
  }

  const level = levelOf(score);
  const L = LEVELS[level];
  let reasons = Array.isArray(r.reasons) && r.reasons.length ? r.reasons.map(String) : deriveReasons(type, d);
  if (!reasons.length) reasons = ["Không phát hiện dấu hiệu bất thường"];
  paint({
    scanning: false, level, score: Math.round(score), code,
    title: L.title, sum: L.sum, reasons, advice: L.advice(NOUN[type] || "nội dung"),
    tech: techRows(type, d),
  });
}


function showFormError(message) {
  const el = $("form-error");
  el.textContent = message;
  el.hidden = false;
}
function clearFormError() { $("form-error").hidden = true; }

function setBusy(busy) {
  document.querySelectorAll("[data-submit]").forEach((b) => { b.disabled = busy; });
  $("scan-form").setAttribute("aria-busy", String(busy));
}