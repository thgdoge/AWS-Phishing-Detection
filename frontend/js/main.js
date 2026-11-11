/* Điều phối: chuyển tab, kiểm tra đầu vào, gửi yêu cầu, hiển thị kết quả. */

const state = { tab: "link", busy: false };

/* ---- Chuyển tab ---- */
document.querySelectorAll(".seg__btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    state.tab = btn.dataset.tab;
    document.querySelectorAll(".seg__btn").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
    ["link", "email", "file"].forEach((k) => { $("p-" + k).hidden = k !== state.tab; });
    clearFormError();
  });
});

/* ---- Hiện tên tệp đã chọn ---- */
$("file").addEventListener("change", () => {
  const file = $("file").files[0];
  const label = $("file-name");
  label.hidden = !file;
  label.textContent = file ? file.name : "";
  clearFormError();
});

/* ---- Đọc và kiểm tra đầu vào (kiểm tra ở trình duyệt chỉ để báo lỗi sớm,
        backend vẫn phải kiểm tra lại) ---- */
function readInput() {
  if (state.tab === "link") {
    const value = $("link").value.trim();
    if (!value) return { error: "Hãy nhập một đường link." };
    if (/\s/.test(value)) return { error: "Link không được chứa khoảng trắng." };
    if (value.length > CONFIG.MAX_URL_CHARS) return { error: "Link quá dài (tối đa " + CONFIG.MAX_URL_CHARS + " ký tự)." };
    return { type: "link", payload: value };
  }
  if (state.tab === "email") {
    const value = $("email").value.trim();
    if (!value) return { error: "Hãy dán nội dung email cần kiểm tra." };
    if (value.length > CONFIG.MAX_EMAIL_CHARS) return { error: "Nội dung email quá dài (tối đa " + CONFIG.MAX_EMAIL_CHARS + " ký tự)." };
    return { type: "email", payload: value };
  }
  const file = $("file").files[0];
  if (!file) return { error: "Hãy chọn một tệp." };
  if (file.size === 0) return { error: "Tệp rỗng, không có gì để kiểm tra." };
  if (file.size > CONFIG.MAX_FILE_MB * 1024 * 1024) return { error: "Tệp quá lớn (tối đa " + CONFIG.MAX_FILE_MB + " MB)." };
  return { type: "file", payload: file.name, file };
}

/* ---- Gửi và chờ kết quả ---- */
$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.busy) return;
  clearFormError();

  const input = readInput();
  if (input.error) { showFormError(input.error); return; }

  state.busy = true;
  setBusy(true);
  renderScanning();

  try {
    const res = await submitScan(input.type, input.payload);
    let data;
    if (res && res.status === "COMPLETED" && res.result) {
      data = res;                               // đã có sẵn trong bộ nhớ đệm
    } else {
      if (!res || !res.job_id) throw new ApiError("Không nhận được mã phiên kiểm tra. Vui lòng thử lại.");
      if (input.type === "file") {
        if (!res.upload_url) throw new ApiError("Không nhận được địa chỉ tải tệp lên. Vui lòng thử lại.");
        await uploadToS3(res.upload_url, input.file);
      }
      data = await waitForResult(res.job_id, input.type);
    }
    renderResult(data, input.type, res.job_id);
  } catch (err) {
    renderUnknown(err instanceof ApiError ? err.message : "Có lỗi không mong muốn. Vui lòng thử lại.");
  } finally {
    state.busy = false;
    setBusy(false);
  }
});