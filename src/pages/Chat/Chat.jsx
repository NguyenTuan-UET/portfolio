import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { useLocation, useNavigate } from "react-router-dom"
import chatAvatar from "../../assets/chat-avatar.png"
import offlineArt from "../../assets/chat-offline.webp"
import tiredArt from "../../assets/chat-tired.webp"
import "./Chat.css"

const LAYER_NAME = {
  rate_limiter: "Giới hạn tốc độ",
  input_guardrail: "Guardrail",
  llm_error: "Lỗi mô hình",
  output_guardrail: "Guardrail",
}

// lỗi không phải do guardrail chặn: hiện thẻ minh hoạ thay cho câu trả lời
const STATUS_CARDS = {
  offline: { art: offlineArt, text: "Server mất điện rồi, chưa kết nối được với trợ lý. Bạn thử lại sau nhé." },
  tired: { art: tiredArt, text: "Em mệt quá, cho em nghỉ chút nhé." },
}
// giới hạn tốc độ của server và lỗi phía mô hình (hết quota, 429, không gửi được) đều là "mệt"
const TIRED_LAYERS = new Set(["rate_limiter", "llm_error"])

const CHAT_SUGGESTIONS = [
  "Làm sao tạo mật khẩu mạnh mà dễ nhớ?",
  "Giải thích prompt injection cho người mới",
  "Gợi ý lộ trình học Python 1 tháng",
]

const Icon = ({ children }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    {children}
  </svg>
)
const MinusIcon = () => <Icon><path d="M6 12h12" /></Icon>
const ArrowUpRightIcon = () => <Icon><path d="M7 17 17 7M8 7h9v9" /></Icon>
const ArrowUpIcon = () => <Icon><path d="M12 19V5M6 11l6-6 6 6" /></Icon>
const PaperclipIcon = () => (
  <Icon>
    <path d="m21 11-8.6 8.6a5.5 5.5 0 0 1-7.8-7.8l8.9-8.9a3.7 3.7 0 0 1 5.2 5.2l-8.9 8.9a1.8 1.8 0 0 1-2.6-2.6l8.3-8.3" />
  </Icon>
)

const MAX_IMAGE_SIDE = 1280 // resize trước khi gửi để nhẹ payload, ảnh gốc không rời khỏi trình duyệt
const POPUP_MARGIN = 12
const LAUNCHER_MARGIN = 12

function clampPopupPosition(x, y, popup) {
  return {
    x: Math.min(Math.max(POPUP_MARGIN, x), Math.max(POPUP_MARGIN, window.innerWidth - popup.offsetWidth - POPUP_MARGIN)),
    y: Math.min(Math.max(POPUP_MARGIN, y), Math.max(POPUP_MARGIN, window.innerHeight - popup.offsetHeight - POPUP_MARGIN)),
  }
}

function clampLauncherPosition(x, y, launcher) {
  return {
    x: Math.min(Math.max(LAUNCHER_MARGIN, x), window.innerWidth - launcher.offsetWidth - LAUNCHER_MARGIN),
    y: Math.min(Math.max(LAUNCHER_MARGIN, y), window.innerHeight - launcher.offsetHeight - LAUNCHER_MARGIN),
  }
}

// nén/resize ảnh ngay trên trình duyệt rồi mới đọc base64: ảnh chưa từng chạm ổ đĩa server
function fileToImage(file) {
  return new Promise((resolve, reject) => {
    const img = new Image()
    const reader = new FileReader()
    reader.onerror = () => reject(new Error("read failed"))
    reader.onload = () => {
      img.onerror = () => reject(new Error("decode failed"))
      img.onload = () => {
        const scale = Math.min(1, MAX_IMAGE_SIDE / Math.max(img.width, img.height))
        const canvas = document.createElement("canvas")
        canvas.width = Math.round(img.width * scale)
        canvas.height = Math.round(img.height * scale)
        canvas.getContext("2d").drawImage(img, 0, 0, canvas.width, canvas.height)
        const dataUrl = canvas.toDataURL("image/jpeg", 0.82)
        resolve({ dataUrl, base64: dataUrl.split(",")[1] })
      }
      img.src = reader.result
    }
    reader.readAsDataURL(file)
  })
}

// crypto.randomUUID chỉ có trên localhost / HTTPS; mở qua IP mạng LAN bằng HTTP thì dùng id ngẫu nhiên thường
const newSessionId = () =>
  globalThis.crypto?.randomUUID?.() ?? `s-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`

export default function Chat() {
  const [open, setOpen] = useState(false)
  const [popupPosition, setPopupPosition] = useState(null)
  const [launcherPosition, setLauncherPosition] = useState(null)
  const [draggingLauncher, setDraggingLauncher] = useState(false)
  const launcherRef = useRef(null)
  const popupRef = useRef(null)
  const dragRef = useRef(null)
  const suppressClickRef = useRef(false)
  const location = useLocation()
  const navigate = useNavigate()

  // Keep legacy /chat links useful without retaining a separate chat page.
  useEffect(() => {
    if (!location.state?.openChat) return
    setOpen(true)
    const { openChat, ...rest } = location.state
    navigate(`${location.pathname}${location.search}${location.hash}`, { replace: true, state: rest })
  }, [location, navigate])

  useEffect(() => {
    if (!open) return
    popupRef.current?.querySelector('input[aria-label="Tin nhắn"]')?.focus({ preventScroll: true })
  }, [open])

  useLayoutEffect(() => {
    if (!open || !launcherPosition) return
    const popup = popupRef.current
    const launcher = launcherRef.current
    if (!popup || !launcher) return
    const rect = launcher.getBoundingClientRect()
    const opensToRight = rect.left + rect.width / 2 < window.innerWidth / 2
    const x = opensToRight ? rect.right + POPUP_MARGIN : rect.left - popup.offsetWidth - POPUP_MARGIN
    const y = rect.top + rect.height / 2 - popup.offsetHeight / 2
    setPopupPosition(clampPopupPosition(x, y, popup))
  }, [open, launcherPosition])

  useEffect(() => {
    let resizeFrame
    function keepLauncherOnScreen() {
      cancelAnimationFrame(resizeFrame)
      resizeFrame = requestAnimationFrame(() => {
        const launcher = launcherRef.current
        setLauncherPosition((position) => {
          if (!position || !launcher) return position
          const clamped = clampLauncherPosition(position.x, position.y, launcher)
          const side = position.side || (clamped.x + launcher.offsetWidth / 2 < window.innerWidth / 2 ? "left" : "right")
          return {
            x: side === "left" ? LAUNCHER_MARGIN : window.innerWidth - launcher.offsetWidth - LAUNCHER_MARGIN,
            y: clamped.y,
            side,
          }
        })
      })
    }
    window.addEventListener("resize", keepLauncherOnScreen)
    return () => {
      cancelAnimationFrame(resizeFrame)
      window.removeEventListener("resize", keepLauncherOnScreen)
    }
  }, [])

  function startDraggingLauncher(event) {
    if (event.button !== 0) return
    const launcher = launcherRef.current
    if (!launcher) return
    const rect = launcher.getBoundingClientRect()
    dragRef.current = {
      pointerId: event.pointerId,
      offsetX: event.clientX - rect.left,
      offsetY: event.clientY - rect.top,
      startX: event.clientX,
      startY: event.clientY,
      moved: false,
    }
    event.currentTarget.setPointerCapture(event.pointerId)
    setDraggingLauncher(true)
  }

  function dragLauncher(event) {
    const drag = dragRef.current
    const launcher = launcherRef.current
    if (!drag || !launcher || drag.pointerId !== event.pointerId) return
    if (!drag.moved && Math.hypot(event.clientX - drag.startX, event.clientY - drag.startY) < 4) return
    drag.moved = true
    const position = clampLauncherPosition(event.clientX - drag.offsetX, event.clientY - drag.offsetY, launcher)
    setLauncherPosition({
      ...position,
      side: position.x + launcher.offsetWidth / 2 < window.innerWidth / 2 ? "left" : "right",
    })
  }

  function stopDraggingLauncher(event) {
    const drag = dragRef.current
    const launcher = launcherRef.current
    if (!drag || !launcher || drag.pointerId !== event.pointerId) return
    if (drag.moved && event.type !== "pointercancel") {
      const position = clampLauncherPosition(event.clientX - drag.offsetX, event.clientY - drag.offsetY, launcher)
      const side = position.x + launcher.offsetWidth / 2 < window.innerWidth / 2 ? "left" : "right"
      setLauncherPosition({
        x: side === "left" ? LAUNCHER_MARGIN : window.innerWidth - launcher.offsetWidth - LAUNCHER_MARGIN,
        y: position.y,
        side,
      })
      suppressClickRef.current = true
      window.setTimeout(() => {
        suppressClickRef.current = false
      }, 0)
    }
    dragRef.current = null
    setDraggingLauncher(false)
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId)
    }
  }

  function minimize() {
    setOpen(false)
    launcherRef.current?.focus({ preventScroll: true })
  }

  const [sessionId] = useState(newSessionId)
  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(false)

  async function send(message, image) {
    const msg = message.trim()
    if ((!msg && !image) || loading) return
    const push = (m) => setMessages((prev) => [...prev, m])
    push({ role: "user", text: msg, imageUrl: image?.dataUrl })
    setLoading(true)
    // tin nhắn bot được tạo ở sự kiện đầu tiên rồi cập nhật dần; chỉ có một câu trả lời chạy tại một thời điểm
    let started = false
    const apply = (patch) => {
      const first = !started // đọc ngay lúc gọi, không đọc trong updater vì React có thể chạy updater sau
      started = true
      setMessages((prev) => {
        if (first) return [...prev, { role: "bot", text: "", ...patch({ text: "" }) }]
        const last = prev[prev.length - 1]
        return [...prev.slice(0, -1), { ...last, ...patch(last) }]
      })
    }
    try {
      const res = await fetch("/api/chat/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: sessionId, message: msg, image: image?.base64 }),
      })
      if (!res.ok || !res.body) throw Object.assign(new Error(`HTTP ${res.status}`), { status: res.status })
      // Server-Sent Events: mỗi sự kiện là "data: {json}" và kết thúc bằng một dòng trống
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
      let buffer = ""
      let done = false
      while (!done) {
        const chunk = await reader.read()
        if (chunk.done) break
        buffer += chunk.value
        const events = buffer.split("\n\n")
        buffer = events.pop()
        for (const raw of events) {
          if (!raw.startsWith("data:")) continue
          const event = JSON.parse(raw.slice(5))
          if (event.type === "delta") apply((m) => ({ text: m.text + event.text }))
          else if (event.type === "replace") apply(() => ({ text: event.text }))
          else if (event.type === "done") {
            // câu trả lời cuối đã qua đủ guardrail, luôn ghi đè phần đã stream
            if (TIRED_LAYERS.has(event.layer)) {
              const wait = event.trace?.find((t) => t.layer === "rate_limiter")?.detail?.match(/\d+/)?.[0]
              apply(() => ({ text: "", status: "tired", wait }))
            } else {
              apply(() => ({ text: event.reply, blocked: event.blocked, redacted: event.redacted, layer: event.layer }))
            }
            done = true
          }
        }
      }
      if (!done) throw new Error("stream ended early")
    } catch (error) {
      // phần đã stream (nếu có) vẫn giữ lại, thẻ lỗi hiện ngay bên dưới
      apply(() => ({ status: error.status === 429 ? "tired" : "offline" }))
    } finally {
      setLoading(false)
    }
  }

  return (
    <aside className="chat-widget" aria-label="Trợ lý trò chuyện">
      <section
        id="chat-popup"
        className="chat-popup"
        role="dialog"
        aria-labelledby="chat-title"
        hidden={!open}
        ref={popupRef}
        style={popupPosition ? { left: popupPosition.x, top: popupPosition.y, right: "auto", bottom: "auto" } : undefined}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            event.stopPropagation()
            minimize()
          }
        }}
      >
        <header className="chat-head">
          <img src={chatAvatar} alt="" className="chat-avatar" />
          <h2 id="chat-title">Trợ lý của bạn</h2>
          <button type="button" className="chat-minimize" onClick={minimize} aria-label="Thu nhỏ trò chuyện" title="Thu nhỏ">
            <MinusIcon />
          </button>
        </header>
        <ChatPanel messages={messages} loading={loading} onSend={send} open={open} />
      </section>
      <button
        type="button"
        className={`chat-launcher${draggingLauncher ? " dragging" : ""}`}
        ref={launcherRef}
        style={launcherPosition ? { left: launcherPosition.x, top: launcherPosition.y, right: "auto", bottom: "auto" } : undefined}
        aria-label={open ? "Thu nhỏ trò chuyện" : "Mở trợ lý trò chuyện"}
        aria-expanded={open}
        aria-controls="chat-popup"
        onPointerDown={startDraggingLauncher}
        onPointerMove={dragLauncher}
        onPointerUp={stopDraggingLauncher}
        onPointerCancel={stopDraggingLauncher}
        onClick={() => {
          if (suppressClickRef.current) {
            suppressClickRef.current = false
            return
          }
          open ? minimize() : setOpen(true)
        }}
      >
        <img src={chatAvatar} alt="" draggable="false" />
      </button>
    </aside>
  )
}

function ChatPanel({ messages, loading, onSend, open }) {
  const [input, setInput] = useState("")
  const [image, setImage] = useState(null) // { dataUrl, base64 } — chỉ ở trong state trình duyệt
  const [imageError, setImageError] = useState("")
  const listRef = useRef(null)
  const fileRef = useRef(null)

  useEffect(() => {
    // đang stream thì cuộn tức thì: cuộn mượt theo từng token sẽ giật
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: loading ? "auto" : "smooth" })
  }, [messages, loading, open])

  function submit(msg) {
    if (loading || (!msg.trim() && !image)) return
    onSend(msg, image)
    setInput("")
    setImage(null)
  }

  async function onPickFile(e) {
    const file = e.target.files?.[0]
    e.target.value = ""
    if (!file) return
    if (!file.type.startsWith("image/")) {
      setImageError("Chỉ nhận file ảnh.")
      return
    }
    try {
      setImageError("")
      setImage(await fileToImage(file))
    } catch {
      setImageError("Không đọc được ảnh này, thử ảnh khác nhé.")
    }
  }

  return (
    <div className="chat-panel">
      <ol className="chat-log" ref={listRef} role="log" aria-label="Lịch sử trò chuyện" aria-live="polite" aria-relevant="additions" aria-busy={loading}>
        {messages.length === 0 && (
          <li className="chat-welcome">
            <span className="chat-orb" aria-hidden="true" />
            <p>
              <strong>Chào bạn.</strong>
              Bạn muốn tìm hiểu điều gì?
            </p>
          </li>
        )}
        {messages.map((m, i) => (
          <li key={i} className={`${m.role}${m.blocked ? " blocked" : ""}`}>
            {m.role === "bot" && m.layer && !m.status && (
              <span className="chat-flag">
                {m.blocked ? "BỊ CHẶN" : m.redacted ? "ĐÃ LÀM SẠCH" : "LỖI"} · {LAYER_NAME[m.layer] || m.layer}
              </span>
            )}
            {m.imageUrl && <img className="chat-image" src={m.imageUrl} alt="Ảnh người dùng gửi" />}
            {m.text && (
              <p>
                <RichText text={m.text} />
              </p>
            )}
            {m.status && (
              <figure className="chat-status-card">
                <img src={STATUS_CARDS[m.status].art} alt="" />
                <figcaption>
                  {STATUS_CARDS[m.status].text}
                  {m.wait && <small>Khoảng {m.wait} giây nữa em quay lại.</small>}
                </figcaption>
              </figure>
            )}
          </li>
        ))}
        {loading && messages[messages.length - 1]?.role !== "bot" && (
          <li className="bot">
            <p className="chat-typing">
              <span />
              <span />
              <span />
            </p>
          </li>
        )}
      </ol>

      {messages.length === 0 && (
        <ul className="chat-suggest">
          {CHAT_SUGGESTIONS.map((s) => (
            <li key={s}>
              <button type="button" onClick={() => submit(s)} disabled={loading}>
                {s}
                <ArrowUpRightIcon />
              </button>
            </li>
          ))}
        </ul>
      )}

      {(image || imageError) && (
        <div className="chat-attach">
          {image && (
            <div className="chat-attach-preview">
              <img src={image.dataUrl} alt="Ảnh sẽ gửi" />
              <button type="button" onClick={() => setImage(null)} aria-label="Bỏ ảnh">
                ×
              </button>
            </div>
          )}
          {imageError && <span className="chat-attach-error">{imageError}</span>}
        </div>
      )}

      <form
        className="chat-form"
        onSubmit={(e) => {
          e.preventDefault()
          submit(input)
        }}
      >
        <input type="file" accept="image/*" ref={fileRef} onChange={onPickFile} hidden />
        <button
          type="button"
          className="chat-attach-btn"
          onClick={() => fileRef.current?.click()}
          disabled={loading}
          aria-label="Đính kèm ảnh"
          title="Đính kèm ảnh"
        >
          <PaperclipIcon />
        </button>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={image ? "Mô tả hoặc hỏi về ảnh (tuỳ chọn)..." : "Nhập câu hỏi..."}
          maxLength={1500}
          aria-label="Tin nhắn"
        />
        <button type="submit" disabled={loading || (!input.trim() && !image)} aria-label="Gửi" title="Gửi">
          <ArrowUpIcon />
        </button>
      </form>
    </div>
  )
}

// model hay trả **đậm** và `code` dù đã dặn plain text; hiển thị gọn thay vì lộ ký tự markdown
function RichText({ text }) {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, i) =>
    part.startsWith("**") && part.endsWith("**") ? (
      <strong key={i}>{part.slice(2, -2)}</strong>
    ) : part.startsWith("`") && part.endsWith("`") && part.length > 1 ? (
      <code key={i}>{part.slice(1, -1)}</code>
    ) : (
      part
    ),
  )
}
