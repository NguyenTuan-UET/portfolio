import { useEffect, useRef, useState } from "react"

const LAYER_NAME = {
  rate_limiter: "Giới hạn tốc độ",
  input_guardrail: "Guardrail",
  llm_error: "Lỗi mô hình",
  output_guardrail: "Guardrail",
}

const CHAT_SUGGESTIONS = [
  "Làm sao tạo mật khẩu mạnh mà dễ nhớ?",
  "Giải thích prompt injection cho người mới",
  "Gợi ý lộ trình học Python 1 tháng",
]

const MAX_IMAGE_SIDE = 1280 // resize trước khi gửi để nhẹ payload, ảnh gốc không rời khỏi trình duyệt

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
  const [sessionId] = useState(newSessionId)
  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(false)

  async function send(message, image) {
    const msg = message.trim()
    if ((!msg && !image) || loading) return
    const push = (m) => setMessages((prev) => [...prev, m])
    push({ role: "user", text: msg, imageUrl: image?.dataUrl })
    setLoading(true)
    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: sessionId, message: msg, image: image?.base64 }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      push({ role: "bot", text: data.reply, blocked: data.blocked, redacted: data.redacted, layer: data.layer })
    } catch {
      push({ role: "bot", text: "Không kết nối được tới server. Hãy chạy: npm run guard-server", blocked: true, layer: "network" })
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="chat-page">
      <header className="chat-head">
        <span className="label">AI CHATBOT</span>
        <h2>Hỏi đáp</h2>
        <p>
          Trò chuyện với mình bằng chữ hoặc đính kèm một ảnh để hỏi về nó. Ảnh chỉ được gửi thẳng cho mô hình, không
          lưu trên server.
        </p>
      </header>

      <ChatPanel messages={messages} loading={loading} onSend={send} />
    </section>
  )
}

function ChatPanel({ messages, loading, onSend }) {
  const [input, setInput] = useState("")
  const [image, setImage] = useState(null) // { dataUrl, base64 } — chỉ ở trong state trình duyệt
  const [imageError, setImageError] = useState("")
  const listRef = useRef(null)
  const fileRef = useRef(null)

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: "smooth" })
  }, [messages, loading])

  function submit(msg) {
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
      <ol className="chat-log" ref={listRef}>
        <li className="bot">
          <p>
            Chào bạn, mình là Guard Bot. Hỏi mình bất cứ điều gì — công nghệ, học tập, công việc, an toàn trên mạng —
            hoặc đính kèm một ảnh (biển báo, ảnh chụp màn hình...) để mình phân tích giúp.
          </p>
        </li>
        {messages.map((m, i) => (
          <li key={i} className={`${m.role}${m.blocked ? " blocked" : ""}`}>
            {m.role === "bot" && m.layer && (
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
          </li>
        ))}
        {loading && (
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
          📎
        </button>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={image ? "Mô tả hoặc hỏi về ảnh (tuỳ chọn)..." : "Nhập câu hỏi..."}
          maxLength={1500}
          aria-label="Tin nhắn"
        />
        <button type="submit" disabled={loading || (!input.trim() && !image)}>
          GỬI
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
