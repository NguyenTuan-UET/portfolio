import { useEffect, useRef, useState } from "react"
import "./TextGlitch.css"

const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const TOUCH_REVEAL_MS = 2500

export function TextGlitch({ text, hoverText, href, className = "", delay = 0 }) {
  const revealRef = useRef(null)
  const scrambleIntervalRef = useRef(null)
  const touchHideTimerRef = useRef(null)
  const revealedRef = useRef(false)
  const [displayHoverText, setDisplayHoverText] = useState(hoverText || text)
  const [mounted, setMounted] = useState(false)

  // hiệu ứng xuất hiện lúc mount: fade + scale + nền chữ giãn ra dần
  useEffect(() => {
    const timer = setTimeout(() => setMounted(true), delay * 1000)
    return () => clearTimeout(timer)
  }, [delay])

  const reveal = () => {
    revealedRef.current = true
    if (hoverText) {
      let iteration = 0
      if (scrambleIntervalRef.current) clearInterval(scrambleIntervalRef.current)

      scrambleIntervalRef.current = setInterval(() => {
        setDisplayHoverText(
          hoverText
            .split("")
            .map((letter, index) => {
              if (letter === " ") return " "
              if (index < iteration) return hoverText[index]
              return LETTERS[Math.floor(Math.random() * LETTERS.length)]
            })
            .join("")
        )

        if (iteration >= hoverText.length) clearInterval(scrambleIntervalRef.current)
        iteration += 1 / 3
      }, 30)
    }

    if (revealRef.current) {
      revealRef.current.style.clipPath = "polygon(0 0, 100% 0, 100% 100%, 0 100%)"
    }
  }

  const hide = () => {
    revealedRef.current = false
    clearTimeout(touchHideTimerRef.current)
    if (scrambleIntervalRef.current) clearInterval(scrambleIntervalRef.current)
    setDisplayHoverText(hoverText || text)

    if (revealRef.current) {
      revealRef.current.style.clipPath = "polygon(0 50%, 100% 50%, 100% 50%, 0 50%)"
    }
  }

  // điện thoại không có hover: chạm để hiện, chạm lần nữa hoặc chờ một lúc thì ẩn
  const handleTouchTap = () => {
    if (revealedRef.current) {
      hide()
      return
    }
    reveal()
    clearTimeout(touchHideTimerRef.current)
    touchHideTimerRef.current = setTimeout(hide, TOUCH_REVEAL_MS)
  }

  useEffect(() => {
    return () => {
      if (scrambleIntervalRef.current) clearInterval(scrambleIntervalRef.current)
      clearTimeout(touchHideTimerRef.current)
    }
  }, [])

  const revealContent = hoverText ? (
    href ? (
      <a href={href} target="_blank" rel="noreferrer" className="text-glitch-link">
        {displayHoverText}
      </a>
    ) : (
      displayHoverText
    )
  ) : (
    text
  )

  return (
    <span
      className={`text-glitch ${mounted ? "text-glitch-in" : ""} ${className}`}
      onPointerEnter={(e) => e.pointerType === "mouse" && reveal()}
      onPointerLeave={(e) => e.pointerType === "mouse" && hide()}
      onPointerUp={(e) => e.pointerType !== "mouse" && handleTouchTap()}
    >
      {text}
      <span ref={revealRef} className="text-glitch-reveal">
        {revealContent}
      </span>
    </span>
  )
}
