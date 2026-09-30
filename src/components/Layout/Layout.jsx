import { useEffect, useState } from "react"
import { NavLink, useLocation, useOutlet } from "react-router-dom"
import Chat from "../../pages/Chat/Chat"
import { CONTACTS, cvFile } from "../../data/profile"

// thời gian cuộn lên đầu khi đổi trang, tăng số này nếu muốn cuộn chậm hơn
const SCROLL_TO_TOP_MS = 800

const easeInOutCubic = (t) => (t < 0.5 ? 4 * t * t * t : 1 - (-2 * t + 2) ** 3 / 2)

// cuộn mượt về đầu trang với thời lượng cố định; dừng nếu người dùng tự cuộn chen vào
function scrollToTop(duration) {
  const startY = window.scrollY
  if (startY === 0) return () => {}
  const startTime = performance.now()
  let frame = 0
  const cancel = () => {
    cancelAnimationFrame(frame)
    window.removeEventListener("wheel", cancel)
    window.removeEventListener("touchstart", cancel)
  }
  const step = (now) => {
    const progress = Math.min(1, (now - startTime) / duration)
    window.scrollTo({ top: startY * (1 - easeInOutCubic(progress)), behavior: "instant" })
    if (progress < 1) frame = requestAnimationFrame(step)
    else cancel()
  }
  window.addEventListener("wheel", cancel, { passive: true })
  window.addEventListener("touchstart", cancel, { passive: true })
  frame = requestAnimationFrame(step)
  return cancel
}

const NAV_LINKS = [
  { to: "/", label: "HOME" },
  { to: "/about", label: "ABOUT" },
]

export default function Layout() {
  const location = useLocation()
  const outlet = useOutlet()
  // trang đang hiển thị thật sự — giữ nguyên trang cũ (kèm Outlet của nó) trong lúc mờ dần,
  // chỉ chuyển sang trang mới sau khi trang cũ đã mờ hẳn (xem route-fade-inner bên dưới)
  const [rendered, setRendered] = useState({ location, outlet })
  const [leaving, setLeaving] = useState(false)

  // chuyển trang thì bắt đầu từ đầu trang mới, không giữ vị trí cuộn của trang trước
  useEffect(() => scrollToTop(SCROLL_TO_TOP_MS), [location.pathname])

  // Home có canvas 3D (Lanyard) nặng để dọn dẹp (Three.js/Rapier); nếu unmount ngay lập tức, canvas
  // đó có thể lóe sáng một khung hình giữa lúc bị gỡ. Nên báo hiệu "leaving" để mờ dần trang cũ trước,
  // rồi mới thật sự đổi sang Outlet của trang mới khi đã mờ hẳn (onTransitionEnd bên dưới).
  useEffect(() => {
    if (location.pathname !== rendered.location.pathname) setLeaving(true)
  }, [location, rendered])

  function handleFadeEnd(e) {
    if (e.target !== e.currentTarget || e.propertyName !== "opacity" || !leaving) return
    setRendered({ location, outlet })
    setLeaving(false)
  }

  return (
    <div className="site-shell">
      <header className="header">
        <span className="label header-date">3 March 2004, Ha Noi</span>
        <nav className="header-nav label">
          {NAV_LINKS.map(({ to, label }, i) => (
            <span key={to} className="header-nav-item">
              {i > 0 && <span className="sep">|</span>}
              <NavLink to={to} end className={({ isActive }) => (isActive ? "strong" : undefined)}>
                {label}
              </NavLink>
            </span>
          ))}
        </nav>
      </header>

      <div className="route-fade">
        {/* key theo đường dẫn để trang mới chạy lại hiệu ứng mờ dần khi xuất hiện */}
        <div
          key={rendered.location.pathname}
          className={`route-fade-inner${leaving ? " is-leaving" : ""}`}
          onTransitionEnd={handleFadeEnd}
        >
          {rendered.outlet}
        </div>
      </div>

      <footer className="footer label">
        <nav>
          {NAV_LINKS.map(({ to, label }) => (
            <NavLink key={to} to={to} end>{label}</NavLink>
          ))}
          <a href={cvFile} download="CV_NguyenQuangTuan_AIE.pdf">CV</a>
        </nav>
        <div className="footer-right">
          <span>© 2026 NGUYEN QUANG TUAN</span>
          {CONTACTS.map(({ label, href, Icon }) => (
            <a key={label} href={href} aria-label={label} target={href.startsWith("http") ? "_blank" : undefined} rel="noreferrer">
              <Icon />
            </a>
          ))}
        </div>
      </footer>

      <Chat />
    </div>
  )
}
