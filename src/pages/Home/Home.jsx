import { useState } from "react"
import { Link } from "react-router-dom"
import Lanyard from "../../components/Lanyard/Lanyard"
import { TextGlitch } from "../../components/TextGlitch/TextGlitch"
import { BADGE, CONTACTS, cvFile } from "../../data/profile"

export default function Home() {
  const [flipCount, setFlipCount] = useState(0)
  const toggleFlip = () => setFlipCount((n) => n + 1)

  return (
    <div className="page">
      <div className="watermark" aria-hidden="true">
        <span>Nguyễn</span>
        <span>Quang</span>
        <span>Tuấn</span>
      </div>

      <div className="lanyard">
        <Lanyard badge={BADGE} flipCount={flipCount} onFlip={toggleFlip} />
      </div>

      <main className="hero">
        <h1>
          <TextGlitch text="Hello world !" hoverText="Hí, anh em!" />
        </h1>

        <div className="contacts">
          <span className="label">FIND ME IN:</span>
          <ul>
            {CONTACTS.map(({ label, handle, href, Icon }) => (
              <li key={label}>
                <a href={href} target={href.startsWith("http") ? "_blank" : undefined} rel="noreferrer">
                  <Icon />
                  <span className="label strong">{handle}</span>
                </a>
              </li>
            ))}
          </ul>
        </div>

        <hr className="divider" />

        <div className="quote-row">
          <blockquote className="quote">
            <p>“One day or day one.”</p>
          </blockquote>

          <a className="button label" href={cvFile} download="CV_NguyenQuangTuan_AIE.pdf">
            DOWNLOAD CV <span aria-hidden="true">↓</span>
          </a>
        </div>
      </main>

      <div className="subfooter label">
        <span>
          OPEN TO NEW OPPORTUNITIES —{" "}
          <a
            href="https://mail.google.com/mail/?view=cm&fs=1&to=nqtuan.code@gmail.com"
            target="_blank"
            rel="noreferrer"
            className="strong"
          >
            SAY HELLO
          </a>
        </span>
        <Link to="/about" className="strong">ABOUT ME ↓</Link>
      </div>
    </div>
  )
}
