import profilePhoto from "../assets/profile.jpg"
import profileIcon from "../assets/icon.jpg"
import qrCode from "../assets/qrcode.png"
import cvFile from "../assets/CV_NguyenQuangTuan_AIE.pdf"
import { GitHubIcon, InstagramIcon, FacebookIcon, MailIcon } from "../icons/SocialIcons"

export { cvFile }

export const BADGE = {
  brand: "devtamin",
  name: "Tuan Q. Nguyen",
  role: "AI Software Engineer",
  cardDate: "3 March 2004",
  url: "devtamin.me",
  photo: profilePhoto,
  icon: profileIcon,
  qr: qrCode,
}

export const CONTACTS = [
  { label: "GitHub", handle: "NguyenTuan-UET", href: "https://github.com/NguyenTuan-UET", Icon: GitHubIcon },
  { label: "Instagram", handle: "@devtamin.exe", href: "https://www.instagram.com/devtamin.exe/", Icon: InstagramIcon },
  { label: "Facebook", handle: "nqtuan.code", href: "https://www.facebook.com/nqtuan.code/", Icon: FacebookIcon },
  { label: "Gmail", handle: "nqtuan.code@gmail.com", href: "https://mail.google.com/mail/?view=cm&fs=1&to=nqtuan.code@gmail.com", Icon: MailIcon },
]

export const EXPERIENCE = [
  {
    place: "Viettel AI",
    role: "AI Software Engineer",
    time: "09/2025 – 07/2026",
    note: "Conversational AI platform: OCR integration, Elasticsearch search, chatbot memory & citations.",
  },
  {
    place: "SOPEN",
    role: "Software Engineer",
    time: "01/2025 – 08/2025",
    note: "Digital signature app and event scheduling on Viettel Digital Workspace.",
  },
  {
    place: "UET Labs × GHTK, Toshiba",
    role: "Research Assistant",
    time: "09/2024 – 07/2025",
    note: "Fine-tuned PhoBERT / XLM-R for NER; unified multi-DAST security reports into SARIF.",
  },
]

export const SKILLS = [
  "Python", "Java", "Go", "JavaScript", "LangChain / LangGraph", "React",
  "Spring Boot", "Elasticsearch", "Qdrant", "Redis", "RabbitMQ",
]
