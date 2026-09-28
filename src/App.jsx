import { BrowserRouter, Routes, Route } from "react-router-dom"
import Layout from "./components/Layout/Layout"
import Home from "./pages/Home/Home"
import About from "./pages/About/About"
import EmailGuard from "./pages/EmailGuard/EmailGuard"
import "./App.css"

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Home />} />
          <Route path="about" element={<About />} />
          <Route path="email-guard" element={<EmailGuard />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
