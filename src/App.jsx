import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import Layout from "./components/Layout/Layout"
import Home from "./pages/Home/Home"
import About from "./pages/About/About"
import "./App.css"

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Home />} />
          <Route path="about" element={<About />} />
          <Route path="chat" element={<Navigate to="/" replace state={{ openChat: true }} />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
