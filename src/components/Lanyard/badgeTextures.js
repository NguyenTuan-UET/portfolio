import * as THREE from "three"

// Vùng UV của card.glb (React Bits) trong atlas: mặt trước nửa trái, mặt sau nửa phải
const FRONT_UV_RECT = { x: 0, y: 0, w: 0.5, h: 0.755 }
const BACK_UV_RECT = { x: 0.5, y: 0, w: 0.5, h: 0.757 }
const ATLAS_SIZE = 2048
const W = 1000
const H = 1510
const SANS = '"Inter", "Helvetica Neue", Helvetica, Arial, sans-serif'
const MONO = '"JetBrains Mono", "SF Mono", Menlo, Consolas, "DejaVu Sans Mono", monospace'

function createCanvas(width, height) {
  const canvas = document.createElement("canvas")
  canvas.width = width
  canvas.height = height
  return [canvas, canvas.getContext("2d")]
}

function setFont(ctx, weight, size, family, spacing = "0px") {
  ctx.font = `${weight} ${size}px ${family}`
  ctx.letterSpacing = spacing
}

function wrapWords(ctx, text, maxWidth) {
  const lines = []
  let line = ""
  for (const word of text.trim().split(/\s+/)) {
    const next = line ? `${line} ${word}` : word
    if (line && ctx.measureText(next).width > maxWidth) {
      lines.push(line)
      line = word
    } else {
      line = next
    }
  }
  if (line) lines.push(line)
  return lines
}

// điểm lấy nét (tỉ lệ trên ảnh gốc) khi ảnh bị cắt để phủ kín mặt thẻ
const PHOTO_FOCUS = { x: 0.5, y: 0.65 }
// phóng gần vào người để ảnh chiếm nhiều diện tích thẻ hơn
const PHOTO_ZOOM = 1.15

// cam đậm cho mặt sau, tương phản với nền xanh của trang
const BACK_GRADIENT = ["#e8691f", "#bf470c"]
const ICON_BG_TOLERANCE = 60

// xoá nền phẳng của icon bằng cách loang từ mép ảnh vào; viền đen của hình vẽ sẽ chặn vùng loang
function removeFlatBackground(image) {
  const [canvas, ctx] = createCanvas(image.width, image.height)
  ctx.drawImage(image, 0, 0)
  const { width, height } = canvas
  const pixels = ctx.getImageData(0, 0, width, height)
  const data = pixels.data
  const bg = [data[0], data[1], data[2]]
  const visited = new Uint8Array(width * height)
  const stack = []
  for (let x = 0; x < width; x++) stack.push(x, x + (height - 1) * width)
  for (let y = 0; y < height; y++) stack.push(y * width, width - 1 + y * width)

  while (stack.length) {
    const index = stack.pop()
    if (visited[index]) continue
    visited[index] = 1
    const o = index * 4
    const diff =
      Math.abs(data[o] - bg[0]) + Math.abs(data[o + 1] - bg[1]) + Math.abs(data[o + 2] - bg[2])
    if (diff > ICON_BG_TOLERANCE) continue
    data[o + 3] = 0
    const x = index % width
    if (x > 0) stack.push(index - 1)
    if (x < width - 1) stack.push(index + 1)
    if (index >= width) stack.push(index - width)
    if (index < width * (height - 1)) stack.push(index + width)
  }
  ctx.putImageData(pixels, 0, 0)
  return canvas
}

function drawCover(ctx, image, focus, zoom = 1) {
  const scale = Math.max(W / image.width, H / image.height) * zoom
  const sw = W / scale
  const sh = H / scale
  const clamp = (value, max) => Math.min(max, Math.max(0, value))
  const sx = clamp(image.width * focus.x - sw / 2, image.width - sw)
  const sy = clamp(image.height * focus.y - sh / 2, image.height - sh)
  ctx.drawImage(image, sx, sy, sw, sh, 0, 0, W, H)
}

// dải tối dọc theo chiều cao thẻ; stops là các cặp [vị trí y, độ tối]
function drawShade(ctx, stops) {
  const from = stops[0][0]
  const to = stops[stops.length - 1][0]
  const gradient = ctx.createLinearGradient(0, from, 0, to)
  for (const [y, opacity] of stops) {
    gradient.addColorStop((y - from) / (to - from), `rgba(0,0,0,${opacity})`)
  }
  ctx.fillStyle = gradient
  ctx.fillRect(0, from, W, to - from)
}

function setTextShadow(ctx, blur) {
  ctx.shadowColor = "rgba(0,0,0,0.75)"
  ctx.shadowBlur = blur
  ctx.shadowOffsetY = blur / 6
}

function drawFront(badge, photo) {
  const [canvas, ctx] = createCanvas(W, H)
  drawCover(ctx, photo, PHOTO_FOCUS, PHOTO_ZOOM)
  // nền ảnh khá sáng nên phủ tối đậm dần ở mép trên và nửa dưới để chữ trắng không bị chìm
  drawShade(ctx, [[0, 0.6], [180, 0.35], [320, 0]])
  drawShade(ctx, [[720, 0], [990, 0.55], [1220, 0.82], [H, 0.92]])

  ctx.fillStyle = "#fff"
  ctx.textBaseline = "alphabetic"

  setTextShadow(ctx, 14)
  setFont(ctx, 700, 46, MONO, "3px")
  ctx.textAlign = "right"
  ctx.fillText(badge.cardDate, W - 70, 190)

  let nameSize = 160
  let lines
  do {
    setFont(ctx, 700, nameSize, SANS, "-2px")
    lines = wrapWords(ctx, badge.name || " ", W - 140)
    nameSize -= 8
  } while (lines.length > 1 && nameSize > 64)

  setTextShadow(ctx, 24)
  ctx.textAlign = "left"
  ctx.fillText(lines.join(" "), 70, 1275)

  setTextShadow(ctx, 12)
  setFont(ctx, 700, 46, MONO, "3px")
  ctx.fillText((badge.role || "").toUpperCase(), 74, 1365)

  setFont(ctx, 600, 42, MONO, "2px")
  ctx.fillStyle = "rgba(255,255,255,0.9)"
  ctx.fillText(badge.url, 74, 1440)

  return canvas
}

function drawBack(icon, qr) {
  const [canvas, ctx] = createCanvas(W, H)
  const gradient = ctx.createLinearGradient(0, 0, 0, H)
  gradient.addColorStop(0, BACK_GRADIENT[0])
  gradient.addColorStop(1, BACK_GRADIENT[1])
  ctx.fillStyle = gradient
  ctx.fillRect(0, 0, W, H)

  const iconSize = 660
  ctx.drawImage(removeFlatBackground(icon), (W - iconSize) / 2, 150, iconSize, iconSize)

  // mã QR đặt trên nền trắng bo góc để máy quét luôn nhận được
  const plate = 480
  const plateX = (W - plate) / 2
  const plateY = 880
  ctx.fillStyle = "#fff"
  ctx.shadowColor = "rgba(60,20,0,0.35)"
  ctx.shadowBlur = 30
  ctx.shadowOffsetY = 8
  ctx.beginPath()
  ctx.roundRect(plateX, plateY, plate, plate, 36)
  ctx.fill()
  ctx.shadowColor = "transparent"

  const padding = 28
  ctx.imageSmoothingEnabled = false
  ctx.drawImage(qr, plateX + padding, plateY + padding, plate - padding * 2, plate - padding * 2)

  return canvas
}

export function createCardAtlas(badge, photo, icon, qr) {
  const [canvas, ctx] = createCanvas(ATLAS_SIZE, ATLAS_SIZE)
  // phần atlas ngoài 2 mặt được dùng cho cạnh thẻ
  ctx.fillStyle = "#111"
  ctx.fillRect(0, 0, ATLAS_SIZE, ATLAS_SIZE)

  const place = (face, rect) =>
    ctx.drawImage(
      face,
      rect.x * ATLAS_SIZE,
      rect.y * ATLAS_SIZE,
      rect.w * ATLAS_SIZE,
      rect.h * ATLAS_SIZE
    )
  place(drawFront(badge, photo), FRONT_UV_RECT)
  place(drawBack(icon, qr), BACK_UV_RECT)

  const texture = new THREE.CanvasTexture(canvas)
  texture.colorSpace = THREE.SRGBColorSpace
  texture.flipY = false
  texture.anisotropy = 16
  return texture
}

export function createBandTexture(badge) {
  const [canvas, ctx] = createCanvas(1024, 250)
  ctx.fillStyle = "#0a0a0a"
  ctx.fillRect(0, 0, 1024, 250)

  ctx.fillStyle = "#fff"
  ctx.textBaseline = "middle"
  ctx.textAlign = "left"
  ctx.textAlign = "center"
  setFont(ctx, 700, 88, SANS, "-1px")
  ctx.fillText(badge.brand, 512, 130)

  const texture = new THREE.CanvasTexture(canvas)
  texture.colorSpace = THREE.SRGBColorSpace
  texture.anisotropy = 16
  texture.wrapS = THREE.RepeatWrapping
  texture.wrapT = THREE.RepeatWrapping
  return texture
}
