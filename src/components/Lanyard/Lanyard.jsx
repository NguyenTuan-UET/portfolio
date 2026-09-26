// Dựa trên component Lanyard của React Bits (reactbits.dev), model card.glb từ repo React Bits
import * as THREE from "three"
import { useEffect, useMemo, useRef, useState } from "react"
import { Canvas, extend, useFrame, useThree } from "@react-three/fiber"
import { Environment, Lightformer, useGLTF, useTexture } from "@react-three/drei"
import {
  BallCollider,
  CuboidCollider,
  Physics,
  RigidBody,
  useRopeJoint,
  useSphericalJoint,
} from "@react-three/rapier"
import { MeshLineGeometry, MeshLineMaterial } from "meshline"
import cardGLB from "../../assets/card.glb"
import { createBandTexture, createCardAtlas } from "./badgeTextures"
extend({ MeshLineGeometry, MeshLineMaterial })
useGLTF.preload(cardGLB)

const ANCHOR_Y = 4
const CARD_SCALE = 2.25
const MIN_SPEED = 0
const MAX_SPEED = 50
// để yên thẻ một lúc thì thẻ tự xoay chậm để lần lượt lộ hai mặt
const AUTO_ROTATE_DELAY = 2.5
const AUTO_ROTATE_SPEED = 0.4
// khớp với breakpoint 860px trong App.css
const WIDE_LAYOUT = 860
const TAP_MAX_MOVE = 10
const TAP_MAX_MS = 300

const segmentProps = {
  type: "dynamic",
  canSleep: true,
  colliders: false,
  angularDamping: 4,
  linearDamping: 4,
}

function useDisposable(factory, deps) {
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const value = useMemo(factory, deps)
  useEffect(() => () => value.dispose(), [value])
  return value
}

function Band({ badge, flipCount, onFlip }) {
  const band = useRef()
  const fixed = useRef()
  const j1 = useRef()
  const j2 = useRef()
  const j3 = useRef()
  const card = useRef()
  const cardPivot = useRef()
  const ring = useRef()

  const { nodes, materials } = useGLTF(cardGLB)
  const width = useThree((state) => state.size.width)
  const viewportWidth = useThree((state) => state.viewport.width)
  const isWide = width >= WIDE_LAYOUT
  const anchorX = isWide ? viewportWidth / 4 : 0
  const [initialAnchorX] = useState(anchorX)
  // màn hẹp: dây treo thẳng đứng ngay từ đầu để thẻ không văng ra khỏi mép màn hình khi rơi
  const [startVertical] = useState(!isWide)
  const gl = useThree((state) => state.gl)

  const [dragged, setDragged] = useState(false)
  const [hovered, setHovered] = useState(false)
  const draggingRef = useRef(false)
  const touchStart = useRef(null)
  draggingRef.current = Boolean(dragged)

  // trên điện thoại, vuốt mặc định là cuộn trang và trình duyệt sẽ huỷ thao tác kéo;
  // chặn cuộn chỉ trong lúc đang giữ thẻ để vẫn cuộn trang bình thường ở chỗ khác
  useEffect(() => {
    const element = gl.domElement
    const preventScrollWhileDragging = (e) => {
      if (draggingRef.current) e.preventDefault()
    }
    element.addEventListener("touchmove", preventScrollWhileDragging, { passive: false })
    return () => element.removeEventListener("touchmove", preventScrollWhileDragging)
  }, [gl])

  const [scratch] = useState(() => ({
    vec: new THREE.Vector3(),
    dir: new THREE.Vector3(),
    ang: new THREE.Vector3(),
    axis: new THREE.Vector3(),
    quat: new THREE.Quaternion(),
    twist: new THREE.Quaternion(),
    euler: new THREE.Euler(),
    lerped: [null, null],
  }))

  const [curve] = useState(() => {
    const c = new THREE.CatmullRomCurve3([
      new THREE.Vector3(),
      new THREE.Vector3(),
      new THREE.Vector3(),
      new THREE.Vector3(),
    ])
    c.curveType = "chordal"
    return c
  })

  const [photo, icon, qr] = useTexture([badge.photo, badge.icon, badge.qr])
  const cardMap = useDisposable(
    () => createCardAtlas(badge, photo.image, icon.image, qr.image),
    [badge, photo, icon, qr]
  )
  const bandTexture = useDisposable(() => createBandTexture(badge), [badge])

  useRopeJoint(fixed, j1, [[0, 0, 0], [0, 0, 0], 1])
  useRopeJoint(j1, j2, [[0, 0, 0], [0, 0, 0], 1])
  useRopeJoint(j2, j3, [[0, 0, 0], [0, 0, 0], 1])
  useSphericalJoint(j3, card, [[0, 0, 0], [0, 1.5, 0]])

  useEffect(() => {
    if (!hovered && !dragged) return
    document.body.style.cursor = dragged ? "grabbing" : "grab"
    return () => {
      document.body.style.cursor = "auto"
    }
  }, [hovered, dragged])

  // góc xoay mong muốn quanh trục dọc của thẻ; bội số chẵn của PI là mặt trước, lẻ là mặt sau
  const targetYaw = useRef(0)
  const idleTime = useRef(0)
  const snapToFace = () => {
    targetYaw.current = Math.round(targetYaw.current / Math.PI) * Math.PI
  }

  useEffect(() => {
    if (flipCount === 0) return
    snapToFace()
    targetYaw.current += Math.PI
    idleTime.current = 0
    card.current?.wakeUp()
  }, [flipCount])

  useEffect(() => {
    fixed.current?.setTranslation({ x: anchorX, y: ANCHOR_Y, z: 0 }, true)
    ;[card, j1, j2, j3].forEach((ref) => ref.current?.wakeUp())
  }, [anchorX])

  useFrame((state, delta) => {
    if (!fixed.current || !card.current) return
    const { vec, dir, ang, axis, quat, twist, euler, lerped } = scratch

    if (dragged) {
      vec.set(state.pointer.x, state.pointer.y, 0.5).unproject(state.camera)
      dir.copy(vec).sub(state.camera.position).normalize()
      vec.add(dir.multiplyScalar(state.camera.position.length()))
      ;[card, j1, j2, j3, fixed].forEach((ref) => ref.current?.wakeUp())
      card.current.setNextKinematicTranslation({
        x: vec.x - dragged.x,
        y: vec.y - dragged.y,
        z: vec.z - dragged.z,
      })
    }

    ;[j1, j2].forEach((ref, i) => {
      const current = ref.current.translation()
      if (!lerped[i]) lerped[i] = new THREE.Vector3().copy(current)
      const distance = Math.max(0.1, Math.min(1, lerped[i].distanceTo(current)))
      const alpha = Math.min(1, delta * (MIN_SPEED + distance * (MAX_SPEED - MIN_SPEED)))
      lerped[i].lerp(current, alpha)
    })

    curve.points[0].copy(j3.current.translation())
    curve.points[1].copy(lerped[1])
    curve.points[2].copy(lerped[0])
    curve.points[3].copy(fixed.current.translation())
    band.current.geometry.setPoints(curve.getPoints(isWide ? 32 : 16))

    if (dragged || hovered) {
      if (idleTime.current > AUTO_ROTATE_DELAY) snapToFace()
      idleTime.current = 0
    } else {
      idleTime.current += delta
      if (idleTime.current > AUTO_ROTATE_DELAY) {
        targetYaw.current += AUTO_ROTATE_SPEED * Math.min(delta, 1 / 30)
      }
    }

    // kéo thẻ quay dần về góc mong muốn
    if (!dragged) {
      quat.copy(card.current.rotation())
      euler.setFromQuaternion(quat, "YXZ")
      const target = targetYaw.current
      const diff = Math.atan2(Math.sin(target - euler.y), Math.cos(target - euler.y))
      if (Math.abs(diff) > 0.002) {
        // xoay quanh trục dọc của thẻ (đi qua khớp nối) để móc không bị lắc theo
        axis.set(0, 1, 0).applyQuaternion(quat)
        const spin = diff * 15 * Math.min(delta, 1 / 30)
        ang.copy(card.current.angvel()).addScaledVector(axis, spin)
        card.current.setAngvel(ang, true)
      }
    }

    // bỏ phần xoay quanh trục dọc (twist), chỉ giữ độ nghiêng (swing) cho khung chữ D
    cardPivot.current.getWorldPosition(ring.current.position)
    cardPivot.current.getWorldQuaternion(quat)
    twist.set(0, quat.y, 0, quat.w).normalize()
    ring.current.quaternion.copy(quat).multiply(twist.invert())
  })

  return (
    <>
      <group position={[initialAnchorX, ANCHOR_Y, 0]}>
        <RigidBody ref={fixed} {...segmentProps} type="fixed" />
        <RigidBody ref={j1} position={startVertical ? [0, -0.5, 0] : [0.5, 0, 0]} {...segmentProps}>
          <BallCollider args={[0.1]} />
        </RigidBody>
        <RigidBody ref={j2} position={startVertical ? [0, -1, 0] : [1, 0, 0]} {...segmentProps}>
          <BallCollider args={[0.1]} />
        </RigidBody>
        <RigidBody ref={j3} position={startVertical ? [0, -1.5, 0] : [1.5, 0, 0]} {...segmentProps}>
          <BallCollider args={[0.1]} />
        </RigidBody>
        <RigidBody
          ref={card}
          position={startVertical ? [0, -3, 0] : [2, 0, 0]}
          {...segmentProps}
          type={dragged ? "kinematicPosition" : "dynamic"}
        >
          <CuboidCollider args={[0.8, 1.125, 0.01]} />
          <group
            scale={CARD_SCALE}
            position={[0, -1.2, -0.01]}
            // chạm trên điện thoại không có "rời chuột", nên chỉ tính hover với chuột thật
            onPointerOver={(e) => e.pointerType === "mouse" && setHovered(true)}
            onPointerOut={() => setHovered(false)}
            onPointerDown={(e) => {
              e.stopPropagation()
              e.target.setPointerCapture(e.pointerId)
              touchStart.current = { x: e.clientX, y: e.clientY, time: performance.now() }
              setDragged(
                new THREE.Vector3()
                  .copy(e.point)
                  .sub(scratch.vec.copy(card.current.translation()))
              )
            }}
            onPointerUp={(e) => {
              e.target.releasePointerCapture(e.pointerId)
              setDragged(false)
              // điện thoại không có double-click: chạm nhanh, không kéo thì lật thẻ
              const start = touchStart.current
              if (e.pointerType !== "mouse" && start) {
                const moved = Math.hypot(e.clientX - start.x, e.clientY - start.y)
                if (moved < TAP_MAX_MOVE && performance.now() - start.time < TAP_MAX_MS) onFlip()
              }
              touchStart.current = null
            }}
            onPointerCancel={() => setDragged(false)}
            onDoubleClick={(e) => {
              e.stopPropagation()
              onFlip()
            }}
          >
            <mesh geometry={nodes.card.geometry}>
              <meshPhysicalMaterial
                map={cardMap}
                roughness={0.8}
                metalness={0}
                // ambientLight (cường độ PI) đã cho đúng 100% màu ảnh; ánh sáng môi trường cộng thêm
                // sẽ làm cháy sáng, còn tone mapping ACES mặc định làm nhạt và giảm độ bão hoà
                envMapIntensity={0.5}
                toneMapped={false}
              />
            </mesh>
            <mesh geometry={nodes.clamp.geometry} material={materials.metal} />
          </group>
          <group ref={cardPivot} />
        </RigidBody>
      </group>

      {/* khung chữ D nối với dây: đi theo thẻ nhưng không xoay theo, thẻ xoay tại khớp tròn */}
      <group ref={ring}>
        <group scale={CARD_SCALE} position={[0, -1.2, -0.01]}>
          <mesh geometry={nodes.clip.geometry} material={materials.metal} material-roughness={0.3} />
        </group>
      </group>

      <mesh ref={band}>
        <meshLineGeometry />
        <meshLineMaterial
          color="white"
          depthTest={false}
          resolution={[1000, 1000]}
          useMap
          map={bandTexture}
          repeat={[-4, 1]}
          lineWidth={1}
        />
      </mesh>
    </>
  )
}

export default function Lanyard({ badge, flipCount, onFlip }) {
  return (
    <Canvas camera={{ position: [0, 0, 14.5], fov: 20 }} dpr={[1, 2]} gl={{ alpha: true }}>
      <ambientLight intensity={Math.PI} />
      {/* bước vật lý chạy trước useFrame của Band để khung chữ D khớp đúng vị trí thẻ đã cập nhật */}
      <Physics interpolate gravity={[0, -40, 0]} timeStep={1 / 60} updatePriority={-50}>
        <Band badge={badge} flipCount={flipCount} onFlip={onFlip} />
      </Physics>
      <Environment>
        <Lightformer intensity={2} position={[0, -1, 5]} rotation={[0, 0, Math.PI / 3]} scale={[100, 0.1, 1]} />
        <Lightformer intensity={3} position={[-1, -1, 1]} rotation={[0, 0, Math.PI / 3]} scale={[100, 0.1, 1]} />
        <Lightformer intensity={3} position={[1, 1, 1]} rotation={[0, 0, Math.PI / 3]} scale={[100, 0.1, 1]} />
        <Lightformer intensity={4} position={[-10, 0, 14]} rotation={[0, Math.PI / 2, Math.PI / 3]} scale={[100, 10, 1]} />
      </Environment>
    </Canvas>
  )
}
