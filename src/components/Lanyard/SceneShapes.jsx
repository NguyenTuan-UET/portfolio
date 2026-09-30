import { useEffect, useRef, useState } from "react"
import { useFrame, useThree } from "@react-three/fiber"

// These are scenery: only the badge should take part in pointer interactions.
const ignoreRaycast = () => null

export default function SceneShapes() {
  const loop = useRef()
  const sphere = useRef()
  const { camera, size, viewport } = useThree()
  const [reducedMotion, setReducedMotion] = useState(
    () => window.matchMedia("(prefers-reduced-motion: reduce)").matches
  )

  useEffect(() => {
    const preference = window.matchMedia("(prefers-reduced-motion: reduce)")
    const update = () => setReducedMotion(preference.matches)
    preference.addEventListener("change", update)
    return () => preference.removeEventListener("change", update)
  }, [])

  // Use the viewport at the sculptures' depth so their silhouette stays inside
  // the card's half of the page, including narrow desktop layouts.
  const stage = viewport.getCurrentViewport(camera, [0, 0, -2.4])
  const wide = size.width >= 860
  const availableWidth = wide ? stage.width / 2 : stage.width
  const scale = Math.min(1, availableWidth / 5.2)

  useFrame(({ clock }) => {
    const time = reducedMotion ? 0 : clock.elapsedTime
    loop.current.rotation.y = -0.62 + Math.sin(time * 0.16) * 0.055
    loop.current.rotation.z = -0.34 + Math.sin(time * 0.12) * 0.035
    sphere.current.position.y = 1.1 + Math.sin(time * 0.3) * 0.065
  })

  return (
    <group position={[wide ? stage.width / 4 : 0, 0.05, -2.4]} scale={scale}>
      <mesh
        ref={loop}
        position={[-0.64, -0.6, 0]}
        rotation={[0.42, -0.62, -0.34]}
        scale={[1, 1.08, 1]}
        raycast={ignoreRaycast}
      >
        <torusGeometry args={[1.25, 0.37, 24, 88]} />
        <meshPhysicalMaterial
          color="#afa4dc"
          roughness={0.3}
          metalness={0.12}
          clearcoat={0.8}
          clearcoatRoughness={0.25}
          envMapIntensity={0.8}
        />
      </mesh>

      <mesh ref={sphere} position={[1.6, 1.1, -0.2]} raycast={ignoreRaycast}>
        <sphereGeometry args={[0.48, 32, 24]} />
        <meshPhysicalMaterial
          color="#eda98b"
          roughness={0.17}
          metalness={0.08}
          clearcoat={1}
          clearcoatRoughness={0.15}
          envMapIntensity={1}
        />
      </mesh>
    </group>
  )
}
