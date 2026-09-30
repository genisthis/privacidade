import { readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"

// O módulo vai ser público: nada dele pode depender do resto do projeto, nem
// de servidor, nem de ambiente, nem escrever em log.
const dir = __dirname
const fontes = readdirSync(dir).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))

describe("privacidade/ é autocontido", () => {
  it("há fontes para conferir", () => {
    expect(fontes.length).toBeGreaterThanOrEqual(5)
  })
  for (const f of fontes) {
    const codigo = readFileSync(path.join(dir, f), "utf8")
    it(`${f}: só importa vizinhos ("./…")`, () => {
      const imports = [...codigo.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)].map((m) => m[1])
      for (const i of imports) expect(i.startsWith("./"), `${f} importa "${i}"`).toBe(true)
    })
    it(`${f}: sem ambiente, sem Node, sem log`, () => {
      const semComentarios = codigo.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "")
      expect(semComentarios).not.toMatch(/process\.env|node:|require\(|console\./)
    })
  }
})
