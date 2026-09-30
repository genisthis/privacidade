import { describe, expect, it } from "vitest"
import { bytesParaHex, hexParaBytes, textoParaBytes } from "./bytes"
import { cifrarBytesComIv } from "./cifra"
import { hkdf, pbkdf2 } from "./derivacao"

// Vetores publicados: provam que a matemática é a padrão, não a nossa.
describe("vetores fixos de referência", () => {
  it("AES-256-GCM: vetor de teste do NIST/McGrew-Viega (chave e IV zerados)", async () => {
    const saida = await cifrarBytesComIv(new Uint8Array(32), new Uint8Array(16), new Uint8Array(12))
    expect(bytesParaHex(saida)).toBe(
      "cea7403d4d606b6e074ec5d3baf39d18" + "d0d1c8a799996bf0265b98b5d48ab919"
    )
  })

  it("HKDF-SHA256: caso 1 do RFC 5869", async () => {
    const okm = await hkdf(
      new Uint8Array(22).fill(0x0b),
      hexParaBytes("000102030405060708090a0b0c"),
      hexParaBytes("f0f1f2f3f4f5f6f7f8f9"),
      42
    )
    expect(bytesParaHex(okm)).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
  })

  it("PBKDF2-HMAC-SHA256: vetores conhecidos (password/salt)", async () => {
    const senha = textoParaBytes("password")
    const sal = textoParaBytes("salt")
    expect(bytesParaHex(await pbkdf2(senha, sal, 1, 32))).toBe(
      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    )
    expect(bytesParaHex(await pbkdf2(senha, sal, 2, 32))).toBe(
      "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
    )
  })
})
