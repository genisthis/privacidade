// Bytes, texto e base64url. Sem dependência: roda no navegador e no Node.

const codificador = new TextEncoder()
const decodificador = new TextDecoder("utf-8", { fatal: true })

export function textoParaBytes(texto: string): Uint8Array {
  return codificador.encode(texto)
}

export function bytesParaTexto(bytes: Uint8Array): string {
  return decodificador.decode(bytes)
}

export function bytesParaBase64Url(bytes: Uint8Array): string {
  let binario = ""
  for (let i = 0; i < bytes.length; i++) binario += String.fromCharCode(bytes[i])
  return btoa(binario).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function base64UrlParaBytes(texto: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(texto)) throw new Error("Base64 inválido.")
  const padded = texto.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((texto.length + 3) % 4)
  const binario = atob(padded)
  const bytes = new Uint8Array(binario.length)
  for (let i = 0; i < binario.length; i++) bytes[i] = binario.charCodeAt(i)
  return bytes
}

export function bytesParaHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

export function hexParaBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) throw new Error("Hex inválido.")
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

export function bytesAleatorios(tamanho: number): Uint8Array {
  const bytes = new Uint8Array(tamanho)
  globalThis.crypto.getRandomValues(bytes)
  return bytes
}

export function concatenar(...partes: Uint8Array[]): Uint8Array {
  const total = partes.reduce((soma, p) => soma + p.length, 0)
  const saida = new Uint8Array(total)
  let posicao = 0
  for (const p of partes) {
    saida.set(p, posicao)
    posicao += p.length
  }
  return saida
}

/** Compara em tempo constante (para o mesmo tamanho). */
export function iguaisEmTempoConstante(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diferenca = 0
  for (let i = 0; i < a.length; i++) diferenca |= a[i] ^ b[i]
  return diferenca === 0
}

/** Prefixa cada parte com o tamanho (4 bytes), para juntar sem ambiguidade. */
export function juntarComTamanho(...partes: Uint8Array[]): Uint8Array {
  const pedacos: Uint8Array[] = []
  for (const p of partes) {
    const cabeca = new Uint8Array(4)
    new DataView(cabeca.buffer).setUint32(0, p.length, false)
    pedacos.push(cabeca, p)
  }
  return concatenar(...pedacos)
}
