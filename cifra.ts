// A cifra do conteúdo: AES-256-GCM, IV aleatório de 96 bits a cada gravação.
//
// GCM autentica: chave errada, dado adulterado ou contexto (AAD) diferente
// FALHAM ao abrir — nunca devolvem lixo em silêncio.
//
// Formato do texto cifrado: `v1.<iv>.<cifrado+tag>` em base64url. O prefixo
// permite trocar de algoritmo no futuro sem adivinhar o que está gravado.

import {
  base64UrlParaBytes,
  bytesAleatorios,
  bytesParaBase64Url,
  bytesParaTexto,
  textoParaBytes,
} from "./bytes"

export const VERSAO_DO_FORMATO = "v1"
export const TAMANHO_DA_CHAVE = 32
export const TAMANHO_DO_IV = 12

const subtle = () => globalThis.crypto.subtle

export class ErroDeCofre extends Error {
  constructor(mensagem: string) {
    super(mensagem)
    this.name = "ErroDeCofre"
  }
}

function exigirChave(chave: Uint8Array): void {
  if (chave.length !== TAMANHO_DA_CHAVE) {
    throw new ErroDeCofre("A chave precisa ter 32 bytes (256 bits).")
  }
}

async function importar(chave: Uint8Array, usos: KeyUsage[]): Promise<CryptoKey> {
  exigirChave(chave)
  return subtle().importKey("raw", chave as BufferSource, { name: "AES-GCM" }, false, usos)
}

/** A chave do cofre: 256 bits aleatórios. Nasce no navegador. */
export function gerarChaveDoCofre(): Uint8Array {
  return bytesAleatorios(TAMANHO_DA_CHAVE)
}

/** Só para teste com vetor fixo: o IV vem de fora. Produção usa `cifrarBytes`. */
export async function cifrarBytesComIv(
  chave: Uint8Array,
  dados: Uint8Array,
  iv: Uint8Array,
  contexto?: string
): Promise<Uint8Array> {
  const k = await importar(chave, ["encrypt"])
  const params: AesGcmParams = { name: "AES-GCM", iv: iv as BufferSource }
  if (contexto !== undefined) params.additionalData = textoParaBytes(contexto) as BufferSource
  return new Uint8Array(await subtle().encrypt(params, k, dados as BufferSource))
}

/**
 * Cifra bytes. `contexto` (opcional) é amarrado ao texto cifrado: só abre com
 * o mesmo contexto (ex.: "mensagens:<id>"), o que impede trocar um valor de
 * lugar no banco.
 */
export async function cifrarBytes(
  chave: Uint8Array,
  dados: Uint8Array,
  contexto?: string
): Promise<string> {
  const iv = bytesAleatorios(TAMANHO_DO_IV)
  const cifrado = await cifrarBytesComIv(chave, dados, iv, contexto)
  return `${VERSAO_DO_FORMATO}.${bytesParaBase64Url(iv)}.${bytesParaBase64Url(cifrado)}`
}

export async function decifrarBytes(
  chave: Uint8Array,
  cifrado: string,
  contexto?: string
): Promise<Uint8Array> {
  const partes = cifrado.split(".")
  if (partes.length !== 3 || partes[0] !== VERSAO_DO_FORMATO) {
    throw new ErroDeCofre("Texto cifrado em formato inesperado.")
  }
  let iv: Uint8Array
  let corpo: Uint8Array
  try {
    iv = base64UrlParaBytes(partes[1])
    corpo = base64UrlParaBytes(partes[2])
  } catch {
    throw new ErroDeCofre("Texto cifrado em formato inesperado.")
  }
  if (iv.length !== TAMANHO_DO_IV) throw new ErroDeCofre("Texto cifrado em formato inesperado.")
  const k = await importar(chave, ["decrypt"])
  const params: AesGcmParams = { name: "AES-GCM", iv: iv as BufferSource }
  if (contexto !== undefined) params.additionalData = textoParaBytes(contexto) as BufferSource
  try {
    return new Uint8Array(await subtle().decrypt(params, k, corpo as BufferSource))
  } catch {
    // Mensagem única de propósito: não diz se foi chave, adulteração ou contexto.
    throw new ErroDeCofre("Não foi possível abrir: chave errada ou conteúdo alterado.")
  }
}

export async function cifrarTexto(chave: Uint8Array, texto: string, contexto?: string): Promise<string> {
  return cifrarBytes(chave, textoParaBytes(texto), contexto)
}

export async function decifrarTexto(chave: Uint8Array, cifrado: string, contexto?: string): Promise<string> {
  return bytesParaTexto(await decifrarBytes(chave, cifrado, contexto))
}

/** Qualquer valor JSON (o conteúdo íntimo costuma ser um objeto). */
export async function cifrarJson(chave: Uint8Array, valor: unknown, contexto?: string): Promise<string> {
  return cifrarTexto(chave, JSON.stringify(valor), contexto)
}

export async function decifrarJson<T = unknown>(
  chave: Uint8Array,
  cifrado: string,
  contexto?: string
): Promise<T> {
  return JSON.parse(await decifrarTexto(chave, cifrado, contexto)) as T
}
