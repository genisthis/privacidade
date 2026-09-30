// De onde vêm as chaves que embrulham a chave do cofre.
//
//  - Passkey (PRF): o segredo que o autenticador devolve passa por HKDF.
//  - Senha do cofre: PBKDF2-SHA256, derivação lenta de propósito.
//  - Recuperação: HKDF(código do e-mail || resposta normalizada || parte do servidor).
//  - Verificador: PBKDF2 sobre código || resposta — o servidor confere sem
//    conhecer a resposta e sem que, sem o código, dê para chutar offline.
//
// Nenhuma dessas funções sabe de banco, rota ou tabela.

import {
  bytesAleatorios,
  bytesParaBase64Url,
  base64UrlParaBytes,
  iguaisEmTempoConstante,
  juntarComTamanho,
  textoParaBytes,
} from "./bytes"
import { ErroDeCofre, TAMANHO_DA_CHAVE } from "./cifra"

/** OWASP, Password Storage Cheat Sheet: PBKDF2-HMAC-SHA256 com 600.000 iterações. */
export const ITERACOES_PBKDF2 = 600_000
export const TAMANHO_DO_SAL = 16
export const TAMANHO_DA_PARTE_DO_SERVIDOR = 32

/** Entrada fixa que se pede ao PRF da passkey (`prf.eval.first`). Não é segredo. */
export const ENTRADA_DO_PRF = textoParaBytes("genisthis/cofre/prf/v1")

const INFO_PRF = "genisthis/cofre/chave-da-passkey/v1"
const INFO_RECUPERACAO = "genisthis/cofre/chave-de-recuperacao/v1"
const SAL_HKDF_PRF = textoParaBytes("genisthis/cofre/hkdf-sal/v1")

const subtle = () => globalThis.crypto.subtle

/** HKDF-SHA256 (RFC 5869). Exportada para o teste conferir com o vetor do RFC. */
export async function hkdf(
  material: Uint8Array,
  sal: Uint8Array,
  info: Uint8Array,
  tamanho = TAMANHO_DA_CHAVE
): Promise<Uint8Array> {
  const base = await subtle().importKey("raw", material as BufferSource, "HKDF", false, ["deriveBits"])
  const bits = await subtle().deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: sal as BufferSource, info: info as BufferSource },
    base,
    tamanho * 8
  )
  return new Uint8Array(bits)
}

/** PBKDF2-HMAC-SHA256. `iteracoes` só é trocado em teste; produção usa o padrão. */
export async function pbkdf2(
  segredo: Uint8Array,
  sal: Uint8Array,
  iteracoes = ITERACOES_PBKDF2,
  tamanho = TAMANHO_DA_CHAVE
): Promise<Uint8Array> {
  const base = await subtle().importKey("raw", segredo as BufferSource, "PBKDF2", false, ["deriveBits"])
  const bits = await subtle().deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: sal as BufferSource, iterations: iteracoes },
    base,
    tamanho * 8
  )
  return new Uint8Array(bits)
}

export function gerarSal(): Uint8Array {
  return bytesAleatorios(TAMANHO_DO_SAL)
}

// ---------------------------------------------------------------- passkey

/** Chave que embrulha a chave do cofre, vinda do segredo PRF da passkey. */
export async function derivarChaveDoPrf(segredoPrf: Uint8Array): Promise<Uint8Array> {
  if (segredoPrf.length < 32) throw new ErroDeCofre("O segredo do PRF veio curto demais.")
  return hkdf(segredoPrf, SAL_HKDF_PRF, textoParaBytes(INFO_PRF))
}

// ------------------------------------------------------------------ senha

/** Chave que embrulha a chave do cofre, vinda da senha do cofre. */
export async function derivarChaveDaSenha(
  senha: string,
  sal: Uint8Array,
  iteracoes = ITERACOES_PBKDF2
): Promise<Uint8Array> {
  if (senha.length === 0) throw new ErroDeCofre("A senha do cofre está vazia.")
  return pbkdf2(textoParaBytes(senha.normalize("NFKC")), sal, iteracoes)
}

// --------------------------------------------------------------- recuperação

/**
 * A resposta é normalizada antes de tudo: sem acento, minúscula, e só letras e
 * números ficam. "  São  José! " e "sao jose" são a mesma resposta.
 */
export function normalizarResposta(resposta: string): string {
  return resposta
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]/gu, "")
}

// Sem 0/O/1/I/L: o código é lido num e-mail e digitado à mão.
const ALFABETO_DO_CODIGO = "ABCDEFGHJKMNPQRSTUVWXYZ23456789" // 31 símbolos
export const TAMANHO_DO_CODIGO = 10

/** O código do e-mail: 10 símbolos sem ambiguidade, sorteio sem viés. Ex.: `K7QM2-XD9PA`. */
export function gerarCodigoDeRecuperacao(): string {
  const saida: string[] = []
  // 248 = 31 * 8: descarta o resto para não haver viés.
  while (saida.length < TAMANHO_DO_CODIGO) {
    for (const b of bytesAleatorios(32)) {
      if (b < 248 && saida.length < TAMANHO_DO_CODIGO) saida.push(ALFABETO_DO_CODIGO[b % 31])
    }
  }
  return `${saida.slice(0, 5).join("")}-${saida.slice(5).join("")}`
}

/** Maiúsculas, sem hífen nem espaço: `k7qm2 xd9pa` vira `K7QM2XD9PA`. */
export function normalizarCodigo(codigo: string): string {
  return codigo.toUpperCase().replace(/[^A-Z0-9]/g, "")
}

/** A terceira parte: fica no servidor, liberada só quando código e resposta conferem. */
export function gerarParteDoServidor(): Uint8Array {
  return bytesAleatorios(TAMANHO_DA_PARTE_DO_SERVIDOR)
}

function segredoDasDuasPartes(codigo: string, resposta: string): Uint8Array {
  const c = normalizarCodigo(codigo)
  const r = normalizarResposta(resposta)
  if (c.length === 0) throw new ErroDeCofre("Falta o código.")
  if (r.length === 0) throw new ErroDeCofre("Falta a resposta.")
  return juntarComTamanho(textoParaBytes(c), textoParaBytes(r))
}

/**
 * A chave de recuperação = HKDF(código || resposta || parte do servidor).
 * Sem qualquer uma das três, a chave é outra e a caixinha não abre.
 */
export async function montarChaveDeRecuperacao(
  codigo: string,
  resposta: string,
  parteDoServidor: Uint8Array
): Promise<Uint8Array> {
  if (parteDoServidor.length !== TAMANHO_DA_PARTE_DO_SERVIDOR) {
    throw new ErroDeCofre("A parte do servidor veio com tamanho errado.")
  }
  const material = juntarComTamanho(segredoDasDuasPartes(codigo, resposta), parteDoServidor)
  return hkdf(material, new Uint8Array(0), textoParaBytes(INFO_RECUPERACAO))
}

/**
 * O verificador que o servidor guarda: PBKDF2 lento sobre código || resposta,
 * com sal próprio. Serve para o servidor decidir se libera a parte 3 (e contar
 * tentativas) sem nunca ver a resposta em claro guardada.
 */
export async function criarVerificador(
  codigo: string,
  resposta: string,
  sal: Uint8Array,
  iteracoes = ITERACOES_PBKDF2
): Promise<string> {
  const saida = await pbkdf2(segredoDasDuasPartes(codigo, resposta), sal, iteracoes)
  return bytesParaBase64Url(saida)
}

export async function conferirVerificador(
  codigo: string,
  resposta: string,
  sal: Uint8Array,
  verificador: string,
  iteracoes = ITERACOES_PBKDF2
): Promise<boolean> {
  let esperado: Uint8Array
  try {
    esperado = base64UrlParaBytes(verificador)
  } catch {
    return false
  }
  let calculado: Uint8Array
  try {
    calculado = await pbkdf2(segredoDasDuasPartes(codigo, resposta), sal, iteracoes)
  } catch {
    return false // código ou resposta vazios: nunca confere
  }
  return iguaisEmTempoConstante(calculado, esperado)
}

