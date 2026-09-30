// Embrulhar e desembrulhar a chave do cofre.
//
// Um embrulho é a chave do cofre cifrada (AES-256-GCM) por outra chave: a da
// passkey, a da senha ou a de recuperação. O servidor guarda o embrulho — nunca
// a chave aberta. O TIPO do embrulho é amarrado ao texto cifrado: um embrulho
// de senha não abre como se fosse de passkey.

import { cifrarBytes, decifrarBytes, ErroDeCofre, TAMANHO_DA_CHAVE } from "./cifra"

export type TipoDeEmbrulho = "passkey" | "senha" | "recuperacao"

function contexto(tipo: TipoDeEmbrulho, quem?: string): string {
  return `genisthis/cofre/embrulho/${tipo}${quem ? `/${quem}` : ""}`
}

/**
 * `quem` (opcional) amarra o embrulho a um dono — ex.: o id da passkey ou do
 * cofre. Quem desembrulha precisa dar o mesmo.
 */
export async function embrulharChaveDoCofre(
  chaveDoCofre: Uint8Array,
  chaveEmbrulhadora: Uint8Array,
  tipo: TipoDeEmbrulho,
  quem?: string
): Promise<string> {
  if (chaveDoCofre.length !== TAMANHO_DA_CHAVE) throw new ErroDeCofre("A chave do cofre precisa ter 32 bytes.")
  return cifrarBytes(chaveEmbrulhadora, chaveDoCofre, contexto(tipo, quem))
}

export async function desembrulharChaveDoCofre(
  embrulho: string,
  chaveEmbrulhadora: Uint8Array,
  tipo: TipoDeEmbrulho,
  quem?: string
): Promise<Uint8Array> {
  const chave = await decifrarBytes(chaveEmbrulhadora, embrulho, contexto(tipo, quem))
  if (chave.length !== TAMANHO_DA_CHAVE) throw new ErroDeCofre("O embrulho não guardava uma chave de cofre.")
  return chave
}
