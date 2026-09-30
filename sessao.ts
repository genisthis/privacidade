// A sessão do cofre: depois de aberto, o navegador entrega a chave ao servidor
// uma vez; o servidor a cifra com um segredo de ambiente e devolve o resultado
// num cookie httpOnly de sessão. A cada requisição o servidor abre o cookie,
// usa a chave e a esquece.
//
// Aqui só a matemática: o segredo vem por parâmetro (este módulo não lê
// ambiente) e o cookie em si é assunto de quem chama.

import { base64UrlParaBytes, hexParaBytes, textoParaBytes } from "./bytes"
import { cifrarBytes, decifrarBytes, ErroDeCofre, TAMANHO_DA_CHAVE } from "./cifra"
import { hkdf } from "./derivacao"

const INFO_SESSAO = textoParaBytes("genisthis/cofre/sessao/v1")

async function chaveDoSegredo(segredo: string): Promise<Uint8Array> {
  // Aceita 64 hex (32 bytes) ou base64url com pelo menos 32 bytes. O segredo
  // passa por HKDF, então formatos diferentes nunca viram a mesma chave.
  let bruto: Uint8Array
  if (/^[0-9a-fA-F]{64,}$/.test(segredo) && segredo.length % 2 === 0) bruto = hexParaBytes(segredo)
  else {
    try {
      bruto = base64UrlParaBytes(segredo)
    } catch {
      throw new ErroDeCofre("O segredo da sessão do cofre está em formato inválido.")
    }
  }
  if (bruto.length < TAMANHO_DA_CHAVE) throw new ErroDeCofre("O segredo da sessão do cofre é curto demais.")
  return hkdf(bruto, new Uint8Array(0), INFO_SESSAO)
}

/**
 * Sela a chave do cofre para viajar no cookie. `humanoId` amarra o cookie ao
 * dono: o cookie de um humano não abre como se fosse de outro.
 */
export async function selarChaveDaSessao(
  chaveDoCofre: Uint8Array,
  segredo: string,
  humanoId: string
): Promise<string> {
  if (chaveDoCofre.length !== TAMANHO_DA_CHAVE) throw new ErroDeCofre("A chave do cofre precisa ter 32 bytes.")
  return cifrarBytes(await chaveDoSegredo(segredo), chaveDoCofre, `genisthis/cofre/sessao/${humanoId}`)
}

export async function abrirChaveDaSessao(
  cookie: string,
  segredo: string,
  humanoId: string
): Promise<Uint8Array> {
  const chave = await decifrarBytes(await chaveDoSegredo(segredo), cookie, `genisthis/cofre/sessao/${humanoId}`)
  if (chave.length !== TAMANHO_DA_CHAVE) throw new ErroDeCofre("O cookie não guardava uma chave de cofre.")
  return chave
}
