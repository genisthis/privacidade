import { describe, expect, it } from "vitest"
import {
  ITERACOES_PBKDF2,
  abrirChaveDaSessao,
  cifrarJson,
  cifrarTexto,
  conferirVerificador,
  criarVerificador,
  decifrarBytes,
  decifrarJson,
  decifrarTexto,
  derivarChaveDaSenha,
  derivarChaveDoPrf,
  desembrulharChaveDoCofre,
  embrulharChaveDoCofre,
  gerarChaveDoCofre,
  gerarCodigoDeRecuperacao,
  gerarParteDoServidor,
  gerarSal,
  montarChaveDeRecuperacao,
  normalizarCodigo,
  normalizarResposta,
  selarChaveDaSessao,
  bytesAleatorios,
  bytesParaHex,
} from "./index"

const ITER = 1000 // só nos testes; produção usa ITERACOES_PBKDF2

describe("constantes", () => {
  it("PBKDF2 segue o OWASP vigente (600.000)", () => {
    expect(ITERACOES_PBKDF2).toBe(600_000)
  })
})

describe("cifra do conteúdo", () => {
  it("cifra e decifra texto e JSON (com acento e emoji)", async () => {
    const chave = gerarChaveDoCofre()
    const texto = "Tenho medo de não ser amada 💔 — ação"
    expect(await decifrarTexto(chave, await cifrarTexto(chave, texto))).toBe(texto)
    const obj = { resposta: "sim", n: [1, 2], escolha: null }
    expect(await decifrarJson(chave, await cifrarJson(chave, obj))).toEqual(obj)
  })

  it("IV novo a cada gravação: o mesmo texto nunca cifra igual", async () => {
    const chave = gerarChaveDoCofre()
    expect(await cifrarTexto(chave, "a")).not.toBe(await cifrarTexto(chave, "a"))
  })

  it("chave errada não abre", async () => {
    const c = await cifrarTexto(gerarChaveDoCofre(), "segredo")
    await expect(decifrarTexto(gerarChaveDoCofre(), c)).rejects.toThrow()
  })

  it("adulteração não abre (qualquer byte)", async () => {
    const chave = gerarChaveDoCofre()
    const [v, iv, corpo] = (await cifrarTexto(chave, "segredo")).split(".")
    const troca = (s: string) => (s[0] === "A" ? "B" : "A") + s.slice(1)
    await expect(decifrarTexto(chave, [v, iv, troca(corpo)].join("."))).rejects.toThrow()
    await expect(decifrarTexto(chave, [v, troca(iv), corpo].join("."))).rejects.toThrow()
  })

  it("formato inesperado é recusado", async () => {
    const chave = gerarChaveDoCofre()
    await expect(decifrarBytes(chave, "lixo")).rejects.toThrow()
    await expect(decifrarBytes(chave, "v9.aaaa.bbbb")).rejects.toThrow()
  })

  it("contexto: o valor não abre em outro lugar", async () => {
    const chave = gerarChaveDoCofre()
    const c = await cifrarTexto(chave, "x", "mensagens:1")
    expect(await decifrarTexto(chave, c, "mensagens:1")).toBe("x")
    await expect(decifrarTexto(chave, c, "mensagens:2")).rejects.toThrow()
    await expect(decifrarTexto(chave, c)).rejects.toThrow()
  })

  it("chave de tamanho errado é recusada", async () => {
    await expect(cifrarTexto(new Uint8Array(16), "x")).rejects.toThrow()
  })
})

describe("normalização", () => {
  it("acento, maiúscula, espaço e pontuação dão a mesma resposta", () => {
    const esperado = "saojose"
    for (const v of ["São José", "  SAO   jose ", "sao-jose!", "SÃO, JOSÉ.", "são josé"]) {
      expect(normalizarResposta(v)).toBe(esperado)
    }
  })
  it("resposta diferente continua diferente", () => {
    expect(normalizarResposta("Rex")).not.toBe(normalizarResposta("Rey"))
  })
  it("o código ignora hífen, espaço e caixa", () => {
    expect(normalizarCodigo("k7qm2 - xd9pa")).toBe("K7QM2XD9PA")
  })
  it("o código gerado tem o molde e nunca símbolo ambíguo", () => {
    for (let i = 0; i < 50; i++) {
      expect(gerarCodigoDeRecuperacao()).toMatch(/^[A-HJKMNP-Z2-9]{5}-[A-HJKMNP-Z2-9]{5}$/)
    }
  })
})

describe("embrulhos", () => {
  it("passkey (PRF): embrulha e desembrulha", async () => {
    const cofre = gerarChaveDoCofre()
    const prf = bytesAleatorios(32)
    const emb = await embrulharChaveDoCofre(cofre, await derivarChaveDoPrf(prf), "passkey", "p1")
    const aberta = await desembrulharChaveDoCofre(emb, await derivarChaveDoPrf(prf), "passkey", "p1")
    expect(bytesParaHex(aberta)).toBe(bytesParaHex(cofre))
  })

  it("PRF diferente, ou tipo/dono trocado, não abre", async () => {
    const cofre = gerarChaveDoCofre()
    const k = await derivarChaveDoPrf(bytesAleatorios(32))
    const emb = await embrulharChaveDoCofre(cofre, k, "passkey", "p1")
    await expect(desembrulharChaveDoCofre(emb, await derivarChaveDoPrf(bytesAleatorios(32)), "passkey", "p1")).rejects.toThrow()
    await expect(desembrulharChaveDoCofre(emb, k, "senha", "p1")).rejects.toThrow()
    await expect(desembrulharChaveDoCofre(emb, k, "passkey", "p2")).rejects.toThrow()
  })

  it("PRF curto demais é recusado", async () => {
    await expect(derivarChaveDoPrf(new Uint8Array(8))).rejects.toThrow()
  })

  it("senha: abre com a certa, não com a errada; sal diferente, chave diferente", async () => {
    const cofre = gerarChaveDoCofre()
    const sal = gerarSal()
    const k = await derivarChaveDaSenha("minha senha", sal, ITER)
    const emb = await embrulharChaveDoCofre(cofre, k, "senha")
    expect(bytesParaHex(await desembrulharChaveDoCofre(emb, await derivarChaveDaSenha("minha senha", sal, ITER), "senha"))).toBe(bytesParaHex(cofre))
    await expect(desembrulharChaveDoCofre(emb, await derivarChaveDaSenha("minha senhA", sal, ITER), "senha")).rejects.toThrow()
    await expect(desembrulharChaveDoCofre(emb, await derivarChaveDaSenha("minha senha", gerarSal(), ITER), "senha")).rejects.toThrow()
    await expect(derivarChaveDaSenha("", sal, ITER)).rejects.toThrow()
  })

  it("senha com as iterações de produção (600.000) funciona", async () => {
    const sal = gerarSal()
    const a = await derivarChaveDaSenha("s", sal)
    const b = await derivarChaveDaSenha("s", sal)
    expect(bytesParaHex(a)).toBe(bytesParaHex(b))
  })
})

describe("recuperação em três partes", () => {
  const codigo = "K7QM2-XD9PA"
  const resposta = "São José"

  async function caixinha() {
    const cofre = gerarChaveDoCofre()
    const parte = gerarParteDoServidor()
    const k = await montarChaveDeRecuperacao(codigo, resposta, parte)
    return { cofre, parte, caixa: await embrulharChaveDoCofre(cofre, k, "recuperacao") }
  }
  const abrir = async (caixa: string, c: string, r: string, p: Uint8Array) =>
    desembrulharChaveDoCofre(caixa, await montarChaveDeRecuperacao(c, r, p), "recuperacao")

  it("as três partes certas abrem — e a mesma resposta escrita de outro jeito também", async () => {
    const { cofre, parte, caixa } = await caixinha()
    expect(bytesParaHex(await abrir(caixa, codigo, resposta, parte))).toBe(bytesParaHex(cofre))
    expect(bytesParaHex(await abrir(caixa, "k7qm2xd9pa", "  SAO jose!! ", parte))).toBe(bytesParaHex(cofre))
  })

  it("resposta errada não abre", async () => {
    const { parte, caixa } = await caixinha()
    await expect(abrir(caixa, codigo, "São Paulo", parte)).rejects.toThrow()
  })

  it("código sem resposta não abre", async () => {
    const { parte, caixa } = await caixinha()
    await expect(abrir(caixa, codigo, "", parte)).rejects.toThrow()
  })

  it("resposta sem código não abre", async () => {
    const { parte, caixa } = await caixinha()
    await expect(abrir(caixa, "", resposta, parte)).rejects.toThrow()
    await expect(abrir(caixa, "AAAAA-BBBBB", resposta, parte)).rejects.toThrow()
  })

  it("sem a parte do servidor (ou com outra) não abre", async () => {
    const { caixa } = await caixinha()
    await expect(abrir(caixa, codigo, resposta, gerarParteDoServidor())).rejects.toThrow()
    await expect(montarChaveDeRecuperacao(codigo, resposta, new Uint8Array(0))).rejects.toThrow()
  })

  it("caixinha apagada não abre (nada a abrir)", async () => {
    const { parte } = await caixinha()
    await expect(abrir("", codigo, resposta, parte)).rejects.toThrow()
  })

  it("juntar código e resposta é sem ambiguidade", async () => {
    const parte = gerarParteDoServidor()
    const a = await montarChaveDeRecuperacao("AB", "cd", parte)
    const b = await montarChaveDeRecuperacao("A", "bcd", parte)
    expect(bytesParaHex(a)).not.toBe(bytesParaHex(b))
  })

  it("verificador: confere o par certo e recusa o resto", async () => {
    const sal = gerarSal()
    const v = await criarVerificador(codigo, resposta, sal, ITER)
    expect(await conferirVerificador("k7qm2 xd9pa", " são josé ", sal, v, ITER)).toBe(true)
    expect(await conferirVerificador(codigo, "outra", sal, v, ITER)).toBe(false)
    expect(await conferirVerificador("AAAAA-BBBBB", resposta, sal, v, ITER)).toBe(false)
    expect(await conferirVerificador(codigo, "", sal, v, ITER)).toBe(false)
    expect(await conferirVerificador("", resposta, sal, v, ITER)).toBe(false)
    expect(await conferirVerificador(codigo, resposta, gerarSal(), v, ITER)).toBe(false)
    expect(await conferirVerificador(codigo, resposta, sal, "!!!", ITER)).toBe(false)
    expect(v).not.toContain(normalizarResposta(resposta))
  })
})

describe("sessão do cofre", () => {
  const segredo = "ab".repeat(32)
  it("sela e abre; outro humano, outro segredo ou adulteração não abrem", async () => {
    const cofre = gerarChaveDoCofre()
    const cookie = await selarChaveDaSessao(cofre, segredo, "h1")
    expect(bytesParaHex(await abrirChaveDaSessao(cookie, segredo, "h1"))).toBe(bytesParaHex(cofre))
    await expect(abrirChaveDaSessao(cookie, segredo, "h2")).rejects.toThrow()
    await expect(abrirChaveDaSessao(cookie, "cd".repeat(32), "h1")).rejects.toThrow()
    await expect(abrirChaveDaSessao(cookie.slice(0, -2) + "AA", segredo, "h1")).rejects.toThrow()
  })
  it("segredo curto é recusado", async () => {
    await expect(selarChaveDaSessao(gerarChaveDoCofre(), "abcd", "h1")).rejects.toThrow()
  })
})
