# privacidade/ — o cofre do humano

> **In short (English).** This directory is the whole cryptographic core of GenIsThis' "vault": the code that
> locks everything intimate a person writes, says or shows. Content is encrypted with AES-256-GCM under a 256-bit key
> that is generated in the person's browser and never stored in the clear; the server only keeps that key wrapped by
> the person's passkey, vault password and recovery path. It has no dependencies, imports nothing from the rest of the
> product, reads no environment, and talks to no database or network (`autocontido.test.ts` enforces this). The
> servers see the key and the plaintext only inside a request made by that very person, because the AI has to read the
> text to serve them. The honest limits are listed below, and the full, plain-language explanation of what we collect,
> why, where it lives, who can see it and when it is erased is at **https://genisthis.com/seguranca**
> (a plain-text version for AIs: https://genisthis.com/seguranca.md). The rest of this file is in Portuguese.

Este diretório é toda a matemática que guarda o que é íntimo de um humano.
Não importa nada do resto do projeto, não lê ambiente, não fala com banco nem
com rede, não escreve em log (`autocontido.test.ts` trava isso). Roda igual no
navegador e no servidor: usa só o WebCrypto (`globalThis.crypto.subtle`), que
o Node também tem. Não tem dependência.

Ler este texto e os arquivos ao lado basta para conferir o que se promete. O
que está aqui é o que o código faz hoje; onde o código ainda não liga alguma
peça, está dito.

## O que é cifrado, e com o quê

- **Conteúdo**: AES-256-GCM, com IV aleatório de 96 bits a cada gravação
  (`cifra.ts`). O GCM autentica: chave errada, byte alterado ou contexto
  diferente falham ao abrir, sem devolver lixo. Formato: `v1.<iv>.<cifrado>`
  em base64url. O `contexto` opcional amarra o valor ao lugar onde foi
  gravado (por exemplo uma linha), para que trocá-lo de lugar no banco o torne
  ilegível.
- **A chave do cofre**: 256 bits aleatórios, gerados no navegador
  (`gerarChaveDoCofre`). Nunca é gravada aberta em lugar nenhum.
- **Embrulhos** (`embrulho.ts`): a chave do cofre cifrada por outra chave. O
  servidor guarda só os embrulhos. O tipo (`passkey`, `senha`,
  `recuperacao`) e um dono opcional entram como contexto: um embrulho de senha
  não abre como se fosse de passkey.
  - **Passkey**: o segredo PRF que o autenticador devolve passa por HKDF-SHA256
    (`derivarChaveDoPrf`); a saída é a chave que embrulha. A entrada do PRF é
    fixa (`ENTRADA_DO_PRF`) e não é segredo.
  - **Senha do cofre** (para aparelho sem PRF): PBKDF2-HMAC-SHA256 com 600.000
    iterações (`ITERACOES_PBKDF2`, o valor do OWASP Password Storage Cheat
    Sheet) e sal aleatório de 16 bytes. Quem grava o embrulho guarda também o
    sal e o número de iterações.
  - **Recuperação**: a chave é HKDF(código do e-mail, resposta normalizada,
    parte do servidor), juntados com o tamanho de cada pedaço para que não haja
    ambiguidade (`montarChaveDeRecuperacao`). Sem qualquer um dos três, a chave
    é outra e a caixinha (o embrulho de recuperação) não abre.
- **Verificador da recuperação** (`criarVerificador`, `conferirVerificador`):
  PBKDF2 (600.000 iterações, sal próprio) sobre código + resposta normalizada.
  É o que o servidor guarda para decidir se libera a parte dele e para contar
  tentativas. Comparação em tempo constante.
- **Normalização da resposta** (`normalizarResposta`): decompõe acentos e os
  descarta, põe em minúsculas e mantém só letras e números. "São José!" e
  "  sao jose" são a mesma resposta. O código do e-mail ignora caixa, espaço e
  hífen (`normalizarCodigo`).
- **Sessão do cofre** (`sessao.ts`): depois de aberto, o navegador entrega a
  chave uma vez; o servidor a sela com um segredo de ambiente (que este módulo
  recebe por parâmetro, nunca lê) e o resultado vai num cookie `httpOnly` de
  sessão, amarrado ao id do humano. A cada requisição o servidor abre o
  cookie, usa a chave e a esquece. O cookie em si e o segredo são assunto de
  quem chama.

## Onde cada parte mora

| Parte | Onde |
|---|---|
| Chave do cofre aberta | só na memória do navegador (e, por uma requisição, na memória do servidor) |
| Embrulho por passkey / por senha | no servidor, ao lado da credencial |
| A caixinha (embrulho de recuperação) e o verificador | no servidor |
| Código da recuperação | no e-mail de garantia de privacidade do humano |
| Resposta da pergunta | na cabeça do humano; o servidor guarda só o verificador |
| Parte 3 da recuperação | no servidor, liberada só quando código + resposta conferem |
| Segredo que sela o cookie da sessão | variável de ambiente do servidor |

## O que o servidor vê, e quando

- Durante uma requisição do humano com o cofre aberto, o servidor tem a chave
  do cofre e o conteúdo decifrado **na memória**, o tempo da requisição.
- A IA lê o conteúdo enquanto trabalha para o humano: para responder, o texto
  vai decifrado ao provedor de IA. Isso não é evitável: é o serviço.
- Sem o cofre aberto (sem o cookie), o servidor só tem texto cifrado.
- Durante a recuperação, o servidor vê o código e a resposta no momento em que
  o humano os digita, para conferir o verificador.

## O que NÃO está no cofre, e por quê

Fica fora o que o sistema precisa ler sem o humano presente: identidade (e-mail,
nome), acesso e cobrança, prova do aceite, contagens, e a posição do humano no
percurso. Também o que é do autor, não do humano. A lista, tabela a tabela, é
mantida na documentação do projeto. Este módulo não conhece tabelas: ele só
cifra o que lhe entregam.

## A voz do humano

Quando o humano responde falando, a gravação é cifrada com a chave do cofre
dele assim que chega (a mesma cifra `v1`, com o contexto `audio:<humano>:<resposta>`) e
guardada cifrada; o armazenamento nunca vê o áudio em claro. Para a IA ouvir, o servidor
abre a gravação com o cofre aberto e faz uma cópia temporária, num caminho neutro
que não leva o id de ninguém (`temporario/<uuid>.<ext>`), que é apagada logo depois
da chamada, dê certo ou não. Quando a IA devolve o texto e o texto
está gravado (cifrado) no cofre, **a gravação é apagada e o cofre registra
"sua gravação foi transcrita e apagada"**. Se a transcrição falha, a gravação
fica, cifrada, até uma nova tentativa funcionar (só com o cofre aberto, porque
só ele a abre). A voz vira texto e é apagada.

## A selfie do humano

A foto do rosto é a coisa mais íntima que o produto recebe, e **não fica guardada**. Ao chegar, ela é
cifrada com a chave do cofre (o contexto é `selfie:<humano>:<resposta>`) e só então toca o armazenamento.
Para a IA olhar, o servidor faz a mesma cópia temporária da voz — num caminho neutro, sem o id do humano,
apagada ao fim da chamada. A IA diz se a foto serve; **só esse resultado fica, cifrado**. Logo em seguida a
selfie cifrada é apagada, sirva ou não, e a anterior também — e o cofre registra "sua selfie foi analisada e
apagada". Como a foto não fica, o produto não consegue criar imagens que usem o rosto da pessoa.

## A narração que cita o humano

Quando o autor escreve uma narração que cita o que o humano respondeu, o áudio gerado diz o que ele escreveu —
então é cifrado como o resto (contexto `narracao:<humano>:<requisição>`), guardado na pasta dele, e só toca por
uma rota que exige a sessão dele e o cofre aberto. Voltar à mesma tela toca a mesma narração; recomeçar a
jornada gera outra, e a antiga continua guardada, cifrada, até o humano apagar os dados. A narração que não cita
ninguém é igual para todos e não é íntima: continua num cache público do produto.

## Como apagar funciona

Há dois jeitos de apagar, e cada um faz exatamente o que está aqui — o que não está listado não é
prometido.

**1. O humano apaga os dados dele num produto** (a tela "Excluir meus dados"). Uma função do banco
(`excluir_dados_do_humano_no_produto`), numa única transação, apaga daquele humano **naquele produto**:
as mensagens e conversas, os percursos, as respostas, as descobertas, as pendências, as liberações de
arquivos e de caminhos e, na personalidade simulada, as conversas e mensagens. Os pedidos à IA (`requisicoes_ia`)
perdem o vínculo com o humano **e o texto** (a entrada, a saída, o erro e o endereço da imagem): o custo
fica, o conteúdo não. Depois da transação, o servidor apaga a pasta do humano naquele produto no Spaces (o
arquivo personalizado, a selfie e qualquer voz cifrada ainda pendente) — lista, apaga e lista de novo até a
pasta voltar vazia; se o Spaces recusar um arquivo, a exclusão **não** se declara concluída. Nada disso pede o
cofre aberto: as linhas cifradas saem como saem as claras, sem serem lidas.

**2. A linha do humano é apagada** (por quem administra o banco; nenhuma tela faz isto hoje). O cofre, os
embrulhos (passkey e senha), os desbloqueios e o registro "Quem leu" caem junto, por cascata
(`ON DELETE CASCADE`) — e também a sessão, a conta do provedor, as passkeys, os acessos e as exclusões. Antes
de a linha sair, um gatilho esvazia o texto dos pedidos à IA. Quem apaga a linha também apaga a pasta dele no
Spaces. **Sem a chave do cofre e sem os embrulhos, qualquer cópia do conteúdo cifrado que tenha sobrado num
backup é ilegível para sempre — para todo mundo, inclusive para nós.**

**O que NÃO é apagado quando o humano apaga os dados de um produto, e por quê:** o cofre e o registro "Quem
leu" (são do humano, não do produto; o cofre guarda o que está nos outros produtos, e o registro prova o que
já aconteceu); o acesso ao produto e a prova do aceite da política (obrigação legal); a contagem de
percursos que o humano já usou (direito de acesso); e o recibo.

**O recibo.** Toda exclusão gera um recibo: a data, o produto, **só contagens por tabela** (nunca uma palavra
do que o humano escreveu), a versão do módulo do cofre em uso (`privacidade/v1`) e o SHA-256 do recibo. O
humano o vê na tela ao fim, recebe por e-mail e pode conferir o código depois; o servidor guarda o mesmo
código em `exclusoes.recibo_hash`. Gerar o recibo não precisa do cofre aberto — nada nele vem de dentro
dele. O texto que o hash resume é este JSON compacto, com as chaves nesta ordem e os itens em ordem
alfabética:

```
{"versao_do_recibo":1,"exclusao_id":"<uuid>","produto":"<slug>","concluida_em":"2026-10-01T09:33:20Z",
 "itens":{"arquivos":0,"mensagens":12,"respostas":3},"modulo":"privacidade/v1"}
```

(`concluida_em` em UTC, em segundos; o JSON real não tem quebra de linha.) Quem tiver o recibo refaz a
conta com qualquer SHA-256 e compara.

## Os limites honestos

- A IA lê o conteúdo durante o serviço, e o conteúdo existe decifrado na
  memória do servidor enquanto a requisição dura.
- Quem perde a passkey **e** esquece a resposta (ou perde o e-mail) perde o
  cofre. Não há chave mestra.
- A recuperação não é "zero conhecimento" contra o próprio servidor: o
  servidor guarda a parte 3 e o verificador, e envia o e-mail com o código. Um
  servidor comprometido que também lesse aquele e-mail poderia tentar adivinhar
  a resposta offline (custo: 600.000 iterações por palpite). O código tem cerca
  de 49 bits e a resposta é curta e humana: esta via protege contra vazamento
  de banco ou de backup, não contra quem controla o servidor e o e-mail ao
  mesmo tempo. O limite de tentativas vale para quem chuta pelo servidor.
- Uma ordem judicial não obtém conteúdo (não há chave em repouso), só os
  registros de acesso e o texto cifrado.
- Um navegador comprometido, ou uma extensão maliciosa, vê o que o humano vê.
- As cópias do banco (o despejo semanal e o backup do provedor do banco) levam as linhas **como estão no
  banco**: cifradas, para tudo o que foi gravado depois do cofre existir. O que foi gravado antes dele
  continua legível nessas cópias até ser apagado, e as cópias antigas só saem pela rotação (oito semanas).
- Durante a transcrição da voz, e durante a análise da selfie, existe uma cópia temporária, em claro, com endereço
  assinado de poucos minutos, num caminho que não leva o id de ninguém, para a IA conseguir ouvi-la ou vê-la. Ela
  é apagada ao fim da chamada; se o apagar falhar, o dono do sistema é avisado, e antes da próxima cópia as que
  tiverem mais de quinze minutos são varridas.
- Se o código deste módulo mudar, quem já gravou precisa que o formato antigo
  (`v1`) continue abrindo: o prefixo existe para isso.

## Testes

`npm test` roda os testes deste diretório: vetores de referência publicados
(AES-GCM do NIST/McGrew-Viega, HKDF do RFC 5869, PBKDF2 conhecido), ida e volta,
adulteração, chave errada, contexto trocado, resposta errada, código sem
resposta, resposta sem código, sem a parte do servidor, caixinha apagada,
normalização e a trava de que o módulo é autocontido.

## Como conferir

O mesmo diretório que roda no servidor é publicado, com histórico só dele,
num repositório público (`genisthis/privacidade`). Para conferir que o que
está lá é idêntico ao que roda:

1. Peça o hash que o servidor declara: `GET /api/privacidade/versao`
   (campo do hash do diretório; a página `/seguranca` mostra o mesmo).
2. Baixe o repositório público e refaça o hash a partir de fora, na raiz dele:

   ```
   find . -type f -not -path './.git/*' -not -name '.*' | sed 's|^\./||' | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256
   ```

   (É o mesmo comando da página técnica, com `cd privacidade` trocado por estar
   já dentro do repositório publicado, e excluindo `.git/`.)
3. Se os dois hashes forem iguais, o código público é o que está rodando. Se
   forem diferentes, a publicação ainda não aconteceu para a versão que roda,
   ou algo está errado: o hash do servidor é o que vale como prova de
   incoerência.

O repositório só passa a existir quando o dono do sistema o cria e configura
a publicação (workflow `.github/workflows/publicar-privacidade.yml`, segredo
`PRIVACIDADE_PUBLICAR_TOKEN`); até lá o workflow termina sem fazer nada.
