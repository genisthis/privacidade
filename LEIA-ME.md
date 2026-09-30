# privacidade/ — o cofre do humano

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

## Como apagar funciona

Apagar o conteúdo de um humano é apagar as linhas cifradas. Apagar a
**caixinha** de recuperação revoga o código do e-mail: sem ela, o código não
abre mais nada. Apagar todos os embrulhos torna o que restar (um backup, por
exemplo) irrecuperável para todo mundo, inclusive para nós.

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
- Se o código deste módulo mudar, quem já gravou precisa que o formato antigo
  (`v1`) continue abrindo: o prefixo existe para isso.

## Testes

`npm test` roda os testes deste diretório: vetores de referência publicados
(AES-GCM do NIST/McGrew-Viega, HKDF do RFC 5869, PBKDF2 conhecido), ida e volta,
adulteração, chave errada, contexto trocado, resposta errada, código sem
resposta, resposta sem código, sem a parte do servidor, caixinha apagada,
normalização e a trava de que o módulo é autocontido.
