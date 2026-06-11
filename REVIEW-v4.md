# Revisão da v4 → decisões da v5

Revisão de 2026-06-11 cobrindo `v4/client/`, `v4/server/`, `v4/security-v4/`,
config e instaladores. Cada achado abaixo aponta a correção correspondente na v5.

## Segurança

| # | Achado na v4 | Correção na v5 |
|---|--------------|----------------|
| S1 | **Senha MQTT em texto plano commitada** em `config/config.json` (e presente no histórico git). Todos os loaders aceitavam `mqtt.password` inline como fallback. | Loader **recusa** qualquer segredo inline (`config.py:_reject_inline_secrets`); segredos só via ambiente (`/etc/authmon/env`, root 600). A senha exposta da v4 deve ser **rotacionada no broker**. |
| S2 | MQTT em TCP puro (porta 1883) pela internet — credenciais e eventos em claro. | TLS por padrão (`mqtt.tls: true`, porta 8883, verificação de certificado). `tls_insecure` existe só para lab e loga warning. |
| S3 | **Eventos assinados mas repetíveis (replay)**: o caminho de produção (`6-block-ips.py` → `listen-to-mosquitto.py`/`7-iptables-agent.py`) não tinha `event_id`, dedupe nem janela de validade. Um `unblock` assinado capturado podia ser reproduzido para sempre. (O módulo `security-v4` tinha as primitivas certas, mas não era o caminho usado.) | Todo evento carrega `event_id` + `ts`; receptor valida assinatura → frescor (300s) → dedupe persistente (`seen_events`). Testes cobrem replay, adulteração e evento vencido. |
| S4 | `listen-to-mosquitto.py` aplicava **qualquer** block recebido: sem guarda de IP privado, sem whitelist, sem proteção do próprio broker/nó → auto-DoS possível com uma credencial vazada. | Guarda única (`ipguard.Guard`) em **todos** os caminhos de enforcement: rejeita não-público/reservado, allowlist, lista never-block e os IPs do próprio nó e do broker (resolvidos em runtime). |
| S5 | Sem limite de volume: um publisher comprometido podia bloquear milhares de IPs por minuto (mass-block DoS). | Rate limit de blocks por minuto no agente (`max_blocks_per_minute`, default 30) + rate limit de escrita na API + cap de entradas em sync (`max_sync_entries`). |
| S6 | Regra iptables individual por IP no topo do INPUT — ruleset cresce sem limite, sem expiração. | Backend **ipset** (uma regra iptables por família, lookup O(1)) com **timeout no kernel**; fallback iptables mantido para hosts sem ipset. |
| S7 | Sem rotação de chave HMAC prevista (a v4 server tinha um mecanismo improvisado via JSON em env). | Rotação de primeira classe: `AUTHMON_EVENT_HMAC` + `AUTHMON_EVENT_HMAC_PREVIOUS` aceitos na verificação; publica sempre com a atual. |
| S8 | API border ok no geral, mas aceitava block de IP privado/broker e não tinha rate limit. | API passa pelo mesmo `Guard` do enforcement automático + rate limit + auditoria em `decisions`. |

## Estabilidade / Resiliência

| # | Achado na v4 | Correção na v5 |
|---|--------------|----------------|
| R1 | Blocks **perdidos no reboot** (iptables volátil; nenhuma reconciliação no boot). | DB SQLite é a fonte de verdade; `firewall.reconcile()` reaplica os blocks ativos com TTL restante no startup do agente. |
| R2 | Watermark por timestamp em `6-block-ips.py` com aritmética frágil (`published - 1` contando heartbeat) — publicação parcial podia pular ou duplicar eventos. | Outbox transacional: cada evento marcado `applied_at`/`published_at` por linha; at-least-once + dedupe por `event_id` no receptor. |
| R3 | Tail fixo de 5500 linhas relido a cada minuto: linhas perdidas em burst, reprocessamento mascarado por heurísticas. | `logtail` com (inode, offset) persistidos: cada linha lida exatamente uma vez, rotação/truncamento detectados, linha parcial preservada. |
| R4 | Janelas de detecção só em memória dentro de um run — burst atravessando runs não detectado de forma confiável. | Sinais persistidos na tabela `signals` com janela deslizante real entre execuções. |
| R5 | Cron a cada minuto + pgrep/kill + lockfiles em `/var/run` no lugar de supervisão de processo. Daemon caía e ficava até 60s morto; instalador matava processos por pattern. | systemd: agente como serviço `Restart=always`, detector como timer oneshot, hardening (`ProtectSystem=strict`, `NoNewPrivileges`). |
| R6 | Conexão MQTT: crash se broker indisponível no boot; eventos perdidos enquanto nó offline. | `connect_async` + retry com backoff; sessão persistente (clean_session=False, QoS1) para entrega pós-reconexão; **sync periódico de estado** (1h) converge nós que ficaram fora além da sessão; Last Will assinado (`node_offline`). |
| R7 | Blocks permanentes; DB e ruleset crescem para sempre. | TTL em todo block (default 7d), expiração no kernel (ipset timeout) **e** no DB (loop de reconcílio), tabelas com prune. |
| R8 | Dois sistemas paralelos (`client/`+`server/` e `security-v4/`) com regex, assinatura e enforcement duplicados e divergentes. | Uma biblioteca (`authmon/`) e três entry points (detector, agente, API). |
| R9 | Enforcement local dependia do round-trip pelo broker (cliente publicava; o agente do mesmo host recebia via MQTT). | Local-first: agente aplica o outbox no firewall local **antes** de publicar; broker fora do ar não impede defesa local. |

## O que NÃO mudou

- Mosquitto/MQTT como transporte do grid (topologia e broker existentes aproveitados).
- Regras de detecção da v4/security-v4 (immediate paths, high-risk paths, bursts,
  scanner UA, traversal, ssh) portadas com os mesmos thresholds default.
- FastAPI + Bearer token na API border (com compare constante, como na v4).

## Pendências de migração (ação manual)

1. **Rotacionar a senha MQTT** exposta no git da v4 (mosquitto_passwd no broker) e o HMAC.
2. Habilitar TLS no Mosquitto (listener 8883 com cert; Let's Encrypt funciona).
3. Instalar v5 (`sudo ./install.sh agent`) nos nós; `sudo ./install.sh api` no broker.
4. Validar convivência: v5 usa tópico próprio (`authmon/v5/events`) — não colide com a v4;
   desativar os crons da v4 por host após o canário (1 nó, observar `decisions`).
5. Importar blocks ativos da v4 se desejado (script ad-hoc lendo `db/blocked_ips.db` → outbox).
