# auth-monitor v5

Firewall reativo distribuído para infraestrutura Linux multi-nó.  
Detecta comportamento malicioso em logs (nginx, sshd), bloqueia localmente e
replica o bloqueio para toda a grade via MQTT — com assinatura HMAC-SHA256,
anti-replay, TTL de kernel e reconciliação pós-reboot.

Reescrita do zero após revisão de segurança e estabilidade —
ver [REVIEW-v4.md](REVIEW-v4.md) para o mapa achado→correção.

---

## O que foi feito nessa versão

### Segurança

- **HMAC-SHA256 em todos os eventos** — campo `sig` = base64(HMAC-SHA256) do
  JSON canônico (chaves ordenadas, sem espaços). O receptor valida antes de
  qualquer ação. Suporta rotação de chave sem downtime (chave anterior aceita
  por janela configurável).
- **Anti-replay** — cada evento carrega `event_id` (UUID4) persistido em
  SQLite; eventos já vistos são silenciosamente descartados.
- **Frescor de eventos** — `ts` (ISO-8601 UTC) deve estar dentro de ±300 s do
  clock do receptor; eventos antigos ou do futuro são rejeitados.
- **Guard de IP** — antes de qualquer bloqueio a v5 verifica: o IP é público?
  Não está na allowlist? Não é o próprio broker? Não é o nó local? Sem isso,
  um evento forjado ou mal configurado poderia auto-bloquear a infraestrutura.
- **Config recusa segredos inline** — se `password`, `hmac_secret` ou
  `api_key` aparecerem diretamente no `config.json`, o processo recusa
  inicializar e loga o erro; segredos só vêm de variáveis de ambiente.
- **TLS no broker** — Mosquitto 2.x escuta na porta 8883 (TLS, cert Let's
  Encrypt); porta 1883 acessível apenas em localhost.
- **MQTT com autenticação por usuário/senha** — recomenda-se um usuário distinto
  por grupo de nós (ex: `authmon_broker`, `authmon_web`, `authmon_app`).
- **Rate limiter** — janela deslizante de 30 bloqueios/min por nó; proteção
  contra mass-block acidental ou forjado.
- **Segredos fora do git** — o histórico foi mantido limpo desde o início;
  senhas e chaves HMAC vivem exclusivamente em variáveis de ambiente.

### Resiliência

- **Local-first** — o agente aplica o outbox no firewall local *antes* de
  publicar para o grid; um nó sem conectividade MQTT continua bloqueando.
- **Startup reconciliation** — no boot, `Firewall.reconcile()` re-aplica ao
  kernel (ipset/iptables) todos os blocos ativos no banco; reboots não abrem
  janela de exposição.
- **Sessão MQTT persistente** (`clean_session=False`) + QoS 1 — eventos
  publicados enquanto o broker estava offline são entregues ao reconectar.
- **SQLite WAL** com `busy_timeout=5000` — detector e agente podem rodar em
  paralelo sem deadlock; WAL garante leituras não-bloqueantes.
- **Logtail por inode+offset** — o detector retoma exatamente de onde parou;
  rotação de log (logrotate) não causa perda nem re-leitura.
- **ipset como backend de firewall** — TTL gerenciado pelo kernel (O(1));
  iptables como fallback se ipset não estiver disponível.
- **Reconnect exponencial** — o cliente MQTT faz back-off de 1 s a 60 s;
  flaps de rede não spam-restartam o processo.

### Estabilidade

- **Separação detector ↔ agente** — o detector é oneshot (systemd timer, 1 min);
  não tem estado em memória, não segura conexão MQTT. O agente é o único daemon
  de longa duração.
- **Decisões auditáveis** — toda ação (block, unblock, rate_limited,
  non_public_address, api_reject, etc.) é gravada na tabela `decisions` com
  motivo e timestamp.
- **Crons da v4 removidos** em todos os nós após rollout.

---

## Arquitetura

```
┌─────────────── nó A (web) ────────────────┐  ┌─────────────── nó B (web) ────────────────┐
│                                           │  │                                           │
│  nginx/access.log ─┐                      │  │  apache2/access.log ─┐                    │
│  auth.log ─────────┴→ detector ──→ outbox │  │  auth.log ───────────┴→ detector ──→ outbox│
│                          ┌────────────────┘  │                            ┌──────────────┘
│                          ▼                   │                            ▼               │
│                    agent ──→ ipset/iptables   │                      agent ──→ ipset/iptables│
│                          │ ▲                 │                            │ ▲             │
└──────────────────────────┼─┼─────────────────┘  ────────────────────────┼─┼──────────────┘
                           │ │                                             │ │
                           ▼ │         eventos assinados                  ▼ │
                           │ │       (HMAC-SHA256 + anti-replay)          │ │
                           └─┴──────────────────┬────────────────────────┘ │
                                                │                           │
                                   ┌────────────▼────────────┐             │
                                   │   MQTT broker  :8883 TLS│◄────────────┘
                                   │   (nó dedicado)         │
                                   │                         │
                                   │  border API (FastAPI)   │
                                   │  block/unblock/status   │
                                   └─────────────────────────┘
                                                │
                              ┌─────────────────┼─────────────────┐
                              ▼                 ▼                 ▼
                         ┌─────────┐       ┌─────────┐       ┌─────────┐
                         │  nó C   │       │  nó D   │       │  nó N   │
                         │ agent   │       │ agent   │       │ agent   │
                         │ ipset   │       │ ipset   │       │ ipset   │
                         └─────────┘       └─────────┘       └─────────┘
```

### Módulos

| Caminho | Função |
|---|---|
| `authmon/config.py` | Carrega config + secrets; rejeita segredos inline |
| `authmon/events.py` | Cria e valida eventos v5 (HMAC, frescor, dedupe) |
| `authmon/state.py` | SQLite WAL: blocos, outbox, decisions, seen_events |
| `authmon/firewall.py` | ipset/iptables wrapper + reconcile() |
| `authmon/logtail.py` | Tail por inode+offset, rotation-safe |
| `authmon/mqttbus.py` | Cliente MQTT resiliente, TLS, QoS1 |
| `authmon/ipguard.py` | Guard: público, não-allowlisted, não-protegido |
| `authmon/ratelimit.py` | Janela deslizante 30 blocks/min |
| `detector/detect.py` | Oneshot: lê logs novos, grava intents no outbox |
| `agent/agent.py` | Daemon: outbox → firewall + grid, heartbeat, TTL |
| `api/api.py` | Control plane REST (Bearer, rate-limited) no broker |
| `desktop/notify-blocked-ips.py` | Notificador desktop (`notify-send`) via systemd --user |
| `desktop/monitor-firewall-activity.py` | Dashboard terminal: nós, IPs bloqueados, eventos |

---

## Protocolo de eventos

```json
{
  "v": 5,
  "event": "block",
  "event_id": "uuid4",
  "ts": "2026-06-11T14:35:00Z",
  "node": "web-prod-01",
  "ip": "1.2.3.4",
  "reason": "ssh_bruteforce",
  "sig": "base64(HMAC-SHA256(canonical_json_sem_sig))"
}
```

Eventos: `block`, `unblock`, `allow_add`, `allow_remove`, `port_allow_add`,
`port_allow_remove`, `ip_change`, `heartbeat`, `sync_state`, `node_offline`.

### Port-allowlist com escopo por nó

Os eventos `port_allow_add`/`port_allow_remove` liberam `ip:port/protocol` e
carregam o campo `target_node`:

- `target_node: "*"` (ou `"all"`) → fleet-wide: **todos** os nós aplicam a regra.
- `target_node: "<node_id>"` → **apenas** aquele nó aplica no iptables; os demais
  persistem a entrada para auditoria/reconciliação, mas não abrem a porta.

A regra é reaplicada no boot (reconciliação filtra pelo `node_id` local + `*`).

---

## Instalação

```bash
# qualquer nó (agent + detector)
sudo ./install.sh agent
sudo vim /etc/authmon/config.json   # mqtt.host, port, tls, username, allowlist
sudo vim /etc/authmon/env           # AUTHMON_MQTT_PASSWORD, AUTHMON_EVENT_HMAC
sudo systemctl restart authmon-agent

# nó do broker (adiciona a border API)
sudo ./install.sh api               # requer AUTHMON_API_KEY no env

# desktop (notificações locais)
bash desktop/install.sh
# editar ~/.config/authmon/env com AUTHMON_MQTT_PASSWORD, AUTHMON_EVENT_HMAC
```

Broker: Mosquitto 2.x com `per_listener_settings true`, listener 8883 TLS.  
Cert Let's Encrypt: renewal hook recomendado em `/etc/letsencrypt/renewal-hooks/deploy/mosquitto.sh`.

---

## Operação

```bash
# status
systemctl status authmon-agent authmon-detector.timer authmon-api

# logs
tail -f /var/log/authmon/agent.log /var/log/authmon/detector.log

# blocos ativos no kernel
ipset list authmon5-v4

# auditoria via SQLite
sqlite3 /var/lib/authmon/authmon.db \
  "SELECT ip, reason, blocked_at, expires_at FROM blocks WHERE active=1"
sqlite3 /var/lib/authmon/authmon.db \
  "SELECT * FROM decisions ORDER BY id DESC LIMIT 20"

# control plane via API (no nó do broker)
curl -H "Authorization: Bearer $AUTHMON_API_KEY" http://127.0.0.1:8741/v5/blocked
curl -H "Authorization: Bearer $AUTHMON_API_KEY" \
     -H 'Content-Type: application/json' \
     -d '{"ip":"1.2.3.4","reason":"manual"}' \
     http://127.0.0.1:8741/v5/block
curl -H "Authorization: Bearer $AUTHMON_API_KEY" \
     http://127.0.0.1:8741/v5/ip/1.2.3.4

# port-allowlist escopado a UM nó (abre 8741/tcp só no lb01sp)
curl -H "Authorization: Bearer $AUTHMON_API_KEY" \
     -H 'Content-Type: application/json' \
     -d '{"ip":"1.2.3.4","port":8741,"protocol":"tcp","target_node":"lb01sp","reason":"config-agent"}' \
     http://127.0.0.1:8741/v5/port-allowlist
# fleet-wide: omitir target_node (default "*") ou usar "all"

# listar (opcionalmente filtrando pelo nó: rows do nó + fleet-wide)
curl -H "Authorization: Bearer $AUTHMON_API_KEY" \
     "http://127.0.0.1:8741/v5/port-allowlist?node=lb01sp"

# remover no mesmo escopo (query ?node=)
curl -X DELETE -H "Authorization: Bearer $AUTHMON_API_KEY" \
     "http://127.0.0.1:8741/v5/port-allowlist/1.2.3.4/8741/tcp?node=lb01sp"
```

---

## Testes

```bash
python3 -m pytest tests/ -q
# 24 testes: HMAC/replay/frescor, guard de IP, logtail/rotação, TTL, outbox, detector
```

---

## Histórico de versões

| Versão | Descrição |
|---|---|
| v5 | Reescrita completa — HMAC, anti-replay, TLS, Guard, SQLite WAL, local-first |
| v4 | Referência — ver `v4/` (credenciais rotacionadas, não usar em produção) |
| v3 | Protótipo anterior |
| v2 | Primeira iteração |
