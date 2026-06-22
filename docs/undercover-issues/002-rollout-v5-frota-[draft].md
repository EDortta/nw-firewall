# 002 — Rollout do authmon v5 na frota inteira (incl. load balancers) + aposentadoria do v4

- **Status:** draft
- **Componente:** authmon v5 (install.sh, systemd) + tooling de deploy (`jkctl.py upload-tool firewall`)
- **Tipo:** ops / rollout
- **Origem:** crash-loop do v4 `listen-to-mosquitto.py` no `lb01sp` (ConnectionRefused MQTT, broker antigo morto). v5 já roda em alguns nós, mas o legado v4 não foi aposentado.

## Problema / motivação

- O **cron v4** (`server/listen-to-mosquitto.py` + `security-v4/api.py`) ainda roda em nós que já têm o v5 (`authmon-agent.service`). No `lb01sp`, v5 e v4 **coexistem** e o v4 fica em crash-loop a cada minuto (8459 erros no `/var/log/nw-monitor.log`).
- O `install.sh` do v5 **não remove** o legado v4 (apesar do comentário "Replaces v4's cron"). Comprovado: `lb01sp` tem v5 agent ativo e o cron v4 continua.
- O `jkctl.py upload-tool firewall` roda `sudo ./install.sh` **sem argumento** → sempre instala `ROLE=agent`. O `--role master|slave` só grava `config/role`, que o `install.sh` ignora (ele lê `ROLE` de `$1`, valores `agent`/`api`/`all`).
- Os **load balancers** (`lb01sp`, `lb01atl`) servem a Border API em `:8741`, da qual o **config-agent depende** (`authmon_url` → `api.zeecred.com.br:8741` / `api.zeecred.dev.br:8741`). Hoje servida pelo `api.py` v4. Migrar sem subir o `authmon-api.service` v5 derruba o acesso do config-agent ao firewall.

## Modelo alvo

- **1 master** = nó do MQTT broker (`management.zeecred.dev.br` = `mgmt01atl`) → role `api`/`all`.
- **Demais nós = slave** (role `agent`) por padrão.
- **LBs** (`lb01sp`, `lb01atl`) → precisam do `authmon-api.service` v5 (`:8741`) para o config-agent → role `api`/`all`.
- v4 totalmente aposentado (cron + processos) em todos os nós.

## Frota (`servers.json _topology_`, ~18 nós)

`sbox1, apresentacao, testes-internos, stg01, stg02, sp01, sp02, sp03, lb01sp, lb01atl, mgmt01atl, log-sp, web01sp, web01atl, atlanta01, atlanta02, db01sp, db02sp`

> Validar contra `_firewall_` em `servers.json` (lista grupos `staging, gcp-sp, sandbox`) — confirmar se TODOS os nós são alvo do firewall ou apenas esses grupos.

## Pré-requisitos (bloqueadores a resolver antes)

1. **Corrigir `jkctl.py upload-tool firewall`** para:
   - passar o role correto ao `install.sh` (`agent` padrão; `api`/`all` para master e LBs);
   - **remover o legado v4** como parte do install: tirar as linhas do crontab do root (`listen-to-mosquitto.py`, `security-v4/api.py`), parar/matar os processos v4 e o lockfile (`/var/run/auth-monitor-border-api.lock`).
2. **`AUTHMON_API_KEY`** — necessário para o role `api`. Está comentado em `.credentials/authmon.env`. Puxar de um nó que já roda o role api (`/etc/authmon/env`) e gravar no `.credentials/authmon.env` (gitignored).
3. Confirmar que o **broker MQTT** (mosquitto) está de pé em `mgmt01atl` (o v4 falhava por ConnectionRefused — garantir que o endpoint v5 `management.zeecred.dev.br` responde).

### Progresso (código/tooling — feito)

- [x] **Pré-req 1a — role correto:** `jkctl.py` (ZeeCred v1 `jk-structure`) agora mapeia
  `--role master → install.sh all` (agent + authmon-api em `:8741`, cobre broker e LBs)
  e `slave/None → install.sh agent`. Antes rodava `./install.sh` sem argumento (sempre `agent`).
- [x] **Pré-req 1b — teardown v4:** `auth-monitor/install.sh` ganhou `remove_v4_legacy()`
  (best-effort, não falha o install): limpa cron de root + `$SUDO_USER`
  (`listen-to-mosquitto.py`, `security-v4/api.py`, `7-iptables-agent.py`, `/var/log/nw-monitor.log`),
  mata os processos v4 e remove os lockfiles
  (`border-api`, `mqtt-listener`, `iptables-agent`).
- [x] **Pré-req 2 — validação AUTHMON_API_KEY:** `jkctl.py` exige `AUTHMON_API_KEY`
  em `.credentials/authmon.env` quando `--role master` (falha cedo, local, em vez de
  abortar o `install.sh` remoto). **Falta ainda preencher o valor real** (puxar de um nó api).
- [ ] **Pré-req 3 — broker MQTT:** validação operacional (não-código), pendente.

> Os passos do **Plano de rollout** abaixo (canário → agents → master → LBs) são
> operação em produção e permanecem manuais/escalonados — não automatizados aqui.

## Plano de rollout (escalonado)

1. **Tooling**: aplicar os fixes do pré-requisito 1 (+ AUTHMON_API_KEY).
2. **Canário**: 1 nó agent não crítico (ex.: `sp01`) → `upload-tool firewall` → validar: `authmon-agent` ativo, cron v4 ausente, sem erros em `/var/log/authmon/`.
3. **Agents**: demais nós slave (stg*, sp02/03, web*, db*, sandbox) em lote, validando cada um.
4. **Master**: `mgmt01atl` (role `api`/`all`) → validar broker + Border API.
5. **LBs por último, um de cada vez** (`lb01sp` depois `lb01atl`): subir `authmon-api.service` v5 (`:8741`), validar que o **config-agent** ainda fala com o firewall, e só então matar o `api.py` v4.

## Critérios de aceite

- [ ] `authmon-agent.service` ativo e sem restart em todos os nós alvo.
- [ ] **Nenhum** vestígio do v4 (cron limpo, `listen-to-mosquitto.py`/`api.py` v4 parados) em todos os nós.
- [ ] Border API `:8741` servida pelo `authmon-api.service` v5 nos LBs; config-agent comunica normalmente.
- [ ] Broker MQTT acessível; grade propaga block/unblock entre nós.
- [ ] `/var/log/nw-monitor.log` para de crescer com `Connection refused`.

## Dependências

- Idealmente coordenar com a [[001-port-allowlist-node-scope]] (a feature de allow escopado roda sobre o v5 já instalado na frota).

## Notas

- Operação em infra de segurança em produção (LBs inclusos): seguir staged/canário, validar cada passo, e manter rollback (não apagar v4 até o v5 do nó estar validado).
