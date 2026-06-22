# 001 — Port-allowlist com escopo por nó (abrir IP→porta em um único servidor da frota)

- **Status:** done
- **Componente:** authmon v5 (api, agent, authmon/state, authmon/firewall, authmon/events)
- **Tipo:** feature
- **Origem:** necessidade operacional ZeeCred — liberar um IP para uma porta específica em **apenas um** servidor da frota (não na grade inteira).

## Problema

Hoje a Border API (`api/api.py`) trata o port-allowlist de forma **não escopada e não propagada**:

- `POST /v5/port-allowlist` (`port_allowlist_add`) chama `state.port_allowlist_add(...)` e `FIREWALL.allow_port(ip, port, protocol)` **apenas no nó da API** (broker). Diferente de `block`/`unblock`/`allowlist_add`, **não** emite evento MQTT (`make_event` + `_publish_or_503`), então a regra nunca chega aos outros nós.
- A tabela `port_allowlist` (`authmon/state.py`) não tem coluna de nó-alvo:
  ```
  port_allowlist(id, ip, port, protocol, reason, created_at, created_by, UNIQUE(ip,port,protocol))
  ```

Resultado: **não há como abrir `ip:port/proto` em um servidor específico da frota**. Só dá para aplicar localmente no broker, sem direcionamento.

## Requisito

Permitir um allow de `ip:port/proto` **escopado a um `node_id` específico** (um único servidor), propagado pela grade MQTT, de modo que **apenas o nó-alvo** aplique a regra de iptables; os demais ignoram. Deve persistir reboot (reconciliação) e ser removível pelo mesmo escopo.

## Escopo técnico (esboço)

1. **Schema (`authmon/state.py`):** adicionar `target_node TEXT NOT NULL` à tabela `port_allowlist`; ajustar a UNIQUE para `UNIQUE(target_node, ip, port, protocol)`; migração idempotente (`ALTER TABLE ... ADD COLUMN` com guarda). Índice por `target_node`.
2. **Modelo API (`api/api.py`):** adicionar `target_node: str` em `PortAllowlistRequest` (validar contra os `node_id` conhecidos da grade; aceitar sentinela `"*"`/`all` para fleet-wide, preservando o comportamento atual como caso especial).
3. **Propagação:** `port_allowlist_add` deve emitir `make_event("port_allow_add", CFG["node_id"], ip=..., port=..., protocol=..., target_node=...)` e `_publish_or_503(event)` — igual ao fluxo de `block`. Idem `port_allow_remove` no DELETE.
4. **Aplicação no agente (`agent/agent.py`):** ao consumir `port_allow_add`/`port_allow_remove`, aplicar `FIREWALL.allow_port` / `deny_port` **somente se** `event["target_node"] == CFG["node_id"]` (ou `target_node in ("*","all")`). Caso contrário, persistir no state (para auditoria/reconcile) mas não aplicar iptables.
5. **Reconciliação (`authmon/firewall.py::reconcile_port_allowlist`):** filtrar as entradas do state pelo `node_id` local antes de reconciliar, respeitando o escopo.
6. **Endpoints GET/DELETE:** `GET /v5/port-allowlist` com filtro opcional `?node=`; `DELETE /v5/port-allowlist/{ip}/{port}/{protocol}` deve aceitar/derivar o `target_node` (rota ou query) para remover só no alvo.

## Critérios de aceite

- [x] Um allow scoped (`target_node=X`) aplica a regra de iptables **apenas** no nó X; demais nós não abrem a porta.
- [x] O allow persiste reboot do nó-alvo (reconciliação reaplica respeitando o escopo).
- [x] DELETE escopado remove a regra só no nó-alvo.
- [x] Compatibilidade: `target_node="*"` reproduz o comportamento fleet-wide (e o caso atual local-no-broker continua possível).
- [x] Eventos `port_allow_add`/`port_allow_remove` são assinados e propagados via MQTT como os demais.
- [x] Documentado na referência da API v5.

## Notas

- Reaproveitar o padrão de evento assinado de `block`/`unblock` (`events.make_event` + `BUS.publish_signed` via `_publish_or_503`).
- `FIREWALL.allow_port`/`deny_port`/`reconcile_port_allowlist` já existem em `authmon/firewall.py` — a mudança é de **escopo/propagação**, não de enforcement de baixo nível.
