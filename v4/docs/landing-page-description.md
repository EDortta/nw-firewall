# auth-monitor v4 — Descrição para landing page

---

## Conceito central

Firewalls tradicionais protegem servidores individualmente. Se um atacante sonda o servidor A e é detectado, o servidor B não sabe nada. O atacante simplesmente muda de alvo.

O auth-monitor v4 funciona de forma diferente — e é aqui que a analogia com o **Artigo 5 da OTAN** deixa de ser metáfora e passa a ser arquitetura: **um ataque contra um nó é tratado como um ataque contra toda a rede.** No instante em que qualquer servidor detecta uma ameaça, todos os outros servidores da rede bloqueiam aquele IP simultaneamente, antes mesmo que o atacante tente o próximo alvo.

---

## O problema que resolve

Infraestruturas distribuídas são naturalmente vulneráveis a reconhecimento silencioso. Um scanner inteligente não satura um único servidor — ele rotaciona entre dezenas de endpoints, colhendo informações antes de atacar de verdade. Cada servidor vê apenas uma fração do comportamento malicioso, abaixo de qualquer limiar individual de alerta.

O auth-monitor elimina esse ponto cego ao unificar a inteligência de ameaças de todos os nós em tempo real.

---

## Como funciona

**Detecção em camadas**
Cada servidor monitora continuamente seus próprios logs — nginx e SSH — em busca de padrões de ataque:

- **Bloqueio imediato:** qualquer requisição a caminhos zero-tolerância (`.env`, `.git/config`, `wp-config.php`, exploits conhecidos como CVE-2021-41773) resulta em bloqueio instantâneo, sem acumulação de pontos.
- **Detecção por volume:** bursts de HTTP 404, tentativas de autenticação SSH inválida, probing de caminhos de alto risco — cada sinal tem peso e janela temporal. Quando a pontuação acumulada ultrapassa o limiar, o bloqueio é acionado.
- **Reconhecimento de scanners:** user-agents conhecidos (Shodan, Zgrab, Masscan, SQLmap) e padrões de path traversal são identificados diretamente.

**Propagação coletiva**
Ao detectar uma ameaça, o nó publica um evento assinado criptograficamente (HMAC-SHA256) via broker MQTT. Em segundos, todos os outros servidores da rede recebem o evento, validam a assinatura e aplicam a regra de bloqueio via iptables — sem intervenção humana, sem janela de exposição.

**Defesa mútua verificável**
Cada evento carrega identidade do emissor, IP alvo, motivo e timestamp. A rede inteira tem rastreabilidade completa de quem bloqueou o quê e por quê.

---

## O que o atacante encontra

Um scanner que compromete credenciais em um servidor de banco de dados é bloqueado automaticamente nos servidores de aplicação, nos load balancers e nos servidores de log — antes de fazer uma única requisição a qualquer deles. A rede reage como um organismo, não como uma coleção de máquinas independentes.

---

## Características técnicas

| | |
|---|---|
| **Propagação** | MQTT com QoS 1 (entrega garantida), assinatura HMAC-SHA256 por evento |
| **Tempo de resposta** | Segundos entre detecção e bloqueio em todos os nós |
| **Camada de bloqueio** | iptables / ip6tables (kernel-level, antes de qualquer processo de aplicação) |
| **Detecção** | Nginx access logs + SSH auth logs, varredura contínua |
| **Whitelist** | Gerenciamento centralizado propagado via MQTT para toda a rede |
| **Auditoria** | Log estruturado de cada evento com emissor, IP, motivo e timestamp |
| **Operação** | Autônomo — sem painel, sem agente central de decisão |

---

## A diferença filosófica

A maioria das soluções de segurança perimetral pergunta: *"esse tráfego parece ruim para mim?"*

O auth-monitor pergunta: *"alguém na rede já viu esse IP se comportar mal?"*

É defesa coletiva. É o Artigo 5 — de verdade.
