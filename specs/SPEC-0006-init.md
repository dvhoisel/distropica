# SPEC-0006 — Init e serviços (sem systemd)

**Status:** rascunho v0.1 · 2026-07-18
**Premissa-mãe:** P4 — devolver a simplicidade ao usuário (SPEC-0001).

## 1. Princípio

O PID1 e tudo ao redor dele DEVEM caber na cabeça de uma pessoa:

- proibidos: systemd e satélites (journald, logind, timers, udevd do
  systemd), e dbus como requisito de qualquer função básica;
- todo o ciclo de boot DEVE ser legível de ponta a ponta em minutos:
  scripts curtos, texto puro, sem estado binário;
- logs são arquivos de texto; o leitor de logs é `grep`.

## 2. Fase A — chroot (Estágios 0–2)

Sem init. O chroot é habitado por `sh` interativo. Nenhum serviço.

## 3. Fase B — primeiro boot (Estágio 3 inicial)

`busybox init` com `/etc/inittab` mínimo e literal:

```
::sysinit:/etc/rc.d/rcS
tty1::respawn:/sbin/getty 38400 tty1
tty2::respawn:/sbin/getty 38400 tty2
::ctrlaltdel:/sbin/reboot
::shutdown:/etc/rc.d/rcK
```

`/etc/rc.d/rcS` (shell, ~20 linhas, sem abstrações):

- `mount -a` (`proc`, `sysfs`, `devtmpfs`, `tmpfs /run`, `tmpfs /tmp`);
- `mdev -s` (dispositivos; busybox);
- hostname, loopback up;
- rede simples: `udhcpc` (busybox) quando configurado.

## 4. Fase C — alvo: runit como PID1

Escolha: **runit** (fonte minúscula, três binários centrais —
`runit`, `runsv`, `runsvdir` —, semântica de supervisão óbvia, documentação
de uma página por ferramenta; compila em segundos com `zig cc` ou gcc).

Estrutura:

- `/etc/runit/1` — inicialização única (equivale ao rcS da fase B);
- `/etc/runit/2` — `exec runsvdir /run/service`;
- `/etc/runit/3` — desligamento ordenado.

Serviços:

- definição: `/etc/sv/<nome>/run` (+ `finish` opcional, + `log/run`);
- habilitação **estática e declarativa**: symlink em `/etc/runit/enabled/`
  (vive em `/etc`, coerente com FHS — configuração local);
- em boot, o estágio 2 materializa `/run/service/<nome>` a partir de
  `enabled/` e o `runsvdir` supervisiona dali (`/run` é o lugar FHS de
  runtime — SPEC-0002 §6);
- controle: `sv up|down|status <nome>`.

Logging: `svlogd` por serviço, em `/var/log/sv/<nome>/current` — texto,
rotacionado pelo próprio svlogd. Sem journal binário.

## 5. Dispositivos e assentos

- Fase B/C inicial: `mdev` (busybox).
- `eudev` (fonte) só se/quando o Estágio 4b exigir hotplug de verdade;
  `seatd` (fonte, pequeno) como gestor de assento para Wayland — ambos
  decisão adiada para a spec do 4b.
- `sudo` não é base: `doas` (fonte pequena) DEVERIA ser o elevador de
  privilégio padrão. Receita no mundo B.

## 6. O que a Distrópica promete ao usuário

1. `cat /etc/inittab` (ou `ls /etc/sv`) responde "o que roda no boot?".
2. Nenhum serviço nasce habilitado sem symlink explícito em `enabled/`.
3. Desabilitar = remover um symlink. Sempre.
4. Nenhum log exige ferramenta especial para ser lido.
5. O boot inteiro — do kernel ao getty — é auditável em uma sessão de
   leitura.

## 7. Questões em aberto

- s6 no lugar de runit (readiness notification e dependências entre
  serviços são melhores; custo: mais peças e mais conceitos): decisão
  v0 = runit; revisitar se surgirem serviços com ordenação complexa.
- Relógio/cron: `busybox crond` basta no v0? (provável sim).
- `elogind` NUNCA, mas alternativa para apps que exigem logind DBus no 4b
  (Firefox roda sem; decidir política para os que não rodam).
- Shutdown ordenado de serviços com dependentes (runit não ordena): aceitar
  ou script em `/etc/runit/3`.
