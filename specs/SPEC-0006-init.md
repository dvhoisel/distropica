# SPEC-0006 — Init e serviços (sem systemd)

**Status:** rascunho v0.2 · 2026-07-21
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
ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100
tty1::respawn:/sbin/getty 38400 tty1
::ctrlaltdel:/sbin/reboot
::shutdown:/etc/rc.d/rcK
```

`/etc/rc.d/rcS` permanece um shell curto, sem abstrações:

- monta explicitamente `proc`, `sysfs`, `devtmpfs`, `tmpfs /run` e
  `tmpfs /tmp`;
- `mdev -s` (dispositivos; busybox);
- hostname, loopback up;
- para cada interface diferente de `lo`, tenta subir o link e obter uma
  configuração IPv4 com `udhcpc` (busybox);
- falha de link ou DHCP é registrada, mas NÃO impede a continuação do boot nem
  a chegada ao getty.

O script chamado pelo `udhcpc` valida a interface e todos os valores IPv4 antes
de aplicá-los. Um lease aceito configura o endereço e, quando fornecida, a
máscara; substitui a rota default por um gateway válido, quando fornecido, e só
publica servidores DNS que também sejam IPv4 válidos. O novo `/etc/resolv.conf`
é preparado no próprio diretório `/etc` e promovido por `rename`, evitando uma
cópia parcial entre filesystems distintos.

A base 0.2 instala esse script em `/etc/udhcpc/default.script`. O instalador
vivo precisa da mesma política antes de existir um sistema-alvo e o incorpora
em `/usr/share/udhcpc/default.script`. Ambos vêm da única fonte versionada
`newspeak/base/files/udhcpc.script`; corrigir a política de lease não deve criar
duas implementações divergentes.

A mesma receita fornece `/etc/motd` com a identidade de desenvolvimento e uma
referência curta aos comandos `minitrue archives`, `minitrue verify` e
`minitrue rectify <pacote>`. O MOTD é orientação local, não um serviço nem uma
fonte de estado do sistema.

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
2. Na Fase C, nenhum serviço supervisionado nasce habilitado sem symlink
   explícito em `enabled/`; as ações únicas da Fase B permanecem visíveis em
   `/etc/rc.d/rcS`.
3. Desabilitar um serviço supervisionado = remover um symlink. Sempre.
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
