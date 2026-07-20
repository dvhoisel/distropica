# SPEC-0008 — minipax, o instalador

**Status:** rascunho v0.2 · 2026-07-18
**Depende de:** SPEC-0003 (minitrue `--root`), SPEC-0005 (estágios), SPEC-0006 (init).

O Ministério da Paz cuida da conquista de territórios novos: `minipax`
anexa um disco vazio à Distrópica.

## 1. Princípio: não existe tecnologia de instalador

Instalar = **o bootstrap apontado para um disco montado**. O minitrue já
sabe popular uma raiz alternativa (`--root`, SPEC-0003 §2) — é assim que o
Estágio 0 nasce. `minipax` é um script de shell curto (alvo: ~200 linhas
legíveis) que orquestra passos pequenos e independentes, no espírito do
`setup-alpine`:

- cada passo é um script autônomo (`minipax-disco`, `minipax-base`,
  `minipax-boot`, `minipax-config`) que pode ser rodado sozinho;
- nenhum estado escondido: tudo que o instalador decide vira arquivo
  legível no alvo (`fstab`, `/etc/hostname`, symlinks de serviço);
- sem interface gráfica, sem curses obrigatório: perguntas de texto puro
  com defaults sensatos (SPEC-0001 §4).

## 2. A mídia viva

Um pendrive FAT32 com o kernel EFI-stub como `EFI/BOOT/BOOTX64.EFI` e um
initramfs contendo: busybox, minitrue, a árvore newspeak, o minipax e as
ferramentas de disco do mundo B (`sfdisk` do util-linux, `mkfs.ext4` do
e2fsprogs, `mkfs.vfat` do dosfstools, `efibootmgr`) — nenhuma delas tem
binário upstream; são compiladas na geração da imagem.

Dois modos, mesmo código:

| Modo | Conteúdo da mídia | Fluxo |
|------|-------------------|-------|
| **online** | só o initramfs (dezenas de MB) | artefatos baixados **direto dos mantenedores** durante a instalação, verificados por hash+assinatura. O sistema não vem na mídia; a mídia é só o mandado. |
| **offline** | idem + `/var/cache/minitrue` pré-populado | `minitrue --offline` instala do cache; zero rede. |

A imagem da mídia é gerada por script do projeto (`mkmedia`, futuro) e
DEVERIA ser publicada com assinatura minisign da chave do projeto.

## 3. Sequência de instalação

1. **`minipax-disco`** — particionamento GPT com layout fixo por default
   (script sfdisk embutido, visível ao usuário antes de aplicar):
   - ESP: 512 MB, FAT32, label `DTP-ESP`;
   - raiz: restante, ext4, **label `distropica-root`**;
   - modo `--manual` aceita partições pré-existentes indicadas pelo usuário.
2. **`minipax-base`** — monta o alvo em `/mnt` e roda
   `minitrue --root /mnt rectify base`, onde `base` é a meta-receita do
   conjunto mínimo (busybox, minitrue, runit, kernel, doas, tzdata…;
   composição exata definida na árvore newspeak, não no instalador).
   Os pacotes do mundo B da `base` (glibc, gcc…) resolvem-se por **binário
   de canal** (SPEC-0009), não por compilação — é o que garante que o
   usuário **não compila a base** ao instalar.
   Esqueleto FHS e usr-merge conforme SPEC-0002. Grava o
   `/etc/minitrue/world` inicial (conjunto `base` + escolhas do usuário);
   `minipax --world <arquivo>` reinstala uma máquina inteira a partir de
   um world salvo (SPEC-0003 §2).
3. **`minipax-boot`** — copia kernel+initramfs para a ESP como
   `EFI/BOOT/BOOTX64.EFI` (caminho de fallback UEFI) e, quando a NVRAM é
   gravável, cria a entrada "Distrópica" via `efibootmgr`. **Não há
   bootloader** (§4).
4. **`minipax-config`** — hostname, senha de root, usuário inicial +
   `doas`, fuso (tzdata), rede (`udhcpc` ou estática → rc simples,
   SPEC-0006 §3), serviços habilitados por symlink (SPEC-0006 §4), `fstab`
   por **LABEL**.
5. Despedida: relatório do que foi escrito e onde (uma tela), `reboot`.

## 4. Boot sem bootloader

- Kernel compilado com `CONFIG_EFI_STUB`: o firmware UEFI executa o kernel
  diretamente. Sem GRUB (fonte GNU pesada, contra P3/P4), sem systemd-boot
  (banido por P4).
- **Nenhuma linha de comando de kernel é necessária**: o initramfs (o
  mesmo script de uma tela do E3, SPEC-0005 §5) localiza a raiz por
  `LABEL=distropica-root` e faz `switch_root`. A instalação fica idêntica
  em qualquer máquina — nada de `root=/dev/sdX` gravado em lugar nenhum.
- **Kernel anterior sempre bootável** (o A/B do ChromeOS, em versão
  simplificada): a ESP mantém o kernel corrente em `EFI/BOOT/BOOTX64.EFI`
  e o anterior em `EFI/distropica/anterior.efi`, com entrada NVRAM
  "Distrópica (anterior)" quando gravável. O `rectify` do pacote `linux`
  rotaciona os dois — a retenção corrente+1 (SPEC-0003 §5) estendida ao
  boot. Kernel novo que não inicia → escolher a entrada anterior no
  gerenciador do próprio firmware; nenhum menu próprio, nenhum timeout.
- Alvo v0: **UEFI x86_64 apenas**. BIOS legado fica fora (questão em
  aberto §7); Secure Boot fora (SPEC-0001 §4) — a mídia documenta como
  desativá-lo.

## 5. O que o minipax NÃO faz (v0)

- LUKS/LVM/RAID (LUKS é o candidato mais forte a v0.2 — cryptsetup é
  mundo B);
- btrfs/zfs/xfs — ext4 apenas;
- dual-boot assistido: não toca em entradas EFI alheias nem redimensiona
  partições; coexistência é responsabilidade do usuário em `--manual`;
- detecção de hardware além do que o kernel genérico + mdev enxergam;
- qualquer coisa gráfica.

## 6. Critérios de aceite

- QEMU/OVMF: mídia online instala em disco virgem e o sistema instalado
  dá boot até o getty com `minitrue verify` limpo, **sem** a mídia.
- Mesmo teste em um hardware UEFI real do projeto.
- Modo offline: instalação completa com rede fisicamente desligada.
- `minipax-boot` rodado isolado num sistema já instalado restaura o boot
  (serve de rescue).
- Após um `rectify linux`, a entrada "Distrópica (anterior)" inicia o
  kernel antigo.

## 7. Questões em aberto

- BIOS legado: existe demanda real? (limine? syslinux? ambos fonte;
  decisão só se aparecer hardware que justifique).
- LUKS no v0.2: initramfs precisaria de cryptsetup estático e prompt de
  senha — dimensionar.
- A meta-receita `base`: composição exata (entra `zig`? entra `git`?) —
  decidir na árvore newspeak com `ABOUT` justificando cada inclusão.
- `minipax` instalado no alvo por padrão (para reuso como rescue) ou só na
  mídia? Tendência: só na mídia; `minipax-boot` vira exceção instalável.
- Assinatura Secure Boot própria (shim/MOK): provavelmente nunca —
  registrar a recusa e o porquê numa nota.
