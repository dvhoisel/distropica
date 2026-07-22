# Perfil oficial (em desenvolvimento)

Este diretório é a entrada canônica do futuro release. Enquanto `STATUS` no
arquivo `profile` for `development`, o `minipax` rotula a resolução sem
overrides como `development`; qualquer override aplicável vira `custom`.
Nenhuma delas é oficial.

`live.world` descreve o ambiente incorporado no `BOOTX64.EFI` da mídia;
`target.world` descreve o sistema instalado. A árvore Newspeak, o overlay e o
cache entram no `profile.lock` por hash.

Quando o canal oficial existir, seu bootstrap versionado poderá viver em
`channel-bootstrap/`, com `channel-config/<nome>` e
`channels/<nome>/{index,index.minisig}`. Esse diretório é autodetectado,
entra em `CACHE_SHA256` e é semeado antes do primeiro `rectify`. Ele não existe
hoje porque endpoint e chave ainda não foram publicados; valores fictícios
tornariam uma mídia online aparentemente pronta, mas inoperante.

`INSTALL_READY=yes` declara que o world mínimo (`base` + `linux`, com BusyBox
como dependência) pode ser materializado num alvo vazio. O caminho validado
neste marco usa um cache de desenvolvimento com índice minisign e
`--offline --only-binary`; ele não compila a toolchain E2 no computador do
usuário. Esse cache e sua chave de assinatura ainda não são artefatos oficiais
publicados pelo projeto. Passá-lo por `--cache` é um override explícito e
classifica esse build como `custom`; um futuro `channel-bootstrap/` versionado
preservará `development` até o perfil ser promovido com os pinos de release.

O overlay fornece o estado mínimo de contas e boot: conta root inicialmente
bloqueada, `fstab`, `securetty`, `passwd` e `group`. A mídia viva pede uma senha
de root antes do primeiro boot; o modo automatizado de teste conserva a conta
bloqueada. Ao congelar as árvores, o Minipax aplica modos canônicos independentes
do Git: diretórios `0755`, `root/` do overlay `0700`, `shadow`/`gshadow` e seus
backups `0600`, executáveis `0755` e demais regulares `0644`.

`bootstrap/live/build-efi` implementa o kernel EFI-stub com initramfs do
instalador, e `minipax media build` compõe localmente IMG ou ISO a partir dele.
Antes de sequer pedir o disco, o initramfs materializa a closure em `/run`,
configura a conta, valida o root preparado e usa
`install-media --export-boot-efi` para capturar o EFI já conferido. Só depois
autoriza e particiona o disco, copia o root, executa `minitrue verify`, instala o
snapshot EFI e publica por último o marcador `disk-install.complete`.

Há duas classes de artefato vivo que não podem ser confundidas:

- A **ISO interativa de desenvolvimento**, construída sem
  `--install-device`, é o caminho humano e o candidato técnico à futura mídia
  oficial. Ela pede senha, valida todo o payload antes de oferecer o disco e
  exige que a pessoa digite o dispositivo inteiro a apagar. Hoje continua
  `development`/`custom`: não é uma release oficial.
- A **ISO automatizada destrutiva do aceite QEMU**, construída com
  `--install-device /dev/vda`, incorpora autorização para apagar esse disco e
  `distropica.test=1`. Ela serve somente à VM raw descartável criada por
  `bootstrap/live/accept-qemu`; **nunca deve ser distribuída, publicada nem
  usada em hardware real**.

A variante interativa pode ser aceita com:

```sh
bootstrap/live/accept-virtualbox \
  --iso target/distropica.iso \
  --run-dir target/acceptance-virtualbox
```

O runner cria uma VM efêmera sem rede, com UEFI64, VMSVGA e SATA/AHCI. O VDI é
`/dev/sda` no guest. Com o payload já validado em RAM, a ISO é ejetada antes da
autorização do wipe; o próprio instalador reinicia pelo VDI, e o runner verifica
o segundo boot sem ISO e o login de root. Esse fluxo passou em 2026-07-21 no
VirtualBox `7.2.6_Ubuntur172322`; duas composições a partir dos mesmos insumos
produziram ISO byte a byte idêntica:

```text
EVIDENCIA_VIRTUALBOX_INTERATIVA=local-development
ACCEPTANCE_META=target/vbox-acceptance-interactive-v4/evidence/acceptance.meta
VBOX_VERSION=7.2.6_Ubuntur172322
FIRMWARE=efi64
GRAPHICS=vmsvga
STORAGE=IntelAhci
GUEST_DISK=/dev/sda
ISO_SHA256=183a25211175577408e7e21ef960db720b6c6c2fa99face5d0eb1cf71834e426
REPEATED_ISO_SHA256=183a25211175577408e7e21ef960db720b6c6c2fa99face5d0eb1cf71834e426
BOOT_EFI_SHA256=a07b369e6d666e4ff9bb7bb6bba3eda763852a43d31e14971e77908280ebfa3b
RUN_STATE=passed
ISO_EJECTED_BEFORE_WIPE=yes
SECOND_BOOT_WITHOUT_ISO=yes
ROOT_LOGIN=yes
FINAL_RESULT=passed
```

O aceite automatizado final-v10, preservado como evidência separada, passou em
QEMU/OVMF sem NIC: instalou em disco vazio, iniciou o disco sem a ISO e recusou
uma variante cujo `profile.lock` não correspondia ao hash de `media.meta` antes
de qualquer wipe. Duas composições locais dessa ISO de teste também foram byte
a byte idênticas:

```text
EVIDENCIA_FINAL_V10=local-development
ACCEPTANCE_META=target/qemu-acceptance-final-v10/acceptance.meta
RUN_STATE=completed
NETWORK=none
ISO_SHA256=c48b43674ad17d9993862c8ce0fbb8dae4ec4622be35d1d07c750d6ee2e7dae8
REPEATED_ISO_SHA256=c48b43674ad17d9993862c8ce0fbb8dae4ec4622be35d1d07c750d6ee2e7dae8
BOOT_EFI_SHA256=c8a884845aa1568c4e51756f2a26c1b21652969367957387c5efdfb616e3204c
CORRUPT_DISK_SHA256=a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484
ZERO_256_MIB_SHA256=a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484
RESULT=pass
INCONSISTENT_PROFILE_LOCK_RESULT=refused-before-wipe
```

Isso continua sendo desenvolvimento: os manifestos registraram
`PROFILE_CLASS=custom` e `MEDIA_CLASS=custom`; essa evidência não é
pino oficial e igualdade local não provará reprodução entre builders. O kernel
vivo cobre sobretudo o hardware virtual testado e o EFI contém
kernel+initramfs embutidos. `CONFIG_MODULES=y` permanece habilitado, mas a
mídia não contém `.ko`: os drivers do instalador são built-in. O sufixo
`-distropica-live` separa seu release do `7.1.4` instalado e evita que a busca
automática use `/lib/modules/7.1.4` do target. O EFI ainda não acompanha
automaticamente atualizações de `/boot/vmlinuz-*`.

Para virar release faltam, entre outros, endpoint e chave do canal oficial,
bundle estático assinado, pinos oficiais do perfil/EFI/Minitrue, manifesto
externo assinado, runit, política final de contas e uid/gid, atualização
atômica do EFI e testes em hardware real. Também faltam `channel refresh`
auditável, Journal integralmente fd-relative contra TOCTOU e streaming: durante
o consumo binário, o `.tar.zst` selado e o tar descompactado coexistem em RAM, e
o instalador vivo ainda mantém a raiz pré-validada em `/run` até concluir a
cópia segura para o disco.
