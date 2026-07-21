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

O aceite final-v10 passou em QEMU/OVMF sem NIC: instalou em disco vazio, iniciou
o disco sem a ISO e recusou uma variante cujo `profile.lock` não correspondia
ao hash de `media.meta` antes de qualquer wipe. Duas composições locais da ISO
foram byte a byte idênticas:

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
