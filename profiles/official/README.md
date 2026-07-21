# Perfil oficial (em desenvolvimento)

Este diretório é a entrada canônica do futuro release. Enquanto `STATUS` no
arquivo `profile` for `development`, o `minipax` rotula toda saída como
desenvolvimento — nunca como oficial.

`live.world` descreve o ambiente incorporado no `BOOTX64.EFI` da mídia;
`target.world` descreve o sistema instalado. A árvore Newspeak, eventual
overlay e cache entram no `profile.lock` por hash.

`INSTALL_READY=no` faz a instalação direta recusar antes de tocar no target:
o world oficial ainda não consegue obter uma toolchain/base completa num alvo
vazio. A geração estrutural de mídia e a inspeção do lock continuam disponíveis.

O perfil ainda não fecha uma instalação de release: faltam canais binários,
runit, gestão de contas e o kernel EFI com initramfs do instalador incorporado.
Esses gates são intencionais e documentados; o builder não inventa um artefato
bootável na ausência deles.
