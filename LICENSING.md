# Licenciamento da Distrópica

Copyright (C) 2026 Daniel Hoisel.

## Código e documentação próprios

Salvo indicação expressa em contrário, o código, os scripts de build e
instalação, a lógica autoral das receitas, os perfis, as especificações e a
documentação produzidos para a Distrópica são licenciados sob a
**GNU General Public License, versão 3 ou qualquer versão posterior**
(`GPL-3.0-or-later`). O texto integral da versão 3 está em [LICENSE](LICENSE).
O aviso curto que acompanha os artefatos está em [NOTICE](NOTICE).

Essa concessão “ou posterior” é a que governa o conteúdo próprio mesmo que
uma ferramenta de detecção identifique o arquivo `LICENSE` apenas como GPLv3.
Versões antigas que tenham sido efetivamente disponibilizadas sob outra
licença conservam as permissões já concedidas para aquelas cópias.

## Receitas e componentes de terceiros

O campo `LICENSE=` de uma receita Newspeak descreve a licença do **payload do
pacote**, não a licença autoral do arquivo `recipe`. A implementação original
da receita pertence ao código da Distrópica e segue a regra acima; o software
que ela baixa, compila ou instala mantém a licença indicada pelo upstream.

Em particular, esta licença não relicencia Linux, BusyBox, glibc, GCC, Zig,
ripgrep, dependências Cargo nem qualquer outro componente de terceiros. Uma
ISO ou um canal da Distrópica reúne componentes sob licenças distintas, cada
um com seus próprios avisos e condições. O inventário definitivo e as
combinações efetivamente distribuídas precisam ser verificados a partir dos
insumos exatos de cada publicação.

O pacote `base`, por conter payload escrito para a própria Distrópica, passa a
declarar `GPL-3.0-or-later` nesta revisão. Cópias anteriores disponibilizadas
como `MIT-0` não perdem retroativamente essa permissão.

## Binários e fontes correspondentes

Publicar o repositório de fontes não equivale, sozinho, a publicar uma release
binária. Para cada ISO, EFI, cache ou canal distribuído pelo projeto, a
Distrópica deverá oferecer, com acesso equivalente, um conjunto de fontes
correspondentes àquele artefato. Esse conjunto deve incluir, conforme o caso:

- a revisão exata da Distrópica, os dois `Cargo.lock` e as crates vendorizadas;
- fontes upstream exatas, configurações, patches e scripts de build/instalação;
- fontes e configuração do kernel e do BusyBox presentes na mídia;
- textos de licença, avisos de copyright e um inventário legível por máquina;
- hashes que associem inequivocamente o bundle-fonte ao artefato binário.

Uma receita com URL e hash é rastreabilidade, mas não substitui a retenção
durável exigida de quem redistribui o binário. A imagem custom de
desenvolvimento `miniplenty-v2` é acompanhada por um
[bundle de fontes correspondentes](https://distropica.com.br/releases/distropica-miniplenty-v2-corresponding-sources.tar.zst),
seu [hash](https://distropica.com.br/releases/distropica-miniplenty-v2-corresponding-sources.tar.zst.sha256)
e um [inventário legível por máquina](https://distropica.com.br/releases/distropica-miniplenty-v2-sources.tsv).
Isso não promove a imagem a release oficial: o SBOM arquivo a arquivo e o
inventário conclusivo de licenças continuam sendo gates dessa futura
publicação.

Em particular, o tar binário oficial do Zig agrega sysroots, libc++, libunwind
e outras fontes auxiliares sob várias licenças. Enquanto o inventário exato
dessa composição não for gerado, sua receita declara `LICENSE=NOASSERTION` em
vez de atribuir incorretamente MIT ao bundle inteiro. Os textos upstream
continuam dentro do tar/payload; `NOASSERTION` não autoriza omiti-los.

O mesmo critério conservador vale para `gcc-pass2`: seu payload final combina o
compilador, bibliotecas cobertas pela GCC Runtime Library Exception, manuais
GFDL e componentes auxiliares sob outras licenças. Até o SBOM arquivo a arquivo
ser produzido a partir do novo artefato, a receita declara
`LICENSE=NOASSERTION`; isso não altera nenhuma licença upstream nem reduz as
obrigações de fornecer fontes, exceções e avisos correspondentes.

Quem apenas constrói ou modifica a Distrópica para uso privado não é obrigado
por esta política a publicar sua cópia. Quem redistribui binários deve cumprir
as licenças aplicáveis componente a componente.

## Marca

A GPL rege copyright do código, não concede por si só direito de apresentar
uma variante como publicação oficial da Distrópica. Isso não restringe o
direito de copiar, modificar ou redistribuir o código nos termos da GPL; apenas
evita atribuição ou endosso falsos.
