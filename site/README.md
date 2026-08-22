# Site da Distrópica

Página estática publicada em `https://distropica.com.br/`.

- `index.html`: página autocontida, sem JavaScript ou dependências externas;
- `logo.png`: arte original do logo, 1774×887, fundo preto chapado;
- `distropica-logo-grande-v1.png`: logo do título, 1280×341, fundo transparente;
- `distropica-logo-v1.png`: logo do cabeçalho, 315×84;
- `distropica-icone-v1.png`: só a marca, 180×180, para `apple-touch-icon`;
- `favicon.ico`: 16, 32 e 48 px no mesmo arquivo;
- `distropica-social-v1.svg`: fonte editável da miniatura social;
- `distropica-social-v1.png`: miniatura Open Graph/Twitter, 1200×630;
- `nginx-bootstrap.conf`: virtual host HTTP usado somente para obter o primeiro
  certificado;
- `nginx.conf`: configuração final HTTP→HTTPS e arquivos de release.

## Publicação

A fonte é **este diretório**, e não a cópia no servidor. Publicar é um comando:

```sh
site/publicar
```

Ele recusa árvore suja (publicar o que não está commitado é publicar o que
ninguém pode auditar depois), valida o HTML antes de subir, guarda o
`index.html` anterior como `index.html.before-<data>-<revisão>` e, no fim,
confere o sha256 de cada arquivo **no ar** contra o do repositório — a prova é
o que está publicado, não o que o transporte disse ter enviado.

Editar direto no servidor cria duas fontes do mesmo fato, e já criou: em
2026-08-22 a página do ar e a do repositório discordaram por algumas horas.
Se acontecer de novo, o caminho de volta é `scp` do servidor para cá,
conferir o diff e commitar.

O diretório remoto é `/var/www/distropica.com.br`. ISOs e sidecars ficam em
`/var/www/distropica.com.br/releases/`, junto dos bundles de fontes
correspondentes e seus inventários. O certificado Let's Encrypt usa o webroot
desse mesmo virtual host.

## Reprodução da miniatura

O SVG é a fonte; o PNG é o artefato pinado. O render é determinístico —
execuções repetidas produzem bytes iguais:

```sh
inkscape --export-type=png --export-width=1200 --export-height=630 \
  --export-filename=distropica-social-v1.png distropica-social-v1.svg
```

Conferido com Inkscape 1.4.3 e as famílias Liberation/DejaVu declaradas no SVG;
sem essas fontes o traçado muda. O PNG publicado tem exatamente os mesmos
pixels desse render (`magick compare -metric AE` = 0), mas não os mesmos bytes:
ele foi reempacotado sem os chunks `pHYs` e `tEXt`. A reprodução daqui é,
portanto, por pixel; o pino de bytes vale para o artefato publicado:

```text
distropica-social-v1.png  1200×630
sha256  95e1571818b8eb25ae474e004e35e9c2a8ffe506e9e374b8ecdedaca9578b7ea
```

## Reprodução do logo e do favicon

`logo.png` é a fonte; os quatro arquivos abaixo derivam dela por comando, e não
à mão. Duas transformações valem explicação.

**O fundo vira transparente.** A arte tem preto chapado `#070808`, e o papel do
site é `#10100f` com uma grade de 1 px por cima. Um retângulo quase-preto sobre
esse fundo aparece como remendo, e some com a grade onde ele passa. Com alfa, o
logo assenta sobre qualquer um dos dois.

**A paleta cai para 64 cores.** A arte é chapada, mas o render trouxe ruído
suave; sem quantizar, o logo do título pesa 126 KB. Com 64 cores ele pesa 17 KB
e fica indistinguível no tamanho em que é exibido — conferido lado a lado.

```sh
# recorte da margem + fundo transparente, uma vez
magick logo.png -bordercolor '#070808' -border 1 -fuzz 6% -trim +repage \
  -fuzz 14% -transparent '#070808' -strip PNG32:trim.png

magick trim.png -resize 1280x -colors 64 -strip PNG8:distropica-logo-grande-v1.png
magick trim.png -resize x84   -colors 64 -strip PNG8:distropica-logo-v1.png

# o ícone é o quadrado da esquerda da arte recortada
magick logo.png -bordercolor '#070808' -border 1 -fuzz 6% -trim +repage \
  -crop 371x371+0+0 +repage -fuzz 14% -transparent '#070808' \
  -resize 180x180 -colors 64 -strip PNG8:distropica-icone-v1.png

optipng -o5 distropica-logo-grande-v1.png distropica-logo-v1.png \
            distropica-icone-v1.png
```

O `favicon.ico` NÃO sai de um `auto-resize`. O 16 px gerado assim vira borrão:
as quatro linhas do documento, o prompt e o círculo não cabem em 16 pixels e
viram uma mancha cinza. O menor tamanho é gerado à parte, com a margem
raspada — o traço fica proporcionalmente mais grosso — e com realce:

```sh
magick distropica-icone-v1.png -shave 10x10 +repage -resize 16x16 \
  -unsharp 0x1+1.8+0 PNG32:ico16.png
magick distropica-icone-v1.png -resize 32x32 -unsharp 0x1+0.8+0 PNG32:ico32.png
magick distropica-icone-v1.png -resize 48x48 PNG32:ico48.png
magick ico16.png ico32.png ico48.png favicon.ico
```

Artefatos publicados:

```text
logo.png                       1774×887   sha256 6259ab1dc28ebb163be26a442ace0ceb980e58e97a5da82eb3fc4ed42837b66c
distropica-logo-grande-v1.png  1280×341   sha256 9c069237189c249e2026f6068c63c5ce5279ff64d098c0a78a1ca0e956cd8973
distropica-logo-v1.png          315×84    sha256 aba9962ded4513bd8045ac2a1f197f2524757357cd6ba916315951a253a04070
distropica-icone-v1.png         180×180   sha256 796a5240429279b7e303b8e91e928eb1e7d29488b2d8aff11acfc584dd4ffbac
favicon.ico                     16/32/48  sha256 31e6c234e44ad859015d96f12438b8fe6a07cd9134570135ea14c3bb816a38fe
```
