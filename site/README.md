# Site da Distrópica

Página estática publicada em `https://distropica.com.br/`.

- `index.html`: página autocontida, sem JavaScript ou dependências externas;
- `distropica-social-v1.svg`: fonte editável da miniatura social;
- `distropica-social-v1.png`: miniatura Open Graph/Twitter, 1200×630;
- `nginx-bootstrap.conf`: virtual host HTTP usado somente para obter o primeiro
  certificado;
- `nginx.conf`: configuração final HTTP→HTTPS e arquivos de release.

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
