# Site da Distrópica

Página estática publicada em `https://distropica.com.br/`.

- `index.html`: página autocontida, sem JavaScript ou dependências externas;
- `nginx-bootstrap.conf`: virtual host HTTP usado somente para obter o primeiro
  certificado;
- `nginx.conf`: configuração final HTTP→HTTPS e arquivos de release.

O diretório remoto é `/var/www/distropica.com.br`. ISOs e sidecars ficam em
`/var/www/distropica.com.br/releases/`, junto dos bundles de fontes
correspondentes e seus inventários. O certificado Let's Encrypt usa o webroot
desse mesmo virtual host.
