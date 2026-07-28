//! Assinatura minisign da própria árvore (SPEC-0009 §4).
//!
//! O consumidor de canal já exigia minisign, mas o produtor dependia do
//! binário `minisign` do HOSPEDEIRO — e a Distrópica não depende de
//! hospedeiro. Pedir `apt install minisign` para assinar a raiz de confiança
//! do canal é exatamente a inversão que este projeto recusa: a autoridade
//! sobre o que é publicado passaria a vir de um pacote que a máquina do
//! mantenedor por acaso tinha.
//!
//! Nada aqui é criptografia nova. O formato já era conhecido pela árvore — os
//! testes de `channel.rs` construíam assinaturas minisign à mão para provar o
//! verificador —, e a ed25519-dalek já estava presente por causa das
//! attestations. Isto apenas torna produtor e consumidor simétricos.
//!
//! Formato (o mesmo do minisign 0.x, variante pré-hasheada `ED`):
//!
//! ```text
//! chave secreta (158 bytes, base64 na segunda linha):
//!   [0..2]    algoritmo de assinatura  "Ed"
//!   [2..4]    algoritmo de KDF         0x0000 = sem senha; "Sc" = scrypt
//!   [4..6]    algoritmo de checksum    "B2"
//!   [6..38]   sal do KDF
//!   [38..46]  opslimit (u64 LE)
//!   [46..54]  memlimit (u64 LE)
//!   [54..62]  key_id
//!   [62..126] chave secreta ed25519 (semente ‖ pública)
//!   [126..158] checksum BLAKE2b-256 de (algoritmo ‖ key_id ‖ secreta)
//!
//! chave pública (42 bytes): "Ed" ‖ key_id ‖ pública
//!
//! assinatura:
//!   untrusted comment: <comentário>
//!   base64("ED" ‖ key_id ‖ sign(BLAKE2b-512(mensagem)))
//!   trusted comment: <comentário confiável>
//!   base64(sign(assinatura ‖ comentário confiável))
//! ```
//!
//! O comentário confiável entra na segunda assinatura; é isso que o torna
//! confiável, e é por isso que o timestamp vai ali e não no primeiro.

use crate::Fail;
use anyhow::Result;
use base64::Engine;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest};
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Erro de saída 1, no formato que o `main` já traduz em mensagem e código.
fn erro(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Fail {
        code: 1,
        msg: msg.into(),
    })
}

const SECRET_LEN: usize = 158;
const PUBLIC_LEN: usize = 42;
const LEGACY_ALGORITHM: &[u8; 2] = b"Ed";
const PREHASHED_ALGORITHM: &[u8; 2] = b"ED";
const CHECKSUM_ALGORITHM: &[u8; 2] = b"B2";
const UNTRUSTED_PREFIX: &str = "untrusted comment: ";
const TRUSTED_PREFIX: &str = "trusted comment: ";

type Blake2b256 = Blake2b<U32>;

fn base64_decode(line: &str, what: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(line.trim())
        .map_err(|error| erro(format!("{what}: base64 inválido: {error}")))
}

fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Segunda linha de um arquivo minisign: a primeira é sempre comentário.
fn payload_line(text: &str, what: &str) -> Result<String> {
    let mut lines = text.lines();
    let first = lines
        .next()
        .ok_or_else(|| erro(format!("{what}: arquivo vazio")))?;
    if !first.starts_with(UNTRUSTED_PREFIX) {
        return Err(erro(format!("{what}: falta a linha 'untrusted comment:'")));
    }
    let payload = lines
        .next()
        .ok_or_else(|| erro(format!("{what}: falta a linha de dados")))?;
    Ok(payload.to_string())
}

/// Deliberadamente SEM `derive(Debug)`: um `{:?}` num tipo que guarda a
/// semente ed25519 é como material secreto acaba em log de erro. Os testes
/// abaixo comparam a mensagem do erro, não o valor do sucesso, justamente
/// para não precisar disso.
pub struct SecretKey {
    key_id: [u8; 8],
    signing: SigningKey,
}

impl SecretKey {
    /// Lê uma chave secreta minisign SEM senha.
    ///
    /// Chave protegida por scrypt é recusada em vez de silenciosamente
    /// ignorada: derivar a senha exigiria scrypt, que esta árvore não tem, e
    /// tratar bytes cifrados como semente produziria uma assinatura que só
    /// falha na verificação — tarde demais e longe da causa.
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .map_err(|error| erro(format!("chave secreta {}: {error}", path.display())))?;
        let payload = payload_line(&text, "chave secreta")?;
        let raw = base64_decode(&payload, "chave secreta")?;
        if raw.len() != SECRET_LEN {
            return Err(erro(format!(
                "chave secreta: esperava {SECRET_LEN} bytes, li {}",
                raw.len()
            )));
        }
        if &raw[0..2] != LEGACY_ALGORITHM {
            return Err(erro("chave secreta: algoritmo não é Ed25519"));
        }
        if raw[2..4] != [0, 0] {
            return Err(erro(
                "chave secreta protegida por senha; o minitrue só assina com chave sem senha \
                 (gere com `minitrue channel keygen`)",
            ));
        }
        if &raw[4..6] != CHECKSUM_ALGORITHM {
            return Err(erro("chave secreta: checksum não é BLAKE2b"));
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&raw[54..62]);
        let secret = &raw[62..126];
        let stored_checksum = &raw[126..158];

        // O checksum do minisign existe para detectar SENHA ERRADA, não
        // corrupção: numa chave sem senha o `minisign -G -W` deixa o campo
        // ZERADO, e foi assim que a chave de desenvolvimento desta árvore
        // nasceu (conferido gerando uma chave nova com o próprio minisign
        // 0.12). Exigi-lo aqui recusava chave legítima. Então: se vier
        // preenchido, tem de conferir; se vier zerado, é a convenção do
        // upstream e não há o que conferir.
        if stored_checksum != [0u8; 32] {
            let mut hasher = Blake2b256::new();
            hasher.update(LEGACY_ALGORITHM);
            hasher.update(key_id);
            hasher.update(secret);
            if hasher.finalize().as_slice() != stored_checksum {
                return Err(erro("chave secreta: checksum não confere"));
            }
        }

        // Esta é a integridade que de fato importa e que vale para os dois
        // casos: a parte pública guardada tem de ser a que a semente deriva.
        // Um bit trocado em qualquer das duas metades morre aqui, e sem isso
        // assinaríamos com uma chave cuja pública ninguém consegue usar.
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&secret[0..32]);
        let signing = SigningKey::from_bytes(&seed);
        if signing.verifying_key().to_bytes() != secret[32..64] {
            return Err(erro(
                "chave secreta: a parte pública não deriva da semente (chave corrompida)",
            ));
        }
        Ok(SecretKey { key_id, signing })
    }

    pub fn public_line(&self) -> String {
        let mut raw = Vec::with_capacity(PUBLIC_LEN);
        raw.extend_from_slice(LEGACY_ALGORITHM);
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(&self.signing.verifying_key().to_bytes());
        base64_encode(&raw)
    }

    /// Assina `message` no formato pré-hasheado (`ED`), que é o que o
    /// minisign moderno produz e o que `minisign-verify` aceita nos dois
    /// modos.
    pub fn sign(&self, message: &[u8], untrusted: &str, trusted: &str) -> Result<String> {
        for (rotulo, texto) in [("untrusted", untrusted), ("trusted", trusted)] {
            if texto.contains('\n') || texto.contains('\r') {
                return Err(erro(format!(
                    "comentário {rotulo} não pode conter quebra de linha"
                )));
            }
        }
        let digest = Blake2b512::digest(message);
        let signature = self.signing.sign(&digest);

        let mut first = Vec::with_capacity(2 + 8 + 64);
        first.extend_from_slice(PREHASHED_ALGORITHM);
        first.extend_from_slice(&self.key_id);
        first.extend_from_slice(&signature.to_bytes());

        // A assinatura global cobre assinatura ‖ comentário confiável: é o que
        // impede trocar o comentário sem invalidar o arquivo.
        let mut global_body = Vec::from(signature.to_bytes());
        global_body.extend_from_slice(trusted.as_bytes());
        let global = self.signing.sign(&global_body);

        Ok(format!(
            "{UNTRUSTED_PREFIX}{untrusted}\n{}\n{TRUSTED_PREFIX}{trusted}\n{}\n",
            base64_encode(&first),
            base64_encode(&global.to_bytes())
        ))
    }
}

/// Gera um par minisign novo. Sem isto a independência seria só parcial:
/// quem começa do zero ainda precisaria do minisign do hospedeiro para criar
/// a chave que o canal usa.
pub fn keygen(name: &str, secret_path: &Path, public_path: &Path) -> Result<()> {
    for path in [secret_path, public_path] {
        if path.exists() {
            return Err(erro(format!(
                "keygen não sobrescreve: {} já existe",
                path.display()
            )));
        }
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|error| erro(format!("sem entropia para a chave: {error}")))?;
    let mut key_id = [0u8; 8];
    getrandom::getrandom(&mut key_id)
        .map_err(|error| erro(format!("sem entropia para o key_id: {error}")))?;

    let signing = SigningKey::from_bytes(&seed);
    let mut secret = Vec::with_capacity(64);
    secret.extend_from_slice(&seed);
    secret.extend_from_slice(&signing.verifying_key().to_bytes());

    // Checksum ZERADO, como o `minisign -G -W` faz: o campo serve para
    // detectar senha errada, e esta chave não tem senha. Escrever um checksum
    // válido aqui produziria uma chave que o minisign aceita mas que difere,
    // byte a byte, de tudo que ele próprio gera — divergência gratuita num
    // formato que não é nosso.
    let checksum = [0u8; 32];

    let mut raw = Vec::with_capacity(SECRET_LEN);
    raw.extend_from_slice(LEGACY_ALGORITHM);
    raw.extend_from_slice(&[0, 0]); // sem KDF: chave sem senha
    raw.extend_from_slice(CHECKSUM_ALGORITHM);
    raw.extend_from_slice(&[0u8; 32]); // sal irrelevante sem KDF
    raw.extend_from_slice(&0u64.to_le_bytes()); // opslimit
    raw.extend_from_slice(&0u64.to_le_bytes()); // memlimit
    raw.extend_from_slice(&key_id);
    raw.extend_from_slice(&secret);
    raw.extend_from_slice(&checksum);

    let secret_text = format!(
        "{UNTRUSTED_PREFIX}minisign encrypted secret key\n{}\n",
        base64_encode(&raw)
    );
    let mut public_raw = Vec::with_capacity(PUBLIC_LEN);
    public_raw.extend_from_slice(LEGACY_ALGORITHM);
    public_raw.extend_from_slice(&key_id);
    public_raw.extend_from_slice(&signing.verifying_key().to_bytes());
    let public_text = format!(
        "{UNTRUSTED_PREFIX}minisign public key {}\n{}\n",
        hex::encode_upper(key_id),
        base64_encode(&public_raw)
    );

    // 0600 na secreta desde a criação: escrever com o umask e corrigir depois
    // deixaria uma janela em que a chave do canal esteve legível.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(secret_path)
        .map_err(|error| erro(format!("{}: {error}", secret_path.display())))?;
    file.write_all(secret_text.as_bytes())
        .map_err(|error| erro(format!("{}: {error}", secret_path.display())))?;
    fs::write(public_path, &public_text)
        .map_err(|error| erro(format!("{}: {error}", public_path.display())))?;
    println!("chave de canal '{name}' criada:");
    println!("  secreta: {} (0600)", secret_path.display());
    println!("  pública: {}", public_path.display());
    print!("{public_text}");
    Ok(())
}

/// Assina um arquivo, escrevendo `<arquivo>.minisig` ao lado (ou onde pedido).
pub fn sign_file(
    secret_path: &Path,
    message_path: &Path,
    signature_path: &Path,
    untrusted: Option<&str>,
    trusted: Option<&str>,
) -> Result<()> {
    let key = SecretKey::load(secret_path)?;
    let message = fs::read(message_path)
        .map_err(|error| erro(format!("{}: {error}", message_path.display())))?;
    let name = message_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "arquivo".into());
    // O epoch da árvore, não a hora do relógio: um índice reassinado com o
    // mesmo conteúdo deve dar o mesmo arquivo, senão a mídia deixa de ser
    // reproduzível por causa da assinatura.
    let epoch = std::env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| "1704067200".into());
    let default_trusted = format!("timestamp:{epoch} file:{name}");
    let text = key.sign(
        &message,
        untrusted.unwrap_or("Distropica channel index"),
        trusted.unwrap_or(&default_trusted),
    )?;
    if signature_path.exists() {
        return Err(erro(format!(
            "sign não sobrescreve: {} já existe",
            signature_path.display()
        )));
    }
    fs::write(signature_path, text.as_bytes())
        .map_err(|error| erro(format!("{}: {error}", signature_path.display())))?;

    // Verifica com o MESMO verificador que o consumidor usa. Assinar e não
    // conferir seria confiar no código que acabou de ser escrito; aqui o
    // produtor é validado pelo consumidor antes de publicar qualquer coisa.
    let public = minisign_verify::PublicKey::from_base64(&key.public_line()).map_err(|error| {
        erro(format!(
            "chave pública derivada não é aceita pelo verificador: {error}"
        ))
    })?;
    let signature = minisign_verify::Signature::decode(&text)
        .map_err(|error| erro(format!("assinatura recém-escrita não decodifica: {error}")))?;
    public
        .verify(&message, &signature, false)
        .map_err(|error| erro(format!("assinatura recém-escrita não confere: {error}")))?;

    println!("assinado: {}", signature_path.display());
    println!("  chave pública: {}", key.public_line());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(nome: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "minitrue-sign-{nome}-{}-{}",
            std::process::id(),
            nome.len()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn keygen_produz_chave_que_assina_e_o_verificador_aceita() {
        let dir = temp_dir("ciclo");
        let secret = dir.join("k.key");
        let public = dir.join("k.pub");
        keygen("teste", &secret, &public).unwrap();

        let message = dir.join("index");
        fs::write(&message, b"pkg 1 x86_64\n").unwrap();
        let signature = dir.join("index.minisig");
        sign_file(&secret, &message, &signature, None, None).unwrap();

        // A chave pública gravada tem de ser a mesma que a secreta deriva:
        // publicar uma e assinar com a outra é o erro que ninguém percebe até
        // o primeiro consumidor recusar o canal.
        let publicada = fs::read_to_string(&public).unwrap();
        let esperada = SecretKey::load(&secret).unwrap().public_line();
        assert!(publicada.contains(&esperada));

        let key = minisign_verify::PublicKey::from_base64(&esperada).unwrap();
        let texto = fs::read_to_string(&signature).unwrap();
        let sig = minisign_verify::Signature::decode(&texto).unwrap();
        key.verify(b"pkg 1 x86_64\n", &sig, false).unwrap();
        assert!(key.verify(b"outra coisa\n", &sig, false).is_err());
    }

    #[test]
    fn assinatura_e_deterministica_para_o_mesmo_conteudo() {
        let dir = temp_dir("determinismo");
        let secret = dir.join("k.key");
        keygen("t", &secret, &dir.join("k.pub")).unwrap();
        let key = SecretKey::load(&secret).unwrap();
        let a = key.sign(b"mesmo", "c", "t").unwrap();
        let b = key.sign(b"mesmo", "c", "t").unwrap();
        assert_eq!(a, b, "ed25519 é determinístico; a saída também deve ser");
    }

    #[test]
    fn recusa_chave_com_senha_e_chave_corrompida() {
        let dir = temp_dir("recusa");
        let secret = dir.join("k.key");
        keygen("t", &secret, &dir.join("k.pub")).unwrap();
        let texto = fs::read_to_string(&secret).unwrap();
        let payload = payload_line(&texto, "chave").unwrap();
        let mut raw = base64_decode(&payload, "chave").unwrap();

        let mut com_senha = raw.clone();
        com_senha[2] = b'S';
        com_senha[3] = b'c';
        let caminho = dir.join("senha.key");
        fs::write(
            &caminho,
            format!("{UNTRUSTED_PREFIX}x\n{}\n", base64_encode(&com_senha)),
        )
        .unwrap();
        let erro = match SecretKey::load(&caminho) {
            Ok(_) => panic!("aceitou chave protegida por senha"),
            Err(e) => e.to_string(),
        };
        assert!(erro.contains("senha"), "erro inesperado: {erro}");

        // Um bit trocado na semente tem de morrer na conferência semente →
        // pública, não virar assinatura de uma chave que ninguém verifica.
        raw[70] ^= 1;
        let caminho = dir.join("corrompida.key");
        fs::write(
            &caminho,
            format!("{UNTRUSTED_PREFIX}x\n{}\n", base64_encode(&raw)),
        )
        .unwrap();
        let erro = match SecretKey::load(&caminho) {
            Ok(_) => panic!("aceitou chave com semente corrompida"),
            Err(e) => e.to_string(),
        };
        assert!(erro.contains("não deriva"), "erro inesperado: {erro}");
    }

    #[test]
    fn nao_sobrescreve_assinatura_nem_chave() {
        let dir = temp_dir("sobrescrita");
        let secret = dir.join("k.key");
        let public = dir.join("k.pub");
        keygen("t", &secret, &public).unwrap();
        assert!(keygen("t", &secret, &public).is_err());

        let message = dir.join("m");
        fs::write(&message, b"x").unwrap();
        let signature = dir.join("m.minisig");
        sign_file(&secret, &message, &signature, None, None).unwrap();
        assert!(sign_file(&secret, &message, &signature, None, None).is_err());
    }
}
