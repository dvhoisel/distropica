#define _GNU_SOURCE

/*
 * Helper nativo do lock do EFI vivo.
 *
 * Fronteira: este programa não estabelece a primeira raiz de confiança. No
 * modo release ele é compilado estaticamente, dentro do builder já autorizado,
 * a partir deste fonte preso pelo LIVE_RUNNER_PROOF. O launcher anterior ao
 * primeiro bwrap usa somente builtins do shell e o caminho absoluto do bwrap
 * que o pipeline superior autenticou. AUTHENTICATED=yes dentro do proof não
 * se autentica sozinho: o consumidor superior precisa exigir o SHA-256 exato
 * desses bytes como autoridade externa.
 *
 * Limites deliberados:
 *   - Linux/ELF64 little-endian x86-64;
 *   - caminhos absolutos, sem componentes vazios, "." ou "..";
 *   - árvores sem sockets/devices/FIFOs e sem cruzar filesystems;
 *   - SHA-256; arquivos individuais de publicação precisam de nlink=1;
 *   - concorrente com o mesmo uid continua dentro da fronteira de confiança,
 *     mas todas as operações de caminho depois do fd-walk são *at(2).
 */

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_PATH
#define O_PATH 010000000
#endif

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define IO_CHUNK 65536U
#define SMALL_FILE_LIMIT (1024U * 1024U)
#define ELF_TABLE_LIMIT (256U * 1024U * 1024U)
#define CPIO_MEMBER_LIMIT (512U * 1024U * 1024U)
/* Ancora e janela da busca por conteudo do initramfs no vmlinux extraido. */
#define ELF_SCAN_ANCHOR (4U * 1024U)
#define ELF_SCAN_CHUNK (4U * 1024U * 1024U)
/* Janela do fim do blob onde o membro TRAILER!!! precisa aparecer. */
#define CPIO_TRAILER_WINDOW (4U * 1024U)
#define CPIO_ENTRY_LIMIT 100000U
#define TREE_ENTRY_LIMIT 1000000U
#define TREE_PATH_LIMIT (64U * 1024U)
#define TREE_SYMLINK_LIMIT (64U * 1024U)

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif

static void die(const char *fmt, ...) __attribute__((noreturn));

static void die(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "erro: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void die_errno(const char *what) __attribute__((noreturn));

static void die_errno(const char *what) {
    die("%s: %s", what, strerror(errno));
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die("memória insuficiente");
    return p;
}

static char *xstrdup(const char *s) {
    char *p = strdup(s);
    if (!p) die("memória insuficiente");
    return p;
}

static void write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            die_errno("write");
        }
        if (n == 0) die("write devolveu zero");
        p += (size_t)n;
        len -= (size_t)n;
    }
}

static void pread_all(int fd, void *buf, size_t len, off_t off) {
    unsigned char *p = buf;
    while (len) {
        ssize_t n = pread(fd, p, len, off);
        if (n < 0) {
            if (errno == EINTR) continue;
            die_errno("pread");
        }
        if (n == 0) die("arquivo truncado durante leitura");
        p += (size_t)n;
        len -= (size_t)n;
        off += n;
    }
}

/* SHA-256, implementação local para que o helper não volte ao PATH. */
struct sha256_ctx {
    uint32_t h[8];
    uint64_t bytes;
    unsigned char block[64];
    size_t used;
};

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t ror32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32U - n));
}

static void sha256_transform(struct sha256_ctx *c, const unsigned char b[64]) {
    uint32_t w[64], a, d, e, f, g, h, i0, i1, t1, t2;
    for (size_t i = 0; i < 16; i++) {
        w[i] = ((uint32_t)b[i * 4] << 24) |
               ((uint32_t)b[i * 4 + 1] << 16) |
               ((uint32_t)b[i * 4 + 2] << 8) |
               (uint32_t)b[i * 4 + 3];
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0]; i0 = c->h[1]; i1 = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (size_t i = 0; i < 64; i++) {
        uint32_t s1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + s1 + ch + sha256_k[i] + w[i];
        uint32_t s0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        uint32_t maj = (a & i0) ^ (a & i1) ^ (i0 & i1);
        t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = i1; i1 = i0; i0 = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += i0; c->h[2] += i1; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(struct sha256_ctx *c) {
    static const uint32_t initial[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    memcpy(c->h, initial, sizeof(initial));
    c->bytes = 0;
    c->used = 0;
}

static void sha256_update(struct sha256_ctx *c, const void *data, size_t len) {
    const unsigned char *p = data;
    c->bytes += len;
    while (len) {
        size_t take = 64 - c->used;
        if (take > len) take = len;
        memcpy(c->block + c->used, p, take);
        c->used += take;
        p += take;
        len -= take;
        if (c->used == 64) {
            sha256_transform(c, c->block);
            c->used = 0;
        }
    }
}

static void sha256_final(struct sha256_ctx *c, unsigned char out[32]) {
    uint64_t bits = c->bytes * 8;
    c->block[c->used++] = 0x80;
    if (c->used > 56) {
        memset(c->block + c->used, 0, 64 - c->used);
        sha256_transform(c, c->block);
        c->used = 0;
    }
    memset(c->block + c->used, 0, 56 - c->used);
    for (size_t i = 0; i < 8; i++)
        c->block[63 - i] = (unsigned char)(bits >> (i * 8));
    sha256_transform(c, c->block);
    for (size_t i = 0; i < 8; i++) {
        out[i * 4] = (unsigned char)(c->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)c->h[i];
    }
}

static void hex_digest(const unsigned char digest[32], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 15];
    }
    out[64] = '\0';
}

static bool valid_sha256(const char *s) {
    if (!s || strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

static bool stat_stable(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
           a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static void sha256_fd_stable(int fd, char hex[65], struct stat *snapshot) {
    struct stat before, after;
    if (fstat(fd, &before) < 0) die_errno("fstat antes do hash");
    if (!S_ISREG(before.st_mode)) die("hash exige arquivo regular");
    if (lseek(fd, 0, SEEK_SET) < 0) die_errno("lseek antes do hash");
    struct sha256_ctx c;
    sha256_init(&c);
    unsigned char *buf = xmalloc(IO_CHUNK);
    for (;;) {
        ssize_t n = read(fd, buf, IO_CHUNK);
        if (n < 0) {
            if (errno == EINTR) continue;
            die_errno("read durante hash");
        }
        if (n == 0) break;
        sha256_update(&c, buf, (size_t)n);
    }
    free(buf);
    unsigned char digest[32];
    sha256_final(&c, digest);
    if (fstat(fd, &after) < 0) die_errno("fstat depois do hash");
    if (!stat_stable(&before, &after)) die("arquivo mudou durante hash");
    if (lseek(fd, 0, SEEK_SET) < 0) die_errno("lseek depois do hash");
    hex_digest(digest, hex);
    if (snapshot) *snapshot = before;
}

struct path_ref {
    int parent_fd;
    char leaf[NAME_MAX + 1];
};

static bool trusted_ancestor(const struct stat *st, bool exact_root_tmp) {
    uid_t euid = geteuid();
    if (!S_ISDIR(st->st_mode)) return false;
    if (st->st_uid != 0 && st->st_uid != euid) return false;
    /* Somente /tmp exato é exceção root+sticky. WORK, output, staging e
     * publicação continuam exigindo um pai final privado. */
    if (st->st_mode & 0022) {
        if (!exact_root_tmp || st->st_uid != 0 ||
            !(st->st_mode & S_ISVTX)) return false;
    }
    return true;
}

static bool trusted_readonly_dir(const struct stat *st) {
    uid_t euid = geteuid();
    return S_ISDIR(st->st_mode) &&
           (st->st_uid == 0 || st->st_uid == euid) &&
           (st->st_mode & 0022) == 0;
}

static bool trusted_private_dir(const struct stat *st) {
    return S_ISDIR(st->st_mode) && st->st_uid == geteuid() &&
           (st->st_mode & 0022) == 0;
}

static void validate_component(const char *s, size_t n) {
    if (n == 0 || n > NAME_MAX) die("componente de caminho inválido");
    if ((n == 1 && s[0] == '.') ||
        (n == 2 && s[0] == '.' && s[1] == '.'))
        die("caminho contém . ou ..");
    for (size_t i = 0; i < n; i++)
        if (s[i] == '\n' || s[i] == '\r' || s[i] == '\0')
            die("caminho contém controle");
}

/* Abre o pai de um leaf absoluto sem seguir symlink em nenhum componente. */
static struct path_ref open_parent(const char *path, bool private_parent) {
    if (!path || path[0] != '/' || path[1] == '\0')
        die("caminho precisa ser absoluto e ter leaf: %s", path ? path : "(null)");
    size_t len = strlen(path);
    if (path[len - 1] == '/' || strstr(path, "//"))
        die("caminho não canônico: %s", path);
    char *copy = xstrdup(path + 1);
    char *last = strrchr(copy, '/');
    char *leaf = last ? last + 1 : copy;
    validate_component(leaf, strlen(leaf));
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) die_errno("open /");
    struct stat st;
    if (fstat(fd, &st) < 0 || !trusted_ancestor(&st, false))
        die("raiz do caminho não é confiável");
    if (last) {
        *last = '\0';
        char *save = NULL;
        bool at_root = true;
        for (char *part = strtok_r(copy, "/", &save); part;
             part = strtok_r(NULL, "/", &save)) {
            validate_component(part, strlen(part));
            struct stat lst;
            if (fstatat(fd, part, &lst, AT_SYMLINK_NOFOLLOW) < 0)
                die_errno("fstatat ancestral");
            bool exact_root_tmp = at_root && !strcmp(part, "tmp");
            if (!trusted_ancestor(&lst, exact_root_tmp))
                die("ancestral não confiável: %s", part);
            int next = openat(fd, part, O_RDONLY | O_DIRECTORY |
                             O_NOFOLLOW | O_CLOEXEC);
            if (next < 0) die_errno("openat ancestral");
            struct stat opened;
            if (fstat(next, &opened) < 0) die_errno("fstat ancestral aberto");
            if (opened.st_dev != lst.st_dev || opened.st_ino != lst.st_ino ||
                !trusted_ancestor(&opened, exact_root_tmp))
                die("ancestral foi trocado durante abertura: %s", part);
            close(fd);
            fd = next;
            at_root = false;
        }
    }
    if (fstat(fd, &st) < 0) die_errno("fstat pai");
    if (private_parent && !trusted_private_dir(&st))
        die("pai final precisa ser privado, do euid e sem 0022: %s", path);
    struct path_ref ref = {.parent_fd = fd};
    if (strlen(leaf) > NAME_MAX) die("leaf longo demais");
    strcpy(ref.leaf, leaf);
    free(copy);
    return ref;
}

static int open_regular_abs(const char *path, bool private_parent,
                            bool require_nlink_one, struct stat *snapshot) {
    struct path_ref ref = open_parent(path, private_parent);
    int fd = openat(ref.parent_fd, ref.leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) die_errno("openat arquivo");
    struct stat st;
    if (fstat(fd, &st) < 0) die_errno("fstat arquivo");
    if (!S_ISREG(st.st_mode)) die("insumo não é regular: %s", path);
    if (st.st_uid != 0 && st.st_uid != geteuid())
        die("insumo não pertence a root/euid: %s", path);
    if (st.st_mode & 0022) die("insumo permite escrita a grupo/outros: %s", path);
    if (require_nlink_one && st.st_nlink != 1)
        die("insumo tem nlink=%ju: %s", (uintmax_t)st.st_nlink, path);
    close(ref.parent_fd);
    if (snapshot) *snapshot = st;
    return fd;
}

static int open_dir_abs(const char *path, bool private_dir, struct stat *snapshot) {
    struct path_ref ref = open_parent(path, false);
    int fd = openat(ref.parent_fd, ref.leaf, O_RDONLY | O_DIRECTORY |
                    O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) die_errno("openat diretório");
    struct stat st;
    if (fstat(fd, &st) < 0) die_errno("fstat diretório");
    if (!trusted_readonly_dir(&st))
        die("diretório read-only precisa pertencer a root/euid e não ter 0022: %s",
            path);
    if (private_dir && !trusted_private_dir(&st))
        die("diretório precisa ser privado/do euid/sem 0022: %s", path);
    close(ref.parent_fd);
    if (snapshot) *snapshot = st;
    return fd;
}

static void hash_u8(struct sha256_ctx *c, uint8_t v) {
    sha256_update(c, &v, 1);
}

static void hash_u32(struct sha256_ctx *c, uint32_t v) {
    unsigned char b[4] = {(unsigned char)(v >> 24), (unsigned char)(v >> 16),
                          (unsigned char)(v >> 8), (unsigned char)v};
    sha256_update(c, b, sizeof(b));
}

static void hash_u64(struct sha256_ctx *c, uint64_t v) {
    unsigned char b[8];
    for (size_t i = 0; i < 8; i++) b[7 - i] = (unsigned char)(v >> (i * 8));
    sha256_update(c, b, sizeof(b));
}

static void hash_bytes(struct sha256_ctx *c, const void *p, size_t n) {
    hash_u64(c, n);
    sha256_update(c, p, n);
}

static int cmp_names(const void *a, const void *b) {
    const char *const *sa = a;
    const char *const *sb = b;
    return strcmp(*sa, *sb);
}

static bool excluded_path(const char *relative, const char *exclude) {
    if (!exclude || !*exclude) return false;
    size_t n = strlen(exclude);
    return strcmp(relative, exclude) == 0 ||
           (strncmp(relative, exclude, n) == 0 && relative[n] == '/');
}

static void hash_tree_dir(struct sha256_ctx *root_hash, int dirfd,
                          const char *prefix, const char *exclude,
                          dev_t root_dev, uint64_t *entries) {
    struct stat dir_before, dir_after;
    if (fstat(dirfd, &dir_before) < 0) die_errno("fstat árvore antes");
    if (dir_before.st_dev != root_dev) die("tree-hash cruzaria filesystem");
    int dupfd = dup(dirfd);
    if (dupfd < 0) die_errno("dup diretório");
    DIR *dir = fdopendir(dupfd);
    if (!dir) die_errno("fdopendir");
    char **names = NULL;
    size_t count = 0, capacity = 0;
    errno = 0;
    for (struct dirent *de; (de = readdir(dir));) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (++*entries > TREE_ENTRY_LIMIT)
            die("tree-hash excedeu limite de entradas");
        if (capacity == count) {
            capacity = capacity ? capacity * 2 : 32;
            char **next = realloc(names, capacity * sizeof(*names));
            if (!next) die("memória insuficiente");
            names = next;
        }
        names[count++] = xstrdup(de->d_name);
    }
    if (errno) die_errno("readdir");
    if (closedir(dir) < 0) die_errno("closedir");
    qsort(names, count, sizeof(*names), cmp_names);
    for (size_t i = 0; i < count; i++) {
        const char *name = names[i];
        size_t plen = prefix && *prefix ? strlen(prefix) : 0;
        size_t rlen = plen + (plen ? 1 : 0) + strlen(name);
        if (rlen > TREE_PATH_LIMIT) die("caminho de árvore longo demais");
        char *relative = xmalloc(rlen + 1);
        if (plen) {
            size_t nlen = strlen(name);
            memcpy(relative, prefix, plen);
            relative[plen] = '/';
            memcpy(relative + plen + 1, name, nlen);
            relative[rlen] = '\0';
        } else {
            strcpy(relative, name);
        }
        if (excluded_path(relative, exclude)) {
            free(relative);
            free(names[i]);
            continue;
        }
        struct stat before, after;
        if (fstatat(dirfd, name, &before, AT_SYMLINK_NOFOLLOW) < 0)
            die_errno("fstatat árvore antes");
        if (before.st_dev != root_dev) die("tree-hash encontrou mount: %s", relative);
        uint8_t type;
        if (S_ISREG(before.st_mode)) type = 'f';
        else if (S_ISDIR(before.st_mode)) type = 'd';
        else if (S_ISLNK(before.st_mode)) type = 'l';
        else die("tree-hash recusa nó especial: %s", relative);
        hash_u8(root_hash, type);
        hash_bytes(root_hash, relative, strlen(relative));
        hash_u32(root_hash, (uint32_t)before.st_mode);
        hash_u64(root_hash, (uint64_t)before.st_uid);
        hash_u64(root_hash, (uint64_t)before.st_gid);
        hash_u64(root_hash, (uint64_t)before.st_nlink);
        hash_u64(root_hash, (uint64_t)before.st_size);
        if (type == 'f') {
            int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) die_errno("openat arquivo da árvore");
            char hex[65];
            struct stat hashed;
            sha256_fd_stable(fd, hex, &hashed);
            close(fd);
            if (!stat_stable(&before, &hashed))
                die("arquivo trocado durante tree-hash: %s", relative);
            hash_bytes(root_hash, hex, 64);
        } else if (type == 'l') {
            size_t cap = before.st_size > 0 ? (size_t)before.st_size + 1 : PATH_MAX;
            if (cap > TREE_SYMLINK_LIMIT)
                die("symlink longo demais: %s", relative);
            char *target = xmalloc(cap + 1);
            ssize_t n = readlinkat(dirfd, name, target, cap);
            if (n < 0) die_errno("readlinkat");
            if ((size_t)n >= cap) die("symlink mudou/foi truncado: %s", relative);
            target[n] = '\0';
            hash_bytes(root_hash, target, (size_t)n);
            free(target);
        } else {
            int child = openat(dirfd, name, O_RDONLY | O_DIRECTORY |
                               O_NOFOLLOW | O_CLOEXEC);
            if (child < 0) die_errno("openat subdiretório");
            hash_tree_dir(root_hash, child, relative, exclude, root_dev,
                          entries);
            close(child);
        }
        if (fstatat(dirfd, name, &after, AT_SYMLINK_NOFOLLOW) < 0)
            die_errno("fstatat árvore depois");
        if (!stat_stable(&before, &after))
            die("nó mudou durante tree-hash: %s", relative);
        free(relative);
        free(names[i]);
    }
    free(names);
    if (fstat(dirfd, &dir_after) < 0) die_errno("fstat árvore depois");
    if (!stat_stable(&dir_before, &dir_after))
        die("diretório mudou durante tree-hash: %s", prefix ? prefix : "");
}

static void tree_hash_abs(const char *root, const char *exclude, char hex[65]) {
    if (exclude && (*exclude == '/' || strstr(exclude, "//") ||
                    !strcmp(exclude, ".") || strstr(exclude, "../")))
        die("exclusão precisa ser relativa/canônica");
    struct stat st;
    /* Rootfs é um input read-only pinado e pode ser root-owned. WORK e
     * output usam as APIs privadas separadas. */
    int fd = open_dir_abs(root, false, &st);
    struct sha256_ctx c;
    sha256_init(&c);
    static const char domain[] = "DISTROPICA_LIVE_TREE_FORMAT=1\0";
    sha256_update(&c, domain, sizeof(domain));
    hash_u32(&c, (uint32_t)st.st_mode);
    hash_u64(&c, (uint64_t)st.st_uid);
    hash_u64(&c, (uint64_t)st.st_gid);
    hash_u64(&c, (uint64_t)st.st_nlink);
    uint64_t entries = 0;
    hash_tree_dir(&c, fd, "", exclude, st.st_dev, &entries);
    close(fd);
    unsigned char digest[32];
    sha256_final(&c, digest);
    hex_digest(digest, hex);
}

static void command_tree_hash(const char *root, const char *exclude) {
    char hex[65];
    tree_hash_abs(root, exclude, hex);
    puts(hex);
}

static uint64_t checked_add_u64(uint64_t a, uint64_t b, const char *what) {
    if (UINT64_MAX - a < b) die("overflow em %s", what);
    return a + b;
}

static uint64_t align4_u64(uint64_t n, const char *what) {
    return checked_add_u64(n, (4U - (n & 3U)) & 3U, what);
}

static bool range_in_file(uint64_t off, uint64_t len, uint64_t size) {
    return off <= size && len <= size - off;
}

static void sha256_fd_range(int fd, uint64_t off, uint64_t len,
                            unsigned char digest[32]) {
    struct sha256_ctx c;
    sha256_init(&c);
    unsigned char *buf = xmalloc(IO_CHUNK);
    while (len) {
        size_t take = len > IO_CHUNK ? IO_CHUNK : (size_t)len;
        pread_all(fd, buf, take, (off_t)off);
        sha256_update(&c, buf, take);
        off += take;
        len -= take;
    }
    free(buf);
    sha256_final(&c, digest);
}

static void hash_regular_abs(const char *path, char hex[65],
                             struct stat *snapshot) {
    /* Inputs read-only pinados aceitam owner root ou euid. A cadeia inteira
     * segue autenticada por fd-walk/no-follow e sem 0022. */
    int fd = open_regular_abs(path, false, true, NULL);
    sha256_fd_stable(fd, hex, snapshot);
    if (close(fd) < 0) die_errno("close depois do hash");
}

static bool fd_bytes_equal(int left, int right, uint64_t left_off,
                           uint64_t right_off, uint64_t len) {
    unsigned char *a = xmalloc(IO_CHUNK);
    unsigned char *b = xmalloc(IO_CHUNK);
    bool equal = true;
    while (len) {
        size_t take = len > IO_CHUNK ? IO_CHUNK : (size_t)len;
        pread_all(left, a, take, (off_t)left_off);
        pread_all(right, b, take, (off_t)right_off);
        if (memcmp(a, b, take)) {
            equal = false;
            break;
        }
        left_off += take;
        right_off += take;
        len -= take;
    }
    free(a);
    free(b);
    return equal;
}

static void require_same_regular_bytes(const char *left_path,
                                       const char *right_path,
                                       const char *what) {
    struct stat left_before, right_before, left_after, right_after;
    int left = open_regular_abs(left_path, false, true, &left_before);
    int right = open_regular_abs(right_path, false, true, &right_before);
    if (left_before.st_size < 0 || right_before.st_size < 0 ||
        left_before.st_size != right_before.st_size ||
        !fd_bytes_equal(left, right, 0, 0, (uint64_t)left_before.st_size))
        die("bytes divergentes em %s", what);
    if (fstat(left, &left_after) < 0 || fstat(right, &right_after) < 0)
        die_errno("fstat depois da comparação");
    if (!stat_stable(&left_before, &left_after) ||
        !stat_stable(&right_before, &right_after))
        die("insumo mudou durante %s", what);
    if (close(left) < 0 || close(right) < 0)
        die_errno("close depois da comparação");
}

static uint32_t parse_hex8(const unsigned char *p, const char *field) {
    uint32_t value = 0;
    for (size_t i = 0; i < 8; i++) {
        unsigned char c = p[i];
        uint32_t digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10U;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10U;
        else die("hex inválido no campo cpio %s", field);
        value = (value << 4) | digit;
    }
    return value;
}

struct cpio_member_result {
    uint64_t offset;
    uint64_t size;
    char sha256[65];
};

static struct cpio_member_result find_newc_member(int fd, const struct stat *st,
                                                  const char *wanted) {
    if (st->st_size < 0) die("cpio com tamanho negativo");
    uint64_t total = (uint64_t)st->st_size;
    uint64_t off = 0;
    unsigned matches = 0;
    bool trailer = false;
    struct cpio_member_result result = {0};
    size_t wanted_len = strlen(wanted);
    if (!wanted_len || wanted_len > PATH_MAX || wanted[0] == '/' ||
        strstr(wanted, "//") || strstr(wanted, "../"))
        die("nome de membro cpio inválido");
    for (unsigned entry = 0; entry < CPIO_ENTRY_LIMIT; entry++) {
        unsigned char h[110];
        if (!range_in_file(off, sizeof(h), total))
            die("cpio truncado antes do trailer");
        pread_all(fd, h, sizeof(h), (off_t)off);
        if (memcmp(h, "070701", 6))
            die("cpio não é newc canônico sem CRC");
        uint32_t mode = parse_hex8(h + 14, "mode");
        uint32_t file_size = parse_hex8(h + 54, "filesize");
        uint32_t name_size = parse_hex8(h + 94, "namesize");
        if (name_size == 0 || name_size > PATH_MAX + 1U)
            die("nome cpio fora do limite");
        uint64_t name_off = checked_add_u64(off, sizeof(h), "nome cpio");
        if (!range_in_file(name_off, name_size, total)) die("nome cpio truncado");
        char *name = xmalloc(name_size);
        pread_all(fd, name, name_size, (off_t)name_off);
        if (name[name_size - 1] != '\0' || memchr(name, '\0', name_size - 1))
            die("nome cpio sem NUL final único");
        for (uint32_t i = 0; i + 1 < name_size; i++)
            if (name[i] == '\n' || name[i] == '\r' || name[i] == '|')
                die("nome cpio contém byte recusado");
        uint64_t data_off = align4_u64(checked_add_u64(name_off, name_size,
                                                       "dados cpio"),
                                       "alinhamento cpio");
        if (file_size > CPIO_MEMBER_LIMIT ||
            !range_in_file(data_off, file_size, total))
            die("payload cpio truncado/fora do limite");
        if (!strcmp(name, "TRAILER!!!")) {
            if (file_size != 0) die("trailer cpio com payload");
            trailer = true;
            free(name);
            off = align4_u64(data_off, "fim do trailer cpio");
            break;
        }
        if (strlen(name) == wanted_len && !memcmp(name, wanted, wanted_len)) {
            if (++matches != 1) die("membro cpio duplicado: %s", wanted);
            if ((mode & S_IFMT) != S_IFREG)
                die("membro cpio esperado não é regular");
            result.offset = data_off;
            result.size = file_size;
            unsigned char digest[32];
            sha256_fd_range(fd, data_off, file_size, digest);
            hex_digest(digest, result.sha256);
        }
        free(name);
        off = align4_u64(checked_add_u64(data_off, file_size, "fim cpio"),
                         "alinhamento fim cpio");
    }
    if (!trailer) die("cpio excede limite de entradas/sem trailer");
    if (matches != 1) die("membro cpio ausente: %s", wanted);
    /* Depois do trailer, gen_init_cpio só pode ter padding NUL. */
    unsigned char tail[IO_CHUNK];
    while (off < total) {
        size_t take = total - off > IO_CHUNK ? IO_CHUNK : (size_t)(total - off);
        pread_all(fd, tail, take, (off_t)off);
        for (size_t i = 0; i < take; i++)
            if (tail[i] != 0) die("bytes não-NUL depois do trailer cpio");
        off += take;
    }
    return result;
}

struct elf_initramfs {
    uint64_t file_offset;
    uint64_t size;
};

/* Localiza o initramfs no vmlinux extraido POR CONTEUDO, e nao por simbolo.
 *
 * A versao anterior lia __initramfs_start/__initramfs_size da symtab. Isso nao
 * pode funcionar aqui e nunca funcionou: o que o kernel comprime dentro do
 * bzImage e o arch/x86/boot/compressed/vmlinux.bin, que ja saiu do objcopy SEM
 * tabela de simbolos — o extract-vmlinux devolve um ELF que o `file` classifica
 * como "stripped". Os dois simbolos existem no linux-source/vmlinux, que e outro
 * arquivo. A guarda pedia o impossivel, e ninguem notou porque ela nasceu depois
 * da ultima midia publicada.
 *
 * A prova por conteudo e MAIS FORTE que a por simbolo, e nao um contorno: em vez
 * de acreditar num rotulo que diz onde o blob deveria estar, exige que os bytes
 * do blob estejam la — uma vez so, e dentro de um PT_LOAD. Um simbolo mentiroso
 * passaria pela versao antiga; bytes nao mentem sobre si mesmos.
 *
 * A busca usa uma ancora dos primeiros bytes para achar candidatos e so entao
 * compara o blob inteiro. Ocorrencia dupla e recusada em vez de aceita: se o
 * mesmo blob aparece duas vezes, nao se sabe qual e o que o kernel usa.
 */
static struct elf_initramfs locate_elf_initramfs(int fd, const struct stat *st,
                                                 int blob, uint64_t blob_size) {
    if (st->st_size < (off_t)sizeof(Elf64_Ehdr)) die("ELF truncado");
    uint64_t file_size = (uint64_t)st->st_size;
    Elf64_Ehdr eh;
    pread_all(fd, &eh, sizeof(eh), 0);
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB ||
        eh.e_ident[EI_VERSION] != EV_CURRENT ||
        eh.e_machine != EM_X86_64 || eh.e_version != EV_CURRENT ||
        (eh.e_type != ET_EXEC && eh.e_type != ET_DYN))
        die("vmlinux precisa ser ELF64 little-endian x86-64");
    if (eh.e_ehsize != sizeof(Elf64_Ehdr) ||
        eh.e_phentsize != sizeof(Elf64_Phdr) ||
        eh.e_phnum == PN_XNUM || eh.e_phnum == 0)
        die("tabelas ELF estendidas/nao canonicas nao sao aceitas");
    uint64_t ph_size = (uint64_t)eh.e_phnum * sizeof(Elf64_Phdr);
    if (ph_size > ELF_TABLE_LIMIT ||
        !range_in_file(eh.e_phoff, ph_size, file_size))
        die("tabela ELF fora do arquivo/limite");
    Elf64_Phdr *ph = xmalloc((size_t)ph_size);
    pread_all(fd, ph, (size_t)ph_size, (off_t)eh.e_phoff);

    if (blob_size == 0 || blob_size > CPIO_MEMBER_LIMIT || blob_size > file_size)
        die("blob initramfs vazio ou fora do limite");

    /* O BLOB PRECISA SER UM ARQUIVO newc COMPLETO, e nao um prefixo dele.
     *
     * A busca por conteudo sozinha aceitaria um pedaco: os primeiros mil bytes
     * do initramfs verdadeiro TAMBEM aparecem no vmlinux, uma vez so e dentro
     * de um PT_LOAD, entao passariam por todas as outras checagens. Medido, nao
     * suposto — foi o unico dos cinco casos de teste que passou quando nao
     * devia.
     *
     * Todo cpio newc termina no membro TRAILER!!!, e exigi-lo fecha o buraco:
     * um prefixo nao o contem. */
    {
        size_t tail_len = blob_size < CPIO_TRAILER_WINDOW
                              ? (size_t)blob_size : CPIO_TRAILER_WINDOW;
        unsigned char *tail = xmalloc(tail_len);
        pread_all(blob, tail, tail_len, (off_t)(blob_size - tail_len));
        static const char marker[] = "TRAILER!!!";
        bool has_trailer = false;
        if (tail_len >= sizeof(marker) - 1) {
            for (size_t i = 0; i + sizeof(marker) - 1 <= tail_len; i++) {
                if (!memcmp(tail + i, marker, sizeof(marker) - 1)) {
                    has_trailer = true;
                    break;
                }
            }
        }
        free(tail);
        if (!has_trailer)
            die("blob initramfs nao termina em TRAILER!!! — cpio incompleto");
    }

    size_t anchor_len = blob_size < ELF_SCAN_ANCHOR
                            ? (size_t)blob_size : ELF_SCAN_ANCHOR;
    unsigned char *anchor = xmalloc(anchor_len);
    pread_all(blob, anchor, anchor_len, 0);

    uint64_t last_start = file_size - blob_size;
    unsigned char *buf = xmalloc(ELF_SCAN_CHUNK);
    bool found = false;
    uint64_t found_off = 0;
    uint64_t pos = 0;
    while (pos <= last_start) {
        uint64_t want = file_size - pos;
        if (want > ELF_SCAN_CHUNK) want = ELF_SCAN_CHUNK;
        if (want < (uint64_t)anchor_len) break;
        pread_all(fd, buf, (size_t)want, (off_t)pos);
        size_t scan = (size_t)want - anchor_len + 1;
        size_t i = 0;
        while (i < scan) {
            unsigned char *hit = memchr(buf + i, anchor[0], scan - i);
            if (!hit) break;
            size_t at = (size_t)(hit - buf);
            if (!memcmp(hit, anchor, anchor_len)) {
                uint64_t cand = pos + at;
                if (cand <= last_start &&
                    fd_bytes_equal(fd, blob, cand, 0, blob_size)) {
                    if (found && cand != found_off)
                        die("initramfs aparece mais de uma vez no vmlinux");
                    found = true;
                    found_off = cand;
                }
            }
            i = at + 1;
        }
        if (want < ELF_SCAN_CHUNK) break;
        pos += want - (uint64_t)(anchor_len - 1);
    }
    free(buf);
    free(anchor);
    if (!found) die("initramfs nao aparece no vmlinux extraido");

    bool mapped = false;
    for (uint16_t i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (found_off < ph[i].p_offset) continue;
        uint64_t delta = found_off - ph[i].p_offset;
        if (delta <= ph[i].p_filesz && blob_size <= ph[i].p_filesz - delta) {
            mapped = true;
            break;
        }
    }
    free(ph);
    if (!mapped) die("initramfs encontrado fora de qualquer PT_LOAD");
    struct elf_initramfs result = {.file_offset = found_off, .size = blob_size};
    return result;
}

static void command_file_hash(const char *path) {
    char hex[65];
    hash_regular_abs(path, hex, NULL);
    puts(hex);
}

static void command_cpio_member(const char *cpio_path, const char *member,
                                const char *expected_path) {
    struct stat cpio_before, cpio_after, expected_before, expected_after;
    int cpio = open_regular_abs(cpio_path, false, true, &cpio_before);
    int expected = open_regular_abs(expected_path, false, true, &expected_before);
    struct cpio_member_result found = find_newc_member(cpio, &cpio_before, member);
    if (expected_before.st_size < 0 || found.size != (uint64_t)expected_before.st_size ||
        !fd_bytes_equal(cpio, expected, found.offset, 0, found.size))
        die("membro cpio diverge do arquivo esperado");
    if (fstat(cpio, &cpio_after) < 0 || fstat(expected, &expected_after) < 0)
        die_errno("fstat depois do cpio");
    if (!stat_stable(&cpio_before, &cpio_after) ||
        !stat_stable(&expected_before, &expected_after))
        die("insumo mudou durante validação cpio");
    close(cpio);
    close(expected);
    puts(found.sha256);
}

static void verify_elf_initramfs(const char *vmlinux_path,
                                 const char *blob_path) {
    struct stat elf_before, elf_after, blob_before, blob_after;
    int elf = open_regular_abs(vmlinux_path, false, true, &elf_before);
    int blob = open_regular_abs(blob_path, false, true, &blob_before);
    if (blob_before.st_size < 0) die("blob initramfs com tamanho invalido");
    struct elf_initramfs where =
        locate_elf_initramfs(elf, &elf_before, blob, (uint64_t)blob_before.st_size);
    if (blob_before.st_size < 0 || where.size != (uint64_t)blob_before.st_size ||
        !fd_bytes_equal(elf, blob, where.file_offset, 0, where.size))
        die("blob initramfs não é o intervalo ELF declarado");
    if (fstat(elf, &elf_after) < 0 || fstat(blob, &blob_after) < 0)
        die_errno("fstat depois do ELF");
    if (!stat_stable(&elf_before, &elf_after) ||
        !stat_stable(&blob_before, &blob_after))
        die("insumo mudou durante validação ELF");
    close(elf);
    close(blob);
}

static void command_elf_initramfs(const char *vmlinux_path,
                                  const char *blob_path) {
    verify_elf_initramfs(vmlinux_path, blob_path);
    char hex[65];
    hash_regular_abs(blob_path, hex, NULL);
    puts(hex);
}

static char *read_small_fd_stable(int fd, const char *what, struct stat *snapshot) {
    struct stat before, after;
    if (fstat(fd, &before) < 0) die_errno("fstat antes da leitura textual");
    if (!S_ISREG(before.st_mode) || before.st_size < 0 ||
        (uint64_t)before.st_size > SMALL_FILE_LIMIT)
        die("%s não é regular pequeno", what);
    size_t size = (size_t)before.st_size;
    char *text = xmalloc(size + 1);
    if (size) pread_all(fd, text, size, 0);
    text[size] = '\0';
    if (fstat(fd, &after) < 0) die_errno("fstat depois da leitura textual");
    if (!stat_stable(&before, &after)) die("%s mudou durante leitura", what);
    if (size == 0 || text[size - 1] != '\n' || memchr(text, '\0', size) ||
        memchr(text, '\r', size))
        die("%s não é texto canônico terminado por LF", what);
    for (size_t i = 0; i < size; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c != '\n' && (c < 0x20 || c > 0x7e))
            die("%s contém byte fora do ASCII canônico", what);
    }
    if (snapshot) *snapshot = before;
    return text;
}

static char *read_small_abs(const char *path, const char *what, char sha[65]) {
    int fd = open_regular_abs(path, false, true, NULL);
    char *text = read_small_fd_stable(fd, what, NULL);
    sha256_fd_stable(fd, sha, NULL);
    if (close(fd) < 0) die_errno("close texto");
    return text;
}

static const char *text_field(const char *text, const char *key,
                              char *value, size_t capacity) {
    size_t key_len = strlen(key);
    const char *p = text;
    bool found = false;
    while (*p) {
        const char *end = strchr(p, '\n');
        if (!end) die("texto sem LF final");
        size_t len = (size_t)(end - p);
        if (len > key_len && !memcmp(p, key, key_len) && p[key_len] == '=') {
            if (found) die("campo textual duplicado: %s", key);
            size_t value_len = len - key_len - 1;
            if (value_len == 0 || value_len >= capacity)
                die("valor ausente/longo para %s", key);
            memcpy(value, p + key_len + 1, value_len);
            value[value_len] = '\0';
            found = true;
        }
        p = end + 1;
    }
    return found ? value : NULL;
}

static const char *line_after(const char *p, char *line, size_t capacity,
                              const char *what) {
    const char *end = strchr(p, '\n');
    if (!end) die("%s sem LF", what);
    size_t length = (size_t)(end - p);
    if (length == 0 || length >= capacity) die("linha longa/vazia em %s", what);
    memcpy(line, p, length);
    line[length] = '\0';
    return end + 1;
}

static const char *ordered_value(const char *p, const char *key, char *value,
                                 size_t capacity, const char *what) {
    char line[8192];
    const char *next = line_after(p, line, sizeof(line), what);
    size_t n = strlen(key);
    if (strncmp(line, key, n) || line[n] != '=')
        die("ordem/campo inválido em %s: esperava %s", what, key);
    size_t length = strlen(line + n + 1);
    if (!length || length >= capacity) die("valor longo/vazio em %s.%s", what, key);
    memcpy(value, line + n + 1, length + 1);
    return next;
}

static bool safe_atom(const char *s) {
    if (!s || !*s) return false;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c <= 0x20 || c == 0x7f || c == '|' || c == '=') return false;
    }
    return true;
}

static bool valid_origin_kind(const char *s) {
    static const char *const values[] = {
        "repo", "official-tar", "built-from-source",
        "built-from-official-source", "built-from-crates", "provided-static",
        "development-prebuilt", "generated", "toolchain", "builder-rootfs",
    };
    for (size_t i = 0; i < ARRAY_LEN(values); i++)
        if (!strcmp(s, values[i])) return true;
    return false;
}

static const char empty_sha256[] =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct component_descriptor {
    const char *id;
    const char *materiality;
    const char *role;
    const char *artifact_kind;
};

static const struct component_descriptor component_descriptors[] = {
    {"busybox-config", "identity-only", "identity-only", "config"},
    {"busybox-source", "identity-only", "identity-only", "source"},
    {"busybox-static", "material", "runtime", "payload"},
    {"cargo-locks", "identity-only", "identity-only", "provenance"},
    {"e2fsprogs-source", "identity-only", "identity-only", "source"},
    {"e2fsprogs-static", "material", "runtime", "payload"},
    {"linux-config", "identity-only", "identity-only", "config"},
    {"linux-firmware-radeon", "material", "runtime", "payload"},
    {"linux-firmware-source", "identity-only", "identity-only", "source"},
    {"linux-source", "identity-only", "identity-only", "source"},
    {"live-lock-helper-source", "identity-only", "identity-only", "source"},
    {"live-lock-helper-static", "identity-only", "identity-only", "tool"},
    {"minipax-crates", "identity-only", "identity-only", "provenance"},
    {"minipax-static", "material", "runtime", "payload"},
    {"minitrue-crates", "identity-only", "identity-only", "provenance"},
    {"minitrue-static", "material", "runtime", "payload"},
    {"ncurses-source", "identity-only", "identity-only", "source"},
    {"ncurses-static", "material", "runtime", "linked-input"},
    {"overlay-files", "material", "runtime", "overlay"},
    {"runtime-musl-static", "material", "runtime", "linked-input"},
    {"scripts-live", "material", "runtime", "script"},
    {"toolchain-builder", "identity-only", "identity-only", "tool"},
    {"toolchain-musl", "identity-only", "identity-only", "tool"},
    {"toolchain-zig", "identity-only", "identity-only", "tool"},
    {"util-linux-source", "identity-only", "identity-only", "source"},
    {"util-linux-static", "material", "runtime", "payload"},
    {"vendor-scrypt", "identity-only", "identity-only", "provenance"},
};

static const char component_entry_schema[] =
    "ENTRY_SCHEMA=id|variant|status|materiality|role|artifact_kind|origin_kind|source_id|provenance|license|license_evidence_sha256|input_sha256|payload_sha256|config_sha256|contract_sha256|toolchain_id|toolchain_sha256";

struct components_info {
    char mode[16];
    char complete[4];
    char epoch[32];
    char runner_proof[65];
    char entries[65];
    char contract[65];
    size_t entry_count;
};

static void create_canonical_file(const char *path, const char *bytes,
                                  size_t length);
static void hash_self(char hex[65]);

static bool decimal_string(const char *s) {
    if (!s || !*s) return false;
    if (s[0] == '0' && s[1]) return false;
    for (; *s; s++) if (*s < '0' || *s > '9') return false;
    return true;
}

static bool canonical_material_license(const char *license) {
    if (!license || !*license || !strcmp(license, "-") ||
        !strcmp(license, "NOASSERTION") || !strcmp(license, "NONE"))
        return false;
    size_t length = strlen(license);
    if ((unsigned char)license[0] <= 0x20 ||
        (unsigned char)license[length - 1] <= 0x20)
        return false;
    for (const char *p = license; *p; p++)
        if (*p == '|' || *p == '\r' || *p == '\n' || *p == '\t')
            return false;
    return true;
}

static void sha256_bytes_hex(const void *bytes, size_t length, char hex[65]) {
    struct sha256_ctx c;
    unsigned char digest[32];
    sha256_init(&c);
    sha256_update(&c, bytes, length);
    sha256_final(&c, digest);
    hex_digest(digest, hex);
}

static void validate_component_entries(const char *entries, size_t count,
                                       const char *contract, const char *mode) {
    const char *p = entries;
    if (count != ARRAY_LEN(component_descriptors))
        die("conjunto live exige exatamente %zu ENTRY", ARRAY_LEN(component_descriptors));
    for (size_t index = 0; index < count; index++) {
        char line[8192];
        p = line_after(p, line, sizeof(line), "ENTRY");
        if (strncmp(line, "ENTRY=", 6)) die("linha não é ENTRY");
        char *fields[17];
        char *cursor = line + 6;
        for (size_t i = 0; i < ARRAY_LEN(fields); i++) {
            fields[i] = cursor;
            char *separator = strchr(cursor, '|');
            if (i + 1 == ARRAY_LEN(fields)) {
                if (separator) die("ENTRY tem campo extra");
                cursor += strlen(cursor);
            } else {
                if (!separator) die("ENTRY tem campo ausente");
                *separator = '\0';
                cursor = separator + 1;
            }
            if (!*fields[i]) die("ENTRY tem campo vazio");
        }
        const struct component_descriptor *d = &component_descriptors[index];
        if (strcmp(fields[0], d->id) || strcmp(fields[1], "live-efi") ||
            strcmp(fields[3], d->materiality) || strcmp(fields[4], d->role) ||
            strcmp(fields[5], d->artifact_kind))
            die("ENTRY fora da matriz factual em %s", d->id);
        if (strcmp(fields[2], "consumed") && strcmp(fields[2], "produced") &&
            strcmp(fields[2], "measured") && strcmp(fields[2], "not-consumed"))
            die("status inválido em %s", d->id);
        if (!valid_origin_kind(fields[6]) || !safe_atom(fields[7]) ||
            !safe_atom(fields[8]) || !safe_atom(fields[15]))
            die("origin/source/provenance/toolchain não canônico em %s", d->id);
        if (!strcmp(mode, "release") &&
            !strcmp(fields[6], "development-prebuilt"))
            die("release contém origin_kind development-prebuilt em %s", d->id);
        for (size_t i = 10; i <= 14; i++)
            if (!valid_sha256(fields[i])) die("hash inválido em %s", d->id);
        if (!valid_sha256(fields[16]) || strcmp(fields[14], contract))
            die("toolchain/contract hash inválido em %s", d->id);
        if (!strcmp(d->materiality, "identity-only")) {
            if (strcmp(fields[9], "-") || strcmp(fields[10], empty_sha256))
                die("identity-only exige LICENSE=-/evidence vazio em %s", d->id);
        } else {
            if (strcmp(fields[2], "consumed") && strcmp(fields[2], "produced"))
                die("material exige status consumed|produced em %s", d->id);
            if (!strcmp(fields[7], "-") || !strcmp(fields[8], "-") ||
                !canonical_material_license(fields[9]) ||
                !strcmp(fields[10], empty_sha256) ||
                !strcmp(fields[11], empty_sha256) ||
                !strcmp(fields[12], empty_sha256))
                die("material exige LICENSE/evidence/input/payload em %s", d->id);
        }
    }
    if (*p) die("ENTRY extra depois de ENTRY_COUNT");
}

static struct components_info parse_components_text(const char *text,
                                                     bool input_format,
                                                     const char **entries_out) {
    struct components_info info = {0};
    const char *p = text;
    char line[8192], variant[32], eligibility[8], count_text[32], schema[8192];
    p = line_after(p, line, sizeof(line), "Components header");
    const char *header = input_format ? "LIVE_COMPONENT_INPUTS_FORMAT=1" :
                                        "LIVE_COMPONENTS_FORMAT=1";
    if (strcmp(line, header)) die("cabeçalho Components inválido");
    p = ordered_value(p, "VARIANT", variant, sizeof(variant), "Components");
    p = ordered_value(p, "BUILD_MODE", info.mode, sizeof(info.mode), "Components");
    p = ordered_value(p, "RELEASE_INPUTS_COMPLETE", info.complete,
                      sizeof(info.complete), "Components");
    if (!input_format) {
        p = ordered_value(p, "RELEASE_ELIGIBLE", eligibility,
                          sizeof(eligibility), "Components");
        if (strcmp(eligibility, "no"))
            die("Components nunca promove release sem embedding");
    }
    p = ordered_value(p, "SOURCE_DATE_EPOCH", info.epoch,
                      sizeof(info.epoch), "Components");
    p = ordered_value(p, "RUNNER_PROOF_SHA256", info.runner_proof,
                      sizeof(info.runner_proof), "Components");
    if (!input_format)
        p = ordered_value(p, "ENTRIES_SHA256", info.entries,
                          sizeof(info.entries), "Components");
    p = ordered_value(p, "BUILD_CONTRACT_SHA256", info.contract,
                      sizeof(info.contract), "Components");
    p = ordered_value(p, "ENTRY_COUNT", count_text, sizeof(count_text), "Components");
    p = line_after(p, schema, sizeof(schema), "ENTRY_SCHEMA");
    if (strcmp(variant, "live-efi") ||
        (strcmp(info.mode, "release") && strcmp(info.mode, "development")) ||
        (strcmp(info.complete, "yes") && strcmp(info.complete, "no")) ||
        (!strcmp(info.mode, "release") && strcmp(info.complete, "yes")) ||
        (!strcmp(info.mode, "development") && strcmp(info.complete, "no")) ||
        !decimal_string(info.epoch) || !valid_sha256(info.runner_proof) ||
        !valid_sha256(info.contract) || !decimal_string(count_text) ||
        strcmp(schema, component_entry_schema))
        die("metadados Components incoerentes");
    if (!strcmp(info.mode, "release") && !strcmp(info.contract, empty_sha256))
        die("Components release contém build contract vazio");
    errno = 0;
    unsigned long parsed = strtoul(count_text, NULL, 10);
    if (errno || parsed != ARRAY_LEN(component_descriptors))
        die("ENTRY_COUNT inválido");
    info.entry_count = (size_t)parsed;
    validate_component_entries(p, info.entry_count, info.contract, info.mode);
    char measured[65];
    sha256_bytes_hex(p, strlen(p), measured);
    if (!input_format && strcmp(measured, info.entries))
        die("ENTRIES_SHA256 divergente");
    if (input_format) strcpy(info.entries, measured);
    if (entries_out) *entries_out = p;
    return info;
}

static void command_components(const char *input_path, const char *output_path) {
    char input_sha[65];
    char *input = read_small_abs(input_path, "LIVE_COMPONENT_INPUTS", input_sha);
    (void)input_sha;
    const char *entries;
    struct components_info info = parse_components_text(input, true, &entries);
    size_t capacity = strlen(entries) + 2048;
    char *output = xmalloc(capacity);
    int n = snprintf(output, capacity,
        "LIVE_COMPONENTS_FORMAT=1\nVARIANT=live-efi\nBUILD_MODE=%s\n"
        "RELEASE_INPUTS_COMPLETE=%s\nRELEASE_ELIGIBLE=no\n"
        "SOURCE_DATE_EPOCH=%s\nRUNNER_PROOF_SHA256=%s\n"
        "ENTRIES_SHA256=%s\nBUILD_CONTRACT_SHA256=%s\nENTRY_COUNT=%zu\n%s\n%s",
        info.mode, info.complete, info.epoch, info.runner_proof, info.entries,
        info.contract, info.entry_count, component_entry_schema, entries);
    if (n < 0 || (size_t)n >= capacity) die("Components render excedeu limite");
    (void)parse_components_text(output, false, NULL);
    create_canonical_file(output_path, output, (size_t)n);
    free(output);
    free(input);
}

struct runner_info {
    char mode[16];
    char authenticated[4];
    char runner_id[128];
    char runner_path[PATH_MAX + 1];
    char runner_sha[65];
    char builder_id[128];
    char builder_lock[65];
    char builder_root[65];
    char source_snapshot[65];
    char build_source[65];
    char live_lock_source[65];
    char helper_source[65];
    char helper_binary[65];
    char busybox_config[65];
    char linux_tar[65];
    char busybox_tar[65];
    char e2fs_tar[65];
    char ncurses_tar[65];
    char util_linux_tar[65];
    char minipax[65];
    char minitrue[65];
    char zig_tar[65];
    char zig_binary[65];
    char musl_tree[65];
    char epoch[32];
};

static bool lexical_absolute_path(const char *path) {
    if (!path || path[0] != '/' || path[1] == '\0' || strstr(path, "//"))
        return false;
    const char *p = path + 1;
    while (*p) {
        const char *slash = strchr(p, '/');
        size_t n = slash ? (size_t)(slash - p) : strlen(p);
        if (!n || (n == 1 && p[0] == '.') ||
            (n == 2 && p[0] == '.' && p[1] == '.')) return false;
        p = slash ? slash + 1 : p + n;
    }
    return true;
}

static struct runner_info parse_runner_text(const char *text) {
    struct runner_info info = {0};
    const char *p = text;
    char line[256], variant[32];
    p = line_after(p, line, sizeof(line), "Runner header");
    if (strcmp(line, "LIVE_RUNNER_PROOF_FORMAT=1"))
        die("Runner Proof header inválido");
    p = ordered_value(p, "VARIANT", variant, sizeof(variant), "Runner Proof");
    p = ordered_value(p, "BUILD_MODE", info.mode, sizeof(info.mode), "Runner Proof");
    p = ordered_value(p, "AUTHENTICATED", info.authenticated,
                      sizeof(info.authenticated), "Runner Proof");
    p = ordered_value(p, "RUNNER_ID", info.runner_id,
                      sizeof(info.runner_id), "Runner Proof");
    p = ordered_value(p, "RUNNER_PATH", info.runner_path,
                      sizeof(info.runner_path), "Runner Proof");
    p = ordered_value(p, "RUNNER_SHA256", info.runner_sha,
                      sizeof(info.runner_sha), "Runner Proof");
    p = ordered_value(p, "BUILDER_ID", info.builder_id,
                      sizeof(info.builder_id), "Runner Proof");
    p = ordered_value(p, "BUILDER_LOCK_SHA256", info.builder_lock,
                      sizeof(info.builder_lock), "Runner Proof");
    p = ordered_value(p, "BUILDER_ROOTFS_TREE_SHA256", info.builder_root,
                      sizeof(info.builder_root), "Runner Proof");
    p = ordered_value(p, "SOURCE_SNAPSHOT_SHA256", info.source_snapshot,
                      sizeof(info.source_snapshot), "Runner Proof");
    p = ordered_value(p, "BUILD_EFI_SOURCE_SHA256", info.build_source,
                      sizeof(info.build_source), "Runner Proof");
    p = ordered_value(p, "LIVE_LOCK_SOURCE_SHA256", info.live_lock_source,
                      sizeof(info.live_lock_source), "Runner Proof");
    p = ordered_value(p, "LIVE_LOCK_HELPER_SOURCE_SHA256", info.helper_source,
                      sizeof(info.helper_source), "Runner Proof");
    p = ordered_value(p, "LIVE_LOCK_HELPER_BINARY_SHA256", info.helper_binary,
                      sizeof(info.helper_binary), "Runner Proof");
    p = ordered_value(p, "BUSYBOX_CONFIG_SHA256", info.busybox_config,
                      sizeof(info.busybox_config), "Runner Proof");
    p = ordered_value(p, "LINUX_TAR_SHA256", info.linux_tar,
                      sizeof(info.linux_tar), "Runner Proof");
    p = ordered_value(p, "BUSYBOX_TAR_SHA256", info.busybox_tar,
                      sizeof(info.busybox_tar), "Runner Proof");
    p = ordered_value(p, "E2FSPROGS_TAR_SHA256", info.e2fs_tar,
                      sizeof(info.e2fs_tar), "Runner Proof");
    p = ordered_value(p, "NCURSES_TAR_SHA256", info.ncurses_tar,
                      sizeof(info.ncurses_tar), "Runner Proof");
    p = ordered_value(p, "UTIL_LINUX_TAR_SHA256", info.util_linux_tar,
                      sizeof(info.util_linux_tar), "Runner Proof");
    p = ordered_value(p, "MINIPAX_BINARY_SHA256", info.minipax,
                      sizeof(info.minipax), "Runner Proof");
    p = ordered_value(p, "MINITRUE_BINARY_SHA256", info.minitrue,
                      sizeof(info.minitrue), "Runner Proof");
    p = ordered_value(p, "ZIG_TAR_SHA256", info.zig_tar,
                      sizeof(info.zig_tar), "Runner Proof");
    p = ordered_value(p, "ZIG_BINARY_SHA256", info.zig_binary,
                      sizeof(info.zig_binary), "Runner Proof");
    p = ordered_value(p, "MUSL_TREE_SHA256", info.musl_tree,
                      sizeof(info.musl_tree), "Runner Proof");
    p = ordered_value(p, "SOURCE_DATE_EPOCH", info.epoch,
                      sizeof(info.epoch), "Runner Proof");
    if (*p) die("Runner Proof contém linha extra");
    if (strcmp(variant, "live-efi") ||
        (strcmp(info.mode, "release") && strcmp(info.mode, "development")) ||
        (strcmp(info.authenticated, "yes") && strcmp(info.authenticated, "no")) ||
        (!strcmp(info.mode, "release") && strcmp(info.authenticated, "yes")) ||
        (!strcmp(info.mode, "development") && strcmp(info.authenticated, "no")) ||
        !safe_atom(info.runner_id) || !safe_atom(info.builder_id) ||
        !decimal_string(info.epoch))
        die("Runner Proof tem identidade/modo inválido");
    char *hashes[] = {info.runner_sha, info.builder_lock, info.builder_root,
        info.source_snapshot, info.build_source, info.live_lock_source,
        info.helper_source, info.helper_binary, info.busybox_config,
        info.linux_tar, info.busybox_tar,
        info.e2fs_tar, info.ncurses_tar, info.util_linux_tar, info.minipax,
        info.minitrue, info.zig_tar, info.zig_binary, info.musl_tree};
    for (size_t i = 0; i < ARRAY_LEN(hashes); i++) {
        if (!valid_sha256(hashes[i])) die("Runner Proof contém hash inválido");
        if (!strcmp(info.mode, "release") && !strcmp(hashes[i], empty_sha256))
            die("Runner Proof release contém pin vazio");
    }
    if (!strcmp(info.mode, "release") && !lexical_absolute_path(info.runner_path))
        die("RUNNER_PATH release não é absoluto canônico");
    if (!strcmp(info.mode, "development") && !safe_atom(info.runner_path))
        die("RUNNER_PATH development não é átomo canônico");
    return info;
}

static void command_verify_runner(const char *path) {
    char hash[65];
    char *text = read_small_abs(path, "LIVE_RUNNER_PROOF", hash);
    (void)parse_runner_text(text);
    free(text);
}

struct embed_info {
    char efi[65];
    char vmlinux[65];
    char extractor[65];
    char blob[65];
    char cpio[65];
    char components[65];
};

static struct embed_info parse_embed_text(const char *text) {
    struct embed_info info = {0};
    const char *p = text;
    char line[128];
    p = line_after(p, line, sizeof(line), "Embed Proof header");
    if (strcmp(line, "LIVE_EMBED_PROOF_FORMAT=1")) die("Embed Proof header inválido");
    p = ordered_value(p, "BOOT_EFI_SHA256", info.efi, sizeof(info.efi), "Embed Proof");
    p = ordered_value(p, "VMLINUX_SHA256", info.vmlinux,
                      sizeof(info.vmlinux), "Embed Proof");
    p = ordered_value(p, "EXTRACTOR_SHA256", info.extractor,
                      sizeof(info.extractor), "Embed Proof");
    p = ordered_value(p, "INITRAMFS_BLOB_SHA256", info.blob,
                      sizeof(info.blob), "Embed Proof");
    p = ordered_value(p, "INITRAMFS_CPIO_SHA256", info.cpio,
                      sizeof(info.cpio), "Embed Proof");
    p = ordered_value(p, "EMBEDDED_COMPONENTS_SHA256", info.components,
                      sizeof(info.components), "Embed Proof");
    if (*p) die("Embed Proof contém linha extra");
    char *hashes[] = {info.efi, info.vmlinux, info.extractor, info.blob,
                      info.cpio, info.components};
    for (size_t i = 0; i < ARRAY_LEN(hashes); i++)
        if (!valid_sha256(hashes[i])) die("Embed Proof contém hash inválido");
    if (strcmp(info.blob, info.cpio))
        die("Embed Proof desconecta blob initramfs do CPIO autenticado");
    return info;
}

static const char payload_schema[] =
    "PAYLOAD_SCHEMA=id|variant|materiality|role|artifact_kind|origin_kind|source_id|provenance|license|license_evidence_sha256|payload_sha256";

static void validate_license_literal(const char *license, const char *evidence) {
    if (!canonical_material_license(license) || !valid_sha256(evidence) ||
        !strcmp(evidence, empty_sha256))
        die("payload material exige LICENSE/evidence conclusivos");
}

static void command_lock(const char *efi_path, const char *components_path,
                         const char *runner_path, const char *embed_path,
                         const char *license, const char *license_evidence,
                         const char *output_path) {
    validate_license_literal(license, license_evidence);
    char efi_sha[65], components_sha[65], runner_sha[65], embed_sha[65];
    char self_sha[65];
    hash_regular_abs(efi_path, efi_sha, NULL);
    char *components = read_small_abs(components_path, "LIVE_COMPONENTS", components_sha);
    char *runner = read_small_abs(runner_path, "LIVE_RUNNER_PROOF", runner_sha);
    char *embed = read_small_abs(embed_path, "LIVE_EMBED_PROOF", embed_sha);
    struct components_info ci = parse_components_text(components, false, NULL);
    struct runner_info ri = parse_runner_text(runner);
    struct embed_info ei = parse_embed_text(embed);
    if (strcmp(ci.mode, ri.mode) || strcmp(ci.epoch, ri.epoch) ||
        strcmp(ci.runner_proof, runner_sha) || strcmp(ei.efi, efi_sha) ||
        strcmp(ei.components, components_sha))
        die("Components/Runner/Embed/EFI não formam a mesma composição");
    hash_self(self_sha);
    if (strcmp(self_sha, ri.helper_binary))
        die("helper produtor diverge do pin binário no Runner Proof");
    const char *eligible = !strcmp(ci.mode, "release") ? "yes" : "no";
    char provenance[96];
    int pn = snprintf(provenance, sizeof(provenance), "embed-proof:%s", embed_sha);
    if (pn < 0 || (size_t)pn >= sizeof(provenance)) die("provenance longa");
    size_t capacity = strlen(license) + 4096;
    char *lock = xmalloc(capacity);
    int n = snprintf(lock, capacity,
        "LIVE_LOCK_FORMAT=1\nVARIANT=live-efi\nBUILD_MODE=%s\n"
        "RELEASE_ELIGIBLE=%s\nAUTHORITY_KIND=live-lock\n"
        "BOOT_EFI_SHA256=%s\nCOMPONENTS_SHA256=%s\nRUNNER_PROOF_SHA256=%s\n"
        "EMBED_PROOF_SHA256=%s\nENTRIES_SHA256=%s\nBUILD_CONTRACT_SHA256=%s\n"
        "SOURCE_DATE_EPOCH=%s\nINITRAMFS_BLOB_SHA256=%s\n"
        "INITRAMFS_CPIO_SHA256=%s\nEMBEDDED_COMPONENTS_SHA256=%s\n"
        "LIVE_LOCK_HELPER_BINARY_SHA256=%s\nSOURCE_SNAPSHOT_SHA256=%s\n"
        "BUILDER_LOCK_SHA256=%s\nBUILDER_ROOTFS_TREE_SHA256=%s\n%s\n"
        "PAYLOAD=boot-efi|live-efi|material|runtime|payload|built-from-source|"
        "generated:linux-efi-stub|%s|%s|%s|%s\n",
        ci.mode, eligible, efi_sha, components_sha, runner_sha, embed_sha,
        ci.entries, ci.contract, ci.epoch, ei.blob, ei.cpio, ei.components,
        self_sha, ri.source_snapshot, ri.builder_lock, ri.builder_root,
        payload_schema, provenance, license, license_evidence, efi_sha);
    if (n < 0 || (size_t)n >= capacity) die("LIVE_LOCK excedeu limite");
    create_canonical_file(output_path, lock, (size_t)n);
    free(lock);
    free(embed);
    free(runner);
    free(components);
}

struct lock_info {
    char mode[16];
    char eligible[4];
    char efi[65];
    char components[65];
    char runner[65];
    char embed[65];
    char entries[65];
    char contract[65];
    char epoch[32];
    char blob[65];
    char cpio[65];
    char embedded_components[65];
    char helper_binary[65];
    char source_snapshot[65];
    char builder_lock[65];
    char builder_root[65];
    char payload_license[4096];
    char payload_evidence[65];
    char payload_sha[65];
};

static struct lock_info parse_lock_text(const char *text) {
    struct lock_info info = {0};
    const char *p = text;
    char line[8192], variant[32], authority[32], schema[8192], payload[8192];
    p = line_after(p, line, sizeof(line), "Lock header");
    if (strcmp(line, "LIVE_LOCK_FORMAT=1")) die("LIVE_LOCK header inválido");
    p = ordered_value(p, "VARIANT", variant, sizeof(variant), "LIVE_LOCK");
    p = ordered_value(p, "BUILD_MODE", info.mode, sizeof(info.mode), "LIVE_LOCK");
    p = ordered_value(p, "RELEASE_ELIGIBLE", info.eligible,
                      sizeof(info.eligible), "LIVE_LOCK");
    p = ordered_value(p, "AUTHORITY_KIND", authority, sizeof(authority), "LIVE_LOCK");
    p = ordered_value(p, "BOOT_EFI_SHA256", info.efi, sizeof(info.efi), "LIVE_LOCK");
    p = ordered_value(p, "COMPONENTS_SHA256", info.components,
                      sizeof(info.components), "LIVE_LOCK");
    p = ordered_value(p, "RUNNER_PROOF_SHA256", info.runner,
                      sizeof(info.runner), "LIVE_LOCK");
    p = ordered_value(p, "EMBED_PROOF_SHA256", info.embed,
                      sizeof(info.embed), "LIVE_LOCK");
    p = ordered_value(p, "ENTRIES_SHA256", info.entries,
                      sizeof(info.entries), "LIVE_LOCK");
    p = ordered_value(p, "BUILD_CONTRACT_SHA256", info.contract,
                      sizeof(info.contract), "LIVE_LOCK");
    p = ordered_value(p, "SOURCE_DATE_EPOCH", info.epoch,
                      sizeof(info.epoch), "LIVE_LOCK");
    p = ordered_value(p, "INITRAMFS_BLOB_SHA256", info.blob,
                      sizeof(info.blob), "LIVE_LOCK");
    p = ordered_value(p, "INITRAMFS_CPIO_SHA256", info.cpio,
                      sizeof(info.cpio), "LIVE_LOCK");
    p = ordered_value(p, "EMBEDDED_COMPONENTS_SHA256", info.embedded_components,
                      sizeof(info.embedded_components), "LIVE_LOCK");
    p = ordered_value(p, "LIVE_LOCK_HELPER_BINARY_SHA256", info.helper_binary,
                      sizeof(info.helper_binary), "LIVE_LOCK");
    p = ordered_value(p, "SOURCE_SNAPSHOT_SHA256", info.source_snapshot,
                      sizeof(info.source_snapshot), "LIVE_LOCK");
    p = ordered_value(p, "BUILDER_LOCK_SHA256", info.builder_lock,
                      sizeof(info.builder_lock), "LIVE_LOCK");
    p = ordered_value(p, "BUILDER_ROOTFS_TREE_SHA256", info.builder_root,
                      sizeof(info.builder_root), "LIVE_LOCK");
    p = line_after(p, schema, sizeof(schema), "PAYLOAD_SCHEMA");
    p = ordered_value(p, "PAYLOAD", payload, sizeof(payload), "LIVE_LOCK");
    if (*p || strcmp(variant, "live-efi") || strcmp(authority, "live-lock") ||
        (strcmp(info.mode, "release") && strcmp(info.mode, "development")) ||
        (!strcmp(info.mode, "release") && strcmp(info.eligible, "yes")) ||
        (!strcmp(info.mode, "development") && strcmp(info.eligible, "no")) ||
        !decimal_string(info.epoch) || strcmp(schema, payload_schema))
        die("metadados LIVE_LOCK incoerentes");
    char *hashes[] = {info.efi, info.components, info.runner, info.embed,
        info.entries, info.contract, info.blob, info.cpio,
        info.embedded_components, info.helper_binary, info.source_snapshot,
        info.builder_lock, info.builder_root};
    for (size_t i = 0; i < ARRAY_LEN(hashes); i++)
        if (!valid_sha256(hashes[i])) die("LIVE_LOCK contém hash inválido");
    if (!strcmp(info.mode, "release") && !strcmp(info.contract, empty_sha256))
        die("LIVE_LOCK release contém build contract vazio");
    if (strcmp(info.blob, info.cpio))
        die("LIVE_LOCK desconecta blob initramfs do CPIO");
    char *fields[11];
    char *cursor = payload;
    for (size_t i = 0; i < ARRAY_LEN(fields); i++) {
        fields[i] = cursor;
        char *separator = strchr(cursor, '|');
        if (i + 1 == ARRAY_LEN(fields)) {
            if (separator) die("PAYLOAD contém campo extra");
        } else {
            if (!separator) die("PAYLOAD contém campo ausente");
            *separator = '\0';
            cursor = separator + 1;
        }
        if (!*fields[i]) die("PAYLOAD contém campo vazio");
    }
    if (strcmp(fields[0], "boot-efi") || strcmp(fields[1], "live-efi") ||
        strcmp(fields[2], "material") || strcmp(fields[3], "runtime") ||
        strcmp(fields[4], "payload") || strcmp(fields[5], "built-from-source") ||
        strcmp(fields[6], "generated:linux-efi-stub") ||
        strncmp(fields[7], "embed-proof:", 12) ||
        strcmp(fields[7] + 12, info.embed))
        die("PAYLOAD externo não descreve boot-efi live factual");
    if (strlen(fields[8]) >= sizeof(info.payload_license))
        die("LICENSE do PAYLOAD longa");
    strcpy(info.payload_license, fields[8]);
    if (strlen(fields[9]) != 64 || strlen(fields[10]) != 64)
        die("hash do PAYLOAD longo/incompleto");
    strcpy(info.payload_evidence, fields[9]);
    strcpy(info.payload_sha, fields[10]);
    validate_license_literal(info.payload_license, info.payload_evidence);
    if (!valid_sha256(info.payload_sha) || strcmp(info.payload_sha, info.efi))
        die("PAYLOAD_SHA256 não é BOOT_EFI_SHA256");
    return info;
}

static void require_text_sha_field(const char *text, const char *key,
                                   const char *expected, const char *what) {
    char value[65];
    if (!text_field(text, key, value, sizeof(value)) || !valid_sha256(value))
        die("%s sem %s sha256 canônico", what, key);
    if (expected && strcmp(value, expected))
        die("%s diverge em %s", what, key);
}

static void create_canonical_file(const char *path, const char *bytes,
                                  size_t length) {
    struct path_ref ref = open_parent(path, true);
    int fd = openat(ref.parent_fd, ref.leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    if (fd < 0) die_errno("criação NOREPLACE");
    bool linked = true;
    if (length) write_all(fd, bytes, length);
    if (fchmod(fd, 0644) < 0 || fsync(fd) < 0) {
        int saved = errno;
        close(fd);
        if (linked) unlinkat(ref.parent_fd, ref.leaf, 0);
        errno = saved;
        die_errno("fsync/chmod da saída");
    }
    if (close(fd) < 0) die_errno("close da saída");
    if (fsync(ref.parent_fd) < 0) die_errno("fsync do pai da saída");
    close(ref.parent_fd);
}

static void command_embed_proof(const char *efi_path, const char *vmlinux_path,
                                const char *blob_path, const char *decoded_path,
                                const char *cpio_path, const char *components_path,
                                const char *extractor_sha, const char *output_path) {
    if (!valid_sha256(extractor_sha)) die("hash do extrator não canônico");
    char efi_sha[65], vmlinux_sha[65], blob_sha[65], decoded_sha[65];
    char cpio_sha[65], components_sha[65];
    hash_regular_abs(efi_path, efi_sha, NULL);
    hash_regular_abs(vmlinux_path, vmlinux_sha, NULL);
    hash_regular_abs(blob_path, blob_sha, NULL);
    hash_regular_abs(decoded_path, decoded_sha, NULL);
    hash_regular_abs(cpio_path, cpio_sha, NULL);
    hash_regular_abs(components_path, components_sha, NULL);
    verify_elf_initramfs(vmlinux_path, blob_path);
    require_same_regular_bytes(blob_path, decoded_path,
                               "blob ELF e initramfs decodificado");
    require_same_regular_bytes(decoded_path, cpio_path,
                               "cpio decodificado e cpio do kernel");
    if (strcmp(blob_sha, decoded_sha) || strcmp(decoded_sha, cpio_sha))
        die("blob ELF/initramfs decodificado/cpio do kernel divergem");
    struct stat cpio_before, cpio_after, components_before, components_after;
    int cpio = open_regular_abs(cpio_path, false, true, &cpio_before);
    int components = open_regular_abs(components_path, false, true,
                                      &components_before);
    struct cpio_member_result member = find_newc_member(
        cpio, &cpio_before, "usr/share/distropica/LIVE_COMPONENTS");
    if (components_before.st_size < 0 ||
        member.size != (uint64_t)components_before.st_size ||
        strcmp(member.sha256, components_sha) ||
        !fd_bytes_equal(cpio, components, member.offset, 0, member.size))
        die("LIVE_COMPONENTS externo não é o membro exato do cpio");
    if (fstat(cpio, &cpio_after) < 0 ||
        fstat(components, &components_after) < 0)
        die_errno("fstat final da prova de embedding");
    if (!stat_stable(&cpio_before, &cpio_after) ||
        !stat_stable(&components_before, &components_after))
        die("insumo mudou durante prova de embedding");
    close(cpio);
    close(components);
    char proof[2048];
    int n = snprintf(proof, sizeof(proof),
        "LIVE_EMBED_PROOF_FORMAT=1\n"
        "BOOT_EFI_SHA256=%s\n"
        "VMLINUX_SHA256=%s\n"
        "EXTRACTOR_SHA256=%s\n"
        "INITRAMFS_BLOB_SHA256=%s\n"
        "INITRAMFS_CPIO_SHA256=%s\n"
        "EMBEDDED_COMPONENTS_SHA256=%s\n",
        efi_sha, vmlinux_sha, extractor_sha, blob_sha, cpio_sha,
        components_sha);
    if (n < 0 || (size_t)n >= sizeof(proof)) die("embed proof excedeu limite");
    create_canonical_file(output_path, proof, (size_t)n);
}

static const char *selected_failpoint;

static void failpoint(const char *name) {
    if (!name) return;
    if (selected_failpoint && !strncmp(selected_failpoint, "stop:", 5) &&
        !strcmp(selected_failpoint + 5, name)) {
        selected_failpoint = NULL;
        if (kill(getpid(), SIGSTOP) < 0) die_errno("SIGSTOP do failpoint");
    } else if (selected_failpoint && !strcmp(selected_failpoint, name)) {
        if (kill(getpid(), SIGKILL) < 0) die_errno("SIGKILL do failpoint");
        _exit(137);
    }
}

static void fsync_at_point(int fd, const char *point) {
    if (fsync(fd) < 0) die_errno("fsync");
    failpoint(point);
}

static void hash_self(char hex[65]) {
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) die_errno("open /proc/self/exe");
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode))
        die("helper em execução não é regular");
    if (st.st_uid != 0 && st.st_uid != geteuid())
        die("helper em execução não pertence a root/euid");
    if (st.st_nlink != 1) die("helper em execução tem hardlinks");
    if (!(st.st_mode & 0111) || (st.st_mode & 0022))
        die("helper em execução não é executável confiável");
    sha256_fd_stable(fd, hex, NULL);
    if (close(fd) < 0) die_errno("close do helper");
}

struct publish_hashes {
    char efi[65];
    char components[65];
    char runner_proof[65];
    char embed_proof[65];
    char lock[65];
};

static void validate_publication_documents(const char *components_path,
                                           const char *runner_path,
                                           const char *embed_path,
                                           const char *lock_path,
                                           struct publish_hashes *h) {
    char *components = read_small_abs(components_path, "LIVE_COMPONENTS",
                                      h->components);
    char *runner = read_small_abs(runner_path, "LIVE_RUNNER_PROOF",
                                  h->runner_proof);
    char *embed = read_small_abs(embed_path, "LIVE_EMBED_PROOF", h->embed_proof);
    char *lock = read_small_abs(lock_path, "LIVE_LOCK", h->lock);
    struct components_info ci = parse_components_text(components, false, NULL);
    struct runner_info ri = parse_runner_text(runner);
    struct embed_info ei = parse_embed_text(embed);
    struct lock_info li = parse_lock_text(lock);
    char self[65];
    hash_self(self);
    if (strcmp(ci.mode, ri.mode) || strcmp(ci.mode, li.mode) ||
        strcmp(ci.epoch, ri.epoch) || strcmp(ci.epoch, li.epoch) ||
        strcmp(ci.runner_proof, h->runner_proof) ||
        strcmp(li.efi, h->efi) || strcmp(li.components, h->components) ||
        strcmp(li.runner, h->runner_proof) || strcmp(li.embed, h->embed_proof) ||
        strcmp(li.entries, ci.entries) || strcmp(li.contract, ci.contract) ||
        strcmp(li.blob, ei.blob) || strcmp(li.cpio, ei.cpio) ||
        strcmp(ei.blob, ei.cpio) ||
        strcmp(li.embedded_components, ei.components) ||
        strcmp(ei.components, h->components) || strcmp(ei.efi, h->efi) ||
        strcmp(li.helper_binary, self) ||
        strcmp(li.helper_binary, ri.helper_binary) ||
        strcmp(li.source_snapshot, ri.source_snapshot) ||
        strcmp(li.builder_lock, ri.builder_lock) ||
        strcmp(li.builder_root, ri.builder_root))
        die("LIVE_LOCK diverge de EFI/Components/Runner/Embed/helper");
    if ((!strcmp(ci.mode, "release") &&
         (strcmp(ci.complete, "yes") || strcmp(ri.authenticated, "yes") ||
          strcmp(li.eligible, "yes"))) ||
        (!strcmp(ci.mode, "development") &&
         (strcmp(ci.complete, "no") || strcmp(ri.authenticated, "no") ||
          strcmp(li.eligible, "no"))))
        die("elegibilidade não deriva das provas reais");
    free(lock);
    free(embed);
    free(runner);
    free(components);
}

static bool at_lstat(int dirfd, const char *name, struct stat *st) {
    if (fstatat(dirfd, name, st, AT_SYMLINK_NOFOLLOW) == 0) return true;
    if (errno == ENOENT) return false;
    die_errno("fstatat de publicação");
}

static void validate_publish_regular(const struct stat *st, const char *what,
                                     bool allow_link_two) {
    if (!S_ISREG(st->st_mode)) die("%s não é regular", what);
    if (st->st_uid != geteuid()) die("%s não pertence ao euid", what);
    if ((st->st_mode & 07777) != 0644) die("%s não tem modo 0644", what);
    if (st->st_nlink != 1 && !(allow_link_two && st->st_nlink == 2))
        die("%s tem nlink inesperado: %ju", what, (uintmax_t)st->st_nlink);
}

static void hash_at_regular(int dirfd, const char *name, char hex[65],
                            struct stat *snapshot, bool staged) {
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) die_errno("openat para hash de publicação");
    struct stat st;
    if (fstat(fd, &st) < 0) die_errno("fstat de publicação");
    validate_publish_regular(&st, name, staged);
    sha256_fd_stable(fd, hex, NULL);
    struct stat after;
    if (fstat(fd, &after) < 0) die_errno("fstat final de publicação");
    if (!stat_stable(&st, &after)) die("%s mudou durante hash", name);
    if (snapshot) *snapshot = st;
    if (close(fd) < 0) die_errno("close de publicação");
}

static bool output_matches(int parent, const char *name, const char *expected,
                           bool allow_link_two) {
    struct stat lst;
    if (!at_lstat(parent, name, &lst)) return false;
    validate_publish_regular(&lst, name, allow_link_two);
    char actual[65];
    struct stat opened;
    hash_at_regular(parent, name, actual, &opened, allow_link_two);
    if (!stat_stable(&lst, &opened)) die("saída trocada durante validação: %s", name);
    if (strcmp(actual, expected)) die("saída existente diverge: %s", name);
    return true;
}

static void make_internal_name(char output[NAME_MAX + 1], const char *name,
                               const char *suffix) {
    int n = snprintf(output, NAME_MAX + 1, ".%s.%s", name, suffix);
    if (n < 0 || n > NAME_MAX) die("nome interno do journal longo");
}

static void make_internal_point(char output[128], const char *name,
                                const char *suffix) {
    int n = snprintf(output, 128, "after-%s-%s", name, suffix);
    if (n < 0 || n >= 128) die("nome de failpoint longo");
}

static void discard_known_temp(int txn, const char *temp) {
    struct stat st;
    if (!at_lstat(txn, temp, &st)) return;
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
        ((st.st_mode & 07777) != 0600 && (st.st_mode & 07777) != 0644))
        die("temporário estrangeiro/inválido no journal: %s", temp);
    if (unlinkat(txn, temp, 0) < 0) die_errno("unlink de temporário parcial");
    if (fsync(txn) < 0) die_errno("fsync após temporário parcial");
}

static void rename_noreplace(int from_dir, const char *from, int to_dir,
                             const char *to) {
#ifdef SYS_renameat2
    if (syscall(SYS_renameat2, from_dir, from, to_dir, to,
                RENAME_NOREPLACE) == 0)
        return;
    if (errno == ENOSYS || errno == EINVAL)
        die("kernel/filesystem sem renameat2(RENAME_NOREPLACE)");
    die_errno("renameat2 NOREPLACE");
#else
    (void)from_dir; (void)from; (void)to_dir; (void)to;
    die("plataforma sem SYS_renameat2; não há fallback mais fraco");
#endif
}

static void validate_existing_state(int txn, const char *name,
                                    const char *contents) {
    size_t length = strlen(contents);
    struct stat st;
    if (!at_lstat(txn, name, &st)) die("estado persistente desapareceu");
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 07777) != 0600 || st.st_nlink != 1 ||
        st.st_size < 0 || (size_t)st.st_size != length)
        die("estado persistente inválido: %s", name);
    int fd = openat(txn, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) die_errno("openat estado");
    char *actual = xmalloc(length ? length : 1);
    if (length) pread_all(fd, actual, length, 0);
    struct stat after;
    if (fstat(fd, &after) < 0) die_errno("fstat estado");
    if (!stat_stable(&st, &after) || (length && memcmp(actual, contents, length)))
        die("estado persistente diverge: %s", name);
    free(actual);
    /* Retry não presume que uma queda anterior alcançou o fsync do arquivo. */
    if (fsync(fd) < 0) die_errno("fsync de estado recuperado");
    if (close(fd) < 0) die_errno("close de estado");
    if (fsync(txn) < 0) die_errno("fsync do journal recuperado");
}

static void ensure_state_file(int txn, const char *name, const char *contents,
                              const char *file_point, const char *dir_point) {
    char temp[NAME_MAX + 1];
    make_internal_name(temp, name, "tmp");
    struct stat st;
    if (at_lstat(txn, name, &st)) {
        discard_known_temp(txn, temp);
        validate_existing_state(txn, name, contents);
        return;
    }
    discard_known_temp(txn, temp);
    int fd = openat(txn, temp,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    if (fd < 0) die_errno("criação de temporário de estado");
    char point[128];
    make_internal_point(point, name, "temp-create");
    failpoint(point);
    size_t length = strlen(contents);
    size_t first = length > 1 ? length / 2 : length;
    if (first) write_all(fd, contents, first);
    make_internal_point(point, name, "temp-mid-write");
    failpoint(point);
    if (length > first) write_all(fd, contents + first, length - first);
    make_internal_point(point, name, "temp-complete-before-fsync");
    failpoint(point);
    fsync_at_point(fd, file_point);
    if (close(fd) < 0) die_errno("close de temporário de estado");
    rename_noreplace(txn, temp, txn, name);
    make_internal_point(point, name, "temp-rename");
    failpoint(point);
    fsync_at_point(txn, dir_point);
    validate_existing_state(txn, name, contents);
}

static bool validate_state_if_present(int txn, const char *name,
                                      const char *contents) {
    struct stat st;
    if (!at_lstat(txn, name, &st)) return false;
    ensure_state_file(txn, name, contents, NULL, NULL);
    return true;
}

static bool directory_is_empty(int fd) {
    int copy = dup(fd);
    if (copy < 0) die_errno("dup do journal");
    DIR *dir = fdopendir(copy);
    if (!dir) die_errno("fdopendir do journal");
    bool empty = true;
    errno = 0;
    for (struct dirent *de; (de = readdir(dir));) {
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
            empty = false;
            break;
        }
    }
    if (errno) die_errno("readdir do journal");
    if (closedir(dir) < 0) die_errno("closedir do journal");
    return empty;
}

static bool known_journal_name(const char *name) {
    static const char *const base[] = {
        "OWNER", "REQUEST", "EFI", "COMPONENTS", "RUNNER_PROOF", "LOCK",
        "READY", "COMMITTED",
    };
    for (size_t i = 0; i < ARRAY_LEN(base); i++) {
        if (!strcmp(name, base[i])) return true;
        char temp[NAME_MAX + 1];
        make_internal_name(temp, base[i], "tmp");
        if (!strcmp(name, temp)) return true;
    }
    return false;
}

static void validate_journal_names(int txn) {
    int copy = dup(txn);
    if (copy < 0) die_errno("dup do journal para inventário");
    DIR *dir = fdopendir(copy);
    if (!dir) die_errno("fdopendir do journal para inventário");
    errno = 0;
    for (struct dirent *de; (de = readdir(dir));) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (!known_journal_name(de->d_name))
            die("controle estrangeiro no journal: %s", de->d_name);
    }
    if (errno) die_errno("readdir do inventário do journal");
    if (closedir(dir) < 0) die_errno("closedir do inventário do journal");
}

static void verify_stage_hash(int txn, const char *name, const char *expected) {
    char actual[65];
    hash_at_regular(txn, name, actual, NULL, true);
    if (strcmp(actual, expected)) die("staging diverge: %s", name);
}

static void fsync_existing_stage(int txn, const char *name) {
    int fd = openat(txn, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) die_errno("openat stage recuperado");
    struct stat st;
    if (fstat(fd, &st) < 0) die_errno("fstat stage recuperado");
    validate_publish_regular(&st, name, true);
    if (fsync(fd) < 0) die_errno("fsync stage recuperado");
    if (close(fd) < 0) die_errno("close stage recuperado");
    if (fsync(txn) < 0) die_errno("fsync journal com stage recuperado");
}

static void ensure_stage_file(int txn, const char *stage_name,
                              const char *source_path, const char *expected,
                              const char *file_point, const char *dir_point) {
    struct stat existing;
    char temp[NAME_MAX + 1];
    make_internal_name(temp, stage_name, "tmp");
    if (at_lstat(txn, stage_name, &existing)) {
        discard_known_temp(txn, temp);
        verify_stage_hash(txn, stage_name, expected);
        fsync_existing_stage(txn, stage_name);
        return;
    }
    discard_known_temp(txn, temp);
    struct stat source_before, source_after;
    int source = open_regular_abs(source_path, true, true, &source_before);
    char source_hash[65];
    sha256_fd_stable(source, source_hash, NULL);
    if (strcmp(source_hash, expected)) die("fonte mudou antes do staging");
    int dest = openat(txn, temp,
                      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                      0600);
    if (dest < 0) die_errno("criação do temporário de staging");
    char point[128];
    make_internal_point(point, stage_name, "temp-create");
    failpoint(point);
    unsigned char *buf = xmalloc(IO_CHUNK);
    bool midpoint = false;
    for (;;) {
        ssize_t n = read(source, buf, IO_CHUNK);
        if (n < 0) {
            if (errno == EINTR) continue;
            die_errno("read do staging");
        }
        if (n == 0) break;
        if (!midpoint) {
            size_t first = n > 1 ? (size_t)n / 2 : (size_t)n;
            if (first) write_all(dest, buf, first);
            make_internal_point(point, stage_name, "temp-mid-write");
            failpoint(point);
            if ((size_t)n > first)
                write_all(dest, buf + first, (size_t)n - first);
            midpoint = true;
        } else {
            write_all(dest, buf, (size_t)n);
        }
    }
    free(buf);
    if (fchmod(dest, 0644) < 0) die_errno("chmod do staging");
    make_internal_point(point, stage_name, "temp-complete-before-fsync");
    failpoint(point);
    fsync_at_point(dest, file_point);
    if (fstat(source, &source_after) < 0) die_errno("fstat final da fonte");
    if (!stat_stable(&source_before, &source_after))
        die("fonte mudou durante staging");
    if (close(source) < 0 || close(dest) < 0) die_errno("close do staging");
    char temp_hash[65];
    hash_at_regular(txn, temp, temp_hash, NULL, false);
    if (strcmp(temp_hash, expected)) die("temporário de staging diverge");
    rename_noreplace(txn, temp, txn, stage_name);
    make_internal_point(point, stage_name, "temp-rename");
    failpoint(point);
    fsync_at_point(txn, dir_point);
    verify_stage_hash(txn, stage_name, expected);
    fsync_existing_stage(txn, stage_name);
}

static void reconcile_link(int txn, const char *stage_name, int parent,
                           const char *output_name, const char *expected,
                           const char *point) {
    if (linkat(txn, stage_name, parent, output_name, 0) == 0) {
        failpoint(point);
        return;
    }
    if (errno != EEXIST) die_errno("hardlink NOREPLACE de publicação");
    struct stat stage, output;
    if (fstatat(txn, stage_name, &stage, AT_SYMLINK_NOFOLLOW) < 0 ||
        fstatat(parent, output_name, &output, AT_SYMLINK_NOFOLLOW) < 0)
        die_errno("fstatat ao reconciliar hardlink");
    validate_publish_regular(&stage, stage_name, true);
    validate_publish_regular(&output, output_name, true);
    if (stage.st_dev != output.st_dev || stage.st_ino != output.st_ino)
        die("colisão NOREPLACE não pertence à transação: %s", output_name);
    char actual[65];
    hash_at_regular(parent, output_name, actual, NULL, true);
    if (strcmp(actual, expected)) die("hardlink reconciliado tem hash divergente");
}

static void cleanup_file(int txn, const char *name, const char *expected_hash,
                         mode_t expected_mode, const char *unlink_point,
                         const char *sync_point) {
    struct stat st;
    if (!at_lstat(txn, name, &st)) return;
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 07777) != expected_mode)
        die("cleanup recusou nó inesperado: %s", name);
    if (expected_hash) verify_stage_hash(txn, name, expected_hash);
    if (unlinkat(txn, name, 0) < 0) die_errno("unlinkat do journal");
    failpoint(unlink_point);
    fsync_at_point(txn, sync_point);
}

static void cleanup_transaction(int parent, int txn, const char *txn_name,
                                const struct publish_hashes *h) {
    cleanup_file(txn, "EFI", h->efi, 0644,
                 "after-cleanup-efi-unlink", "after-cleanup-efi-fsync");
    cleanup_file(txn, "COMPONENTS", h->components, 0644,
                 "after-cleanup-components-unlink",
                 "after-cleanup-components-fsync");
    cleanup_file(txn, "RUNNER_PROOF", h->runner_proof, 0644,
                 "after-cleanup-runner-proof-unlink",
                 "after-cleanup-runner-proof-fsync");
    cleanup_file(txn, "LOCK", h->lock, 0644,
                 "after-cleanup-lock-unlink", "after-cleanup-lock-fsync");
    cleanup_file(txn, "READY", NULL, 0600,
                 "after-cleanup-ready-unlink", "after-cleanup-ready-fsync");
    cleanup_file(txn, "REQUEST", NULL, 0600,
                 "after-cleanup-request-unlink", "after-cleanup-request-fsync");
    cleanup_file(txn, "OWNER", NULL, 0600,
                 "after-cleanup-owner-unlink", "after-cleanup-owner-fsync");
    /* COMMITTED é deliberadamente o último nome removido. Se houver SIGKILL
     * no intervalo final unlink→rmdir, o retry só aceita o journal vazio. */
    cleanup_file(txn, "COMMITTED", NULL, 0600,
                 "after-cleanup-committed-unlink",
                 "after-cleanup-committed-fsync");
    if (close(txn) < 0) die_errno("close do journal");
    if (unlinkat(parent, txn_name, AT_REMOVEDIR) < 0)
        die_errno("rmdir do journal");
    failpoint("after-journal-rmdir");
    fsync_at_point(parent, "after-journal-parent-fsync");
}

static void command_publish(const char *efi_path, const char *components_path,
                            const char *runner_path, const char *embed_path,
                            const char *lock_path, const char *output_path,
                            const char *failure) {
    selected_failpoint = failure;
    struct publish_hashes h = {0};
    hash_regular_abs(efi_path, h.efi, NULL);
    validate_publication_documents(components_path, runner_path, embed_path,
                                   lock_path, &h);
    char embed_hash_value[65];
    char *embed_text = read_small_abs(embed_path, "LIVE_EMBED_PROOF",
                                      embed_hash_value);
    require_text_sha_field(embed_text, "BOOT_EFI_SHA256", h.efi,
                           "LIVE_EMBED_PROOF");
    free(embed_text);

    struct path_ref out = open_parent(output_path, true);
    size_t base_len = strlen(out.leaf);
    if (base_len + strlen(".live-runner-proof") > NAME_MAX ||
        base_len + strlen(".live-components") > NAME_MAX ||
        base_len + strlen(".live-lock") > NAME_MAX || base_len + 15 > NAME_MAX)
        die("nome da saída longo demais para sidecars/journal");
    char components_name[NAME_MAX + 1], runner_name[NAME_MAX + 1];
    char lock_name[NAME_MAX + 1], txn_name[NAME_MAX + 1];
    snprintf(components_name, sizeof(components_name), "%s.live-components", out.leaf);
    snprintf(runner_name, sizeof(runner_name), "%s.live-runner-proof", out.leaf);
    snprintf(lock_name, sizeof(lock_name), "%s.live-lock", out.leaf);
    snprintf(txn_name, sizeof(txn_name), ".%s.live-publish", out.leaf);

    struct stat txn_st;
    bool txn_exists = at_lstat(out.parent_fd, txn_name, &txn_st);
    bool have_efi = output_matches(out.parent_fd, out.leaf, h.efi, txn_exists);
    bool have_components = output_matches(out.parent_fd, components_name,
                                          h.components, txn_exists);
    bool have_runner = output_matches(out.parent_fd, runner_name,
                                      h.runner_proof, txn_exists);
    bool have_lock = output_matches(out.parent_fd, lock_name, h.lock, txn_exists);
    unsigned present = have_efi + have_components + have_runner + have_lock;
    if (present && present != 4 && !txn_exists)
        die("publicação parcial sem journal recuperável");
    if (present == 4 && !txn_exists) {
        fsync_at_point(out.parent_fd, "after-idempotent-parent-fsync");
        close(out.parent_fd);
        return;
    }
    if (!txn_exists) {
        if (mkdirat(out.parent_fd, txn_name, 0700) < 0)
            die_errno("mkdir do journal");
        failpoint("after-journal-mkdir");
        fsync_at_point(out.parent_fd, "after-journal-create-parent-fsync");
    } else if (!S_ISDIR(txn_st.st_mode) || txn_st.st_uid != geteuid() ||
               (txn_st.st_mode & 07777) != 0700) {
        die("journal existente não é diretório privado do euid");
    }
    int txn = openat(out.parent_fd, txn_name,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (txn < 0) die_errno("open do journal");
    struct stat opened_txn, parent_st;
    if (fstat(txn, &opened_txn) < 0 || fstat(out.parent_fd, &parent_st) < 0)
        die_errno("fstat do journal/pai");
    if (!S_ISDIR(opened_txn.st_mode) || opened_txn.st_uid != geteuid() ||
        (opened_txn.st_mode & 07777) != 0700 ||
        opened_txn.st_dev != parent_st.st_dev)
        die("journal não é privado/no mesmo filesystem");
    validate_journal_names(txn);
    if (txn_exists) {
        /* Se a queda ocorreu entre mkdir/link e o fsync do pai, esta abertura
         * torna novamente durável o nome pelo qual a recuperação prossegue. */
        fsync_at_point(out.parent_fd, "after-journal-reopen-parent-fsync");
        fsync_at_point(txn, "after-journal-reopen-dir-fsync");
    }

    char owner[PATH_MAX + 128];
    int owner_len = snprintf(owner, sizeof(owner),
        "LIVE_PUBLISH_OWNER_FORMAT=1\nEUID=%ju\nOUTPUT=%s\n",
        (uintmax_t)geteuid(), out.leaf);
    if (owner_len < 0 || (size_t)owner_len >= sizeof(owner)) die("OWNER longo");
    char request[1024];
    int request_len = snprintf(request, sizeof(request),
        "LIVE_PUBLISH_REQUEST_FORMAT=1\n"
        "EFI_SHA256=%s\nCOMPONENTS_SHA256=%s\n"
        "RUNNER_PROOF_SHA256=%s\nEMBED_PROOF_SHA256=%s\nLOCK_SHA256=%s\n",
        h.efi, h.components, h.runner_proof, h.embed_proof, h.lock);
    if (request_len < 0 || (size_t)request_len >= sizeof(request))
        die("REQUEST longo");
    if (present == 4) {
        struct stat committed;
        bool already_committed = at_lstat(txn, "COMMITTED", &committed);
        if (already_committed) {
            ensure_state_file(txn, "COMMITTED", "LIVE_PUBLISH_COMMITTED=1\n",
                              "after-committed-file-fsync",
                              "after-committed-dir-fsync");
            (void)validate_state_if_present(txn, "OWNER", owner);
            (void)validate_state_if_present(txn, "REQUEST", request);
            (void)validate_state_if_present(txn, "READY",
                                            "LIVE_PUBLISH_READY=1\n");
        } else {
            struct stat ready;
            bool have_ready = at_lstat(txn, "READY", &ready);
            bool have_owner = validate_state_if_present(txn, "OWNER", owner);
            bool have_request = validate_state_if_present(txn, "REQUEST", request);
            if (!have_ready) {
                if (have_owner || have_request || !directory_is_empty(txn))
                    die("quarteto existe sem READY/COMMITTED persistente");
                if (close(txn) < 0) die_errno("close do journal terminal");
                if (unlinkat(out.parent_fd, txn_name, AT_REMOVEDIR) < 0)
                    die_errno("rmdir do journal terminal");
                failpoint("after-terminal-journal-rmdir");
                fsync_at_point(out.parent_fd,
                               "after-terminal-journal-parent-fsync");
                close(out.parent_fd);
                return;
            }
            if (!have_owner || !have_request)
                die("READY sem OWNER/REQUEST persistentes");
            ensure_state_file(txn, "READY", "LIVE_PUBLISH_READY=1\n",
                              "after-ready-file-fsync", "after-ready-dir-fsync");
            verify_stage_hash(txn, "EFI", h.efi);
            verify_stage_hash(txn, "COMPONENTS", h.components);
            verify_stage_hash(txn, "RUNNER_PROOF", h.runner_proof);
            verify_stage_hash(txn, "LOCK", h.lock);
            reconcile_link(txn, "COMPONENTS", out.parent_fd, components_name,
                           h.components, "after-components-link");
            reconcile_link(txn, "RUNNER_PROOF", out.parent_fd, runner_name,
                           h.runner_proof, "after-runner-proof-link");
            reconcile_link(txn, "LOCK", out.parent_fd, lock_name,
                           h.lock, "after-lock-link");
            reconcile_link(txn, "EFI", out.parent_fd, out.leaf, h.efi,
                           "after-efi-link");
            fsync_at_point(out.parent_fd, "after-reconcile-parent-fsync");
            ensure_state_file(txn, "COMMITTED", "LIVE_PUBLISH_COMMITTED=1\n",
                              "after-committed-file-fsync",
                              "after-committed-dir-fsync");
        }
        cleanup_transaction(out.parent_fd, txn, txn_name, &h);
        close(out.parent_fd);
        return;
    }
    ensure_state_file(txn, "OWNER", owner,
                      "after-owner-file-fsync", "after-owner-dir-fsync");
    ensure_state_file(txn, "REQUEST", request,
                      "after-request-file-fsync", "after-request-dir-fsync");
    ensure_stage_file(txn, "EFI", efi_path, h.efi,
                      "after-stage-efi-file-fsync", "after-stage-efi-dir-fsync");
    ensure_stage_file(txn, "COMPONENTS", components_path, h.components,
                      "after-stage-components-file-fsync",
                      "after-stage-components-dir-fsync");
    ensure_stage_file(txn, "RUNNER_PROOF", runner_path, h.runner_proof,
                      "after-stage-runner-proof-file-fsync",
                      "after-stage-runner-proof-dir-fsync");
    ensure_stage_file(txn, "LOCK", lock_path, h.lock,
                      "after-stage-lock-file-fsync", "after-stage-lock-dir-fsync");
    ensure_state_file(txn, "READY", "LIVE_PUBLISH_READY=1\n",
                      "after-ready-file-fsync", "after-ready-dir-fsync");

    reconcile_link(txn, "COMPONENTS", out.parent_fd, components_name,
                   h.components, "after-components-link");
    reconcile_link(txn, "RUNNER_PROOF", out.parent_fd, runner_name,
                   h.runner_proof, "after-runner-proof-link");
    reconcile_link(txn, "LOCK", out.parent_fd, lock_name,
                   h.lock, "after-lock-link");
    fsync_at_point(out.parent_fd, "after-sidecars-parent-fsync");
    reconcile_link(txn, "EFI", out.parent_fd, out.leaf, h.efi,
                   "after-efi-link");
    fsync_at_point(out.parent_fd, "after-efi-parent-fsync");
    ensure_state_file(txn, "COMMITTED", "LIVE_PUBLISH_COMMITTED=1\n",
                      "after-committed-file-fsync", "after-committed-dir-fsync");

    if (!output_matches(out.parent_fd, out.leaf, h.efi, true) ||
        !output_matches(out.parent_fd, components_name, h.components, true) ||
        !output_matches(out.parent_fd, runner_name, h.runner_proof, true) ||
        !output_matches(out.parent_fd, lock_name, h.lock, true))
        die("trio/quarteto publicado não reconcilia");
    cleanup_transaction(out.parent_fd, txn, txn_name, &h);
    close(out.parent_fd);
}

static void command_check_output(const char *output_path) {
    struct path_ref out = open_parent(output_path, true);
    size_t n = strlen(out.leaf);
    if (n + strlen(".live-runner-proof") > NAME_MAX || n + 15 > NAME_MAX)
        die("nome da saída longo demais");
    char components[NAME_MAX + 1], runner[NAME_MAX + 1];
    char lock[NAME_MAX + 1], journal[NAME_MAX + 1];
    snprintf(components, sizeof(components), "%s.live-components", out.leaf);
    snprintf(runner, sizeof(runner), "%s.live-runner-proof", out.leaf);
    snprintf(lock, sizeof(lock), "%s.live-lock", out.leaf);
    snprintf(journal, sizeof(journal), ".%s.live-publish", out.leaf);
    const char *names[] = {out.leaf, components, runner, lock, journal};
    struct stat st;
    for (size_t i = 0; i < ARRAY_LEN(names); i++)
        if (at_lstat(out.parent_fd, names[i], &st))
            die("saída/journal já existe antes do build: %s", names[i]);
    close(out.parent_fd);
}

static void require_regular_hash(const char *path, const char *expected,
                                 const char *what) {
    if (!valid_sha256(expected)) die("pin inválido para %s", what);
    char actual[65];
    hash_regular_abs(path, actual, NULL);
    if (strcmp(actual, expected)) die("hash divergente em %s", what);
}

static const char work_marker_name[] = ".distropica-live-work";

static void hash_release_request(char **a, char hex[65]) {
    struct sha256_ctx c;
    sha256_init(&c);
    static const char domain[] = "DISTROPICA_LIVE_WORK_REQUEST_FORMAT=1\0";
    sha256_update(&c, domain, sizeof(domain));
    for (uint32_t i = 0; i < 20; i++) {
        hash_u32(&c, i);
        hash_bytes(&c, a[i], strlen(a[i]));
    }
    unsigned char digest[32];
    sha256_final(&c, digest);
    hex_digest(digest, hex);
}

static size_t format_work_marker(char *output, size_t capacity,
                                 const struct stat *work,
                                 const char *proof_sha,
                                 const char *request_sha) {
    int n = snprintf(output, capacity,
        "DISTROPICA_LIVE_WORK_FORMAT=1\n"
        "VARIANT=live-efi\n"
        "RUNNER_PROOF_SHA256=%s\n"
        "REQUEST_SHA256=%s\n"
        "WORK_DEVICE=%ju\n"
        "WORK_INODE=%ju\n"
        "WORK_UID=%ju\n",
        proof_sha, request_sha, (uintmax_t)work->st_dev,
        (uintmax_t)work->st_ino, (uintmax_t)work->st_uid);
    if (n < 0 || (size_t)n >= capacity) die("marcador do WORK longo");
    return (size_t)n;
}

static void require_work_inventory(int work, bool pristine) {
    if (!pristine) return;
    int copy = dup(work);
    if (copy < 0) die_errno("dup do WORK");
    DIR *dir = fdopendir(copy);
    if (!dir) die_errno("fdopendir do WORK");
    unsigned entries = 0;
    errno = 0;
    for (struct dirent *de; (de = readdir(dir));) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (strcmp(de->d_name, work_marker_name))
            die("WORK release não está pristine: %s", de->d_name);
        entries++;
    }
    if (errno) die_errno("readdir do WORK");
    if (closedir(dir) < 0) die_errno("closedir do WORK");
    if (entries != 1) die("WORK release pristine precisa conter só o marcador");
}

static void validate_release_work_fd(int work, const char *marker_expected,
                                     const char *request_expected,
                                     const char *proof_expected,
                                     bool pristine, char marker_actual[65]) {
    if (!valid_sha256(marker_expected) || !valid_sha256(request_expected) ||
        !valid_sha256(proof_expected))
        die("pin do WORK release não canônico");
    struct stat work_before, work_after;
    if (fstat(work, &work_before) < 0) die_errno("fstat do WORK");
    if (!S_ISDIR(work_before.st_mode) || work_before.st_uid != geteuid() ||
        (work_before.st_mode & 07777) != 0700)
        die("WORK release precisa ser diretório 0700 do euid");

    struct stat marker_lstat;
    if (fstatat(work, work_marker_name, &marker_lstat,
                AT_SYMLINK_NOFOLLOW) < 0)
        die_errno("lstat do marcador do WORK");
    if (!S_ISREG(marker_lstat.st_mode) ||
        marker_lstat.st_uid != geteuid() ||
        marker_lstat.st_gid != getegid() ||
        (marker_lstat.st_mode & 07777) != 0600 || marker_lstat.st_nlink != 1)
        die("marcador do WORK precisa ser regular 0600/uid+gid efetivos/nlink=1");
    int marker = openat(work, work_marker_name,
                        O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (marker < 0) die_errno("open do marcador do WORK");
    struct stat marker_opened;
    char *text = read_small_fd_stable(marker, "marcador do WORK",
                                      &marker_opened);
    if (!stat_stable(&marker_lstat, &marker_opened))
        die("marcador do WORK trocado durante abertura");
    sha256_fd_stable(marker, marker_actual, NULL);
    if (strcmp(marker_actual, marker_expected))
        die("hash do marcador do WORK diverge");
    char canonical[1024];
    size_t canonical_len = format_work_marker(canonical, sizeof(canonical),
                                              &work_before, proof_expected,
                                              request_expected);
    if (strlen(text) != canonical_len || memcmp(text, canonical, canonical_len))
        die("marcador do WORK diverge de proof/request/inode");
    free(text);
    if (close(marker) < 0) die_errno("close do marcador do WORK");
    require_work_inventory(work, pristine);
    if (fstat(work, &work_after) < 0) die_errno("fstat final do WORK");
    if (!stat_stable(&work_before, &work_after))
        die("WORK mudou durante validação");
}

static void create_release_work(const char *path, const char *rootfs,
                                const char *proof_sha,
                                const char *request_sha,
                                char marker_sha[65]) {
    struct path_ref work_parent = open_parent(path, true);
    struct path_ref root_parent = open_parent(rootfs, false);
    struct stat wp, rp, root_leaf, existing;
    if (fstat(work_parent.parent_fd, &wp) < 0 ||
        fstat(root_parent.parent_fd, &rp) < 0)
        die_errno("fstat dos pais de WORK/rootfs");
    if (wp.st_dev != rp.st_dev || wp.st_ino != rp.st_ino)
        die("WORK release precisa ser irmão externo do rootfs");
    if (!strcmp(work_parent.leaf, root_parent.leaf))
        die("WORK release não pode ser o rootfs");
    if (fstatat(root_parent.parent_fd, root_parent.leaf, &root_leaf,
                AT_SYMLINK_NOFOLLOW) < 0 || !S_ISDIR(root_leaf.st_mode))
        die("rootfs irmão do WORK não é diretório real");
    if (at_lstat(work_parent.parent_fd, work_parent.leaf, &existing))
        die("WORK release precisa ser novo/inexistente");

    char stage[NAME_MAX + 1];
    int sn = snprintf(stage, sizeof(stage), ".%s.live-work.tmp",
                      work_parent.leaf);
    if (sn < 0 || (size_t)sn >= sizeof(stage)) die("nome de WORK longo");
    if (at_lstat(work_parent.parent_fd, stage, &existing))
        die("staging anterior/estrangeiro do WORK existe");
    if (mkdirat(work_parent.parent_fd, stage, 0700) < 0)
        die_errno("mkdir do staging do WORK");
    int work = openat(work_parent.parent_fd, stage,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (work < 0) die_errno("open do staging do WORK");
    struct stat work_st;
    if (fstat(work, &work_st) < 0) die_errno("fstat do staging do WORK");
    if (!S_ISDIR(work_st.st_mode) || work_st.st_uid != geteuid() ||
        (work_st.st_mode & 07777) != 0700)
        die("staging do WORK não é 0700/do euid");
    char marker_text[1024];
    size_t marker_len = format_work_marker(marker_text, sizeof(marker_text),
                                           &work_st, proof_sha, request_sha);
    static const char marker_temp[] = ".distropica-live-work.tmp";
    int marker = openat(work, marker_temp,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600);
    if (marker < 0) die_errno("criação do marcador temporário do WORK");
    write_all(marker, marker_text, marker_len);
    if (fchmod(marker, 0600) < 0 || fsync(marker) < 0)
        die_errno("persistência do marcador temporário do WORK");
    if (close(marker) < 0) die_errno("close do marcador temporário do WORK");
    rename_noreplace(work, marker_temp, work, work_marker_name);
    if (fsync(work) < 0) die_errno("fsync do staging do WORK");
    rename_noreplace(work_parent.parent_fd, stage, work_parent.parent_fd,
                     work_parent.leaf);
    if (fsync(work_parent.parent_fd) < 0) die_errno("fsync do pai do WORK");

    struct sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, marker_text, marker_len);
    unsigned char digest[32];
    sha256_final(&c, digest);
    hex_digest(digest, marker_sha);
    char verified[65];
    validate_release_work_fd(work, marker_sha, request_sha, proof_sha, true,
                             verified);
    if (close(work) < 0) die_errno("close do WORK criado");
    if (close(root_parent.parent_fd) < 0 || close(work_parent.parent_fd) < 0)
        die_errno("close dos pais de WORK/rootfs");
}

static void command_work_verify(const char *path, const char *marker_sha,
                                const char *request_sha, const char *proof_sha,
                                const char *state) {
    bool pristine;
    if (!strcmp(state, "pristine")) pristine = true;
    else if (!strcmp(state, "populated")) pristine = false;
    else die("estado do WORK precisa ser pristine|populated");
    int work = open_dir_abs(path, true, NULL);
    char actual[65];
    validate_release_work_fd(work, marker_sha, request_sha, proof_sha,
                             pristine, actual);
    if (close(work) < 0) die_errno("close do WORK validado");
    puts(actual);
}

static void validate_builder_lock(const char *path,
                                  const struct runner_info *runner) {
    char lock_sha[65];
    char *text = read_small_abs(path, "LIVE_BUILDER", lock_sha);
    if (strcmp(lock_sha, runner->builder_lock))
        die("builder lock diverge do Runner Proof");
    const char *p = text;
    char line[128], id[128], root[65];
    p = line_after(p, line, sizeof(line), "Builder header");
    if (strcmp(line, "LIVE_BUILDER_FORMAT=1"))
        die("builder lock sem LIVE_BUILDER_FORMAT=1");
    p = ordered_value(p, "ID", id, sizeof(id), "Builder lock");
    p = ordered_value(p, "ROOTFS_TREE_SHA256", root, sizeof(root),
                      "Builder lock");
    if (*p || !safe_atom(id) || !valid_sha256(root) ||
        strcmp(id, runner->builder_id) || strcmp(root, runner->builder_root))
        die("builder lock diverge da identidade/rootfs do Runner Proof");
    free(text);
}

/* Âncora externa do release. O caminho deste helper já foi autenticado pelo
 * pipeline; --self-sha256 apenas revalida o executável efetivamente aberto.
 * Nenhuma ferramenta do rootfs é usada antes de este preflight terminar. */
static void command_release_preflight(char **a) {
    const char *proof_path = a[0], *proof_expected = a[1];
    char proof_sha[65];
    char *proof = read_small_abs(proof_path, "LIVE_RUNNER_PROOF", proof_sha);
    if (!valid_sha256(proof_expected) || strcmp(proof_sha, proof_expected))
        die("hash externo do Runner Proof diverge");
    struct runner_info ri = parse_runner_text(proof);
    if (strcmp(ri.mode, "release") || strcmp(ri.authenticated, "yes"))
        die("preflight exige Runner Proof release autenticado externamente");
    char self[65];
    hash_self(self);
    if (strcmp(self, ri.helper_binary))
        die("helper externo diverge do pin binário no Runner Proof");
    if (strcmp(a[19], ri.epoch) || !decimal_string(a[19]))
        die("epoch externo diverge do Runner Proof");
    if (strcmp(a[2], ri.runner_path))
        die("caminho do runner diverge do Runner Proof");
    require_regular_hash(a[2], ri.runner_sha, "runner externo");
    require_regular_hash(a[3], ri.source_snapshot, "source snapshot");
    require_regular_hash(a[10], ri.build_source, "build-efi externo");
    require_regular_hash(a[11], ri.linux_tar, "tar Linux");
    require_regular_hash(a[12], ri.busybox_tar, "tar BusyBox");
    require_regular_hash(a[13], ri.e2fs_tar, "tar e2fsprogs");
    require_regular_hash(a[14], ri.ncurses_tar, "tar ncurses");
    require_regular_hash(a[15], ri.util_linux_tar, "tar util-linux");
    require_regular_hash(a[16], ri.minipax, "binário Minipax");
    require_regular_hash(a[17], ri.minitrue, "binário Minitrue");
    require_regular_hash(a[18], ri.zig_tar, "tar Zig");
    validate_builder_lock(a[5], &ri);
    require_regular_hash(a[6], a[7], "evidência de licenças");
    char measured_root[65];
    tree_hash_abs(a[4], NULL, measured_root);
    if (strcmp(measured_root, ri.builder_root))
        die("rootfs produtor diverge do Runner Proof/builder lock");
    command_check_output(a[8]);
    char request_sha[65], marker_sha[65];
    hash_release_request(a, request_sha);
    create_release_work(a[9], a[4], proof_sha, request_sha, marker_sha);
    free(proof);
    printf("BUILDER_ROOTFS_TREE_SHA256=%s\n"
           "WORK_REQUEST_SHA256=%s\n"
           "WORK_MARKER_SHA256=%s\n",
           measured_root, request_sha, marker_sha);
}

static void command_tree_exec(const char *root, const char *expected,
                              char **program_argv) {
    if (!valid_sha256(expected)) die("pin do rootfs não canônico");
    char actual[65];
    tree_hash_abs(root, NULL, actual);
    if (strcmp(actual, expected))
        die("rootfs mudou entre preflight e entrada no sandbox");
    if (!program_argv[0] || !lexical_absolute_path(program_argv[0]))
        die("tree-exec exige programa absoluto canônico");
    execv(program_argv[0], program_argv);
    die_errno("execv depois do tree-hash");
}

static void command_release_work_exec(const char *root,
                                      const char *root_expected,
                                      const char *work,
                                      const char *marker_expected,
                                      const char *request_expected,
                                      const char *proof_expected,
                                      const char *state,
                                      char **program_argv) {
    if (!valid_sha256(root_expected)) die("pin do rootfs não canônico");
    char actual[65];
    tree_hash_abs(root, NULL, actual);
    if (strcmp(actual, root_expected))
        die("rootfs mudou entre preflight e entrada no sandbox");
    command_work_verify(work, marker_expected, request_expected,
                        proof_expected, state);
    if (!program_argv[0] || !lexical_absolute_path(program_argv[0]))
        die("release-work-exec exige programa absoluto canônico");
    execv(program_argv[0], program_argv);
    die_errno("execv depois das guardas rootfs/WORK");
}

static void usage(FILE *stream) {
    fprintf(stream,
        "uso:\n"
        "  live-lock-helper sha256 ARQUIVO\n"
        "  live-lock-helper components INPUTS OUTPUT\n"
        "  live-lock-helper verify-runner RUNNER-PROOF\n"
        "  live-lock-helper check-output OUTPUT-EFI\n"
        "  live-lock-helper release-preflight PROOF PROOF-SHA RUNNER SNAPSHOT ROOTFS BUILDER-LOCK LICENSE LICENSE-SHA OUTPUT WORK BUILD-EFI LINUX BUSYBOX E2FS NCURSES UTIL MINIPAX MINITRUE ZIG EPOCH\n"
        "  live-lock-helper work-verify WORK MARKER-SHA REQUEST-SHA PROOF-SHA pristine|populated\n"
        "  live-lock-helper release-work-exec ROOT ROOT-SHA WORK MARKER-SHA REQUEST-SHA PROOF-SHA pristine|populated PROGRAMA [ARG...]\n"
        "  live-lock-helper tree-exec ROOT ROOT-SHA PROGRAMA [ARG...]\n"
        "  live-lock-helper compare ARQUIVO-A ARQUIVO-B\n"
        "  live-lock-helper tree-hash ARVORE [EXCLUSAO-RELATIVA]\n"
        "  live-lock-helper cpio-member CPIO MEMBRO ARQUIVO-ESPERADO\n"
        "  live-lock-helper elf-initramfs VMLINUX BLOB\n"
        "  live-lock-helper embed-proof EFI VMLINUX BLOB DECODIFICADO CPIO COMPONENTS EXTRACTOR-SHA OUTPUT\n"
        "  live-lock-helper lock EFI COMPONENTS RUNNER-PROOF EMBED-PROOF LICENSE LICENSE-EVIDENCE-SHA OUTPUT\n"
        "  live-lock-helper publish EFI COMPONENTS RUNNER-PROOF EMBED-PROOF LOCK OUTPUT [--failpoint NOME]\n"
        "  live-lock-helper verify EFI COMPONENTS RUNNER-PROOF EMBED-PROOF LOCK\n");
}

int main(int argc, char **argv) {
    if (argc >= 3 && !strcmp(argv[1], "--self-sha256")) {
        if (!valid_sha256(argv[2])) die("pin do próprio helper não canônico");
        char actual[65];
        hash_self(actual);
        if (strcmp(actual, argv[2])) die("pin do próprio helper diverge");
        argv += 2;
        argc -= 2;
    }
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    if (!strcmp(argv[1], "sha256") && argc == 3) {
        command_file_hash(argv[2]);
    } else if (!strcmp(argv[1], "components") && argc == 4) {
        command_components(argv[2], argv[3]);
    } else if (!strcmp(argv[1], "verify-runner") && argc == 3) {
        command_verify_runner(argv[2]);
    } else if (!strcmp(argv[1], "check-output") && argc == 3) {
        command_check_output(argv[2]);
    } else if (!strcmp(argv[1], "release-preflight") && argc == 22) {
        command_release_preflight(&argv[2]);
    } else if (!strcmp(argv[1], "work-verify") && argc == 7) {
        command_work_verify(argv[2], argv[3], argv[4], argv[5], argv[6]);
    } else if (!strcmp(argv[1], "release-work-exec") && argc >= 10) {
        command_release_work_exec(argv[2], argv[3], argv[4], argv[5], argv[6],
                                  argv[7], argv[8], &argv[9]);
    } else if (!strcmp(argv[1], "tree-exec") && argc >= 5) {
        command_tree_exec(argv[2], argv[3], &argv[4]);
    } else if (!strcmp(argv[1], "compare") && argc == 4) {
        require_same_regular_bytes(argv[2], argv[3], "compare");
    } else if (!strcmp(argv[1], "tree-hash") && (argc == 3 || argc == 4)) {
        command_tree_hash(argv[2], argc == 4 ? argv[3] : NULL);
    } else if (!strcmp(argv[1], "cpio-member") && argc == 5) {
        command_cpio_member(argv[2], argv[3], argv[4]);
    } else if (!strcmp(argv[1], "elf-initramfs") && argc == 4) {
        command_elf_initramfs(argv[2], argv[3]);
    } else if (!strcmp(argv[1], "embed-proof") && argc == 10) {
        command_embed_proof(argv[2], argv[3], argv[4], argv[5], argv[6],
                            argv[7], argv[8], argv[9]);
    } else if (!strcmp(argv[1], "lock") && argc == 9) {
        command_lock(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7],
                     argv[8]);
    } else if (!strcmp(argv[1], "publish") && (argc == 8 || argc == 10)) {
        if (argc == 10 && strcmp(argv[8], "--failpoint"))
            die("opção de failpoint inválida");
        command_publish(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7],
                        argc == 10 ? argv[9] : NULL);
    } else if (!strcmp(argv[1], "verify") && argc == 7) {
        struct publish_hashes h = {0};
        hash_regular_abs(argv[2], h.efi, NULL);
        validate_publication_documents(argv[3], argv[4], argv[5], argv[6], &h);
        char embed_sha[65];
        char *embed = read_small_abs(argv[5], "LIVE_EMBED_PROOF", embed_sha);
        require_text_sha_field(embed, "BOOT_EFI_SHA256", h.efi,
                               "LIVE_EMBED_PROOF");
        free(embed);
    } else {
        usage(stderr);
        return 2;
    }
    return 0;
}
