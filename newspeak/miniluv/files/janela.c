/*
 * A janela: uma lista, um interruptor, uma linha de estado.
 *
 * O critério de desenho é o mesmo do resto desta distro — dizer a verdade em
 * vez de parecer bem. Uma lista vazia num gerenciador de rede é ambígua: pode
 * ser "não há redes", "o rádio está desligado" ou "o daemon morreu". Aqui cada
 * um desses estados tem texto próprio.
 */
#include "miniluv.h"

#include <arpa/inet.h>
#include <stdlib.h>

typedef struct {
    MlApp *app;
    char  *caminho;
} MlAcao;

static void acao_free(gpointer dados, GClosure *fechamento)
{
    MlAcao *a = dados;
    (void)fechamento;
    g_free(a->caminho);
    g_free(a);
}

/* Acha o serviço pelo caminho D-Bus. Os MlServico são destruídos e recriados a
 * cada ServicesChanged, então guardar o PONTEIRO numa ação de botão daria um
 * ponteiro solto na primeira varredura de Wi-Fi. O caminho é a única
 * identidade estável — nome repete, e índice na lista muda com a ordenação. */
static const MlServico *servico_por_caminho(MlApp *app, const char *caminho)
{
    for (guint i = 0; i < app->servicos->len; i++) {
        const MlServico *s = g_ptr_array_index(app->servicos, i);
        if (g_strcmp0(s->caminho, caminho) == 0)
            return s;
    }
    return NULL;
}

static void ao_clicar_conectar(GtkButton *b, gpointer dados)
{
    MlAcao *a = dados;
    (void)b;
    ml_servico_conectar(a->app, a->caminho);
}

static void ao_clicar_desconectar(GtkButton *b, gpointer dados)
{
    MlAcao *a = dados;
    (void)b;
    ml_servico_desconectar(a->app, a->caminho);
}

static void ao_clicar_ip(GtkButton *b, gpointer dados)
{
    MlAcao *a = dados;
    const MlServico *s = servico_por_caminho(a->app, a->caminho);
    (void)b;

    if (!s) {
        ml_janela_erro(a->app, "a rede saiu da lista antes de a configuração abrir");
        return;
    }
    ml_janela_editar_ip(a->app, s);
}

static void ao_alternar_wifi(GObject *interruptor, GParamSpec *spec, gpointer dados)
{
    (void)spec;
    ml_wifi_ligar(dados, gtk_switch_get_active(GTK_SWITCH(interruptor)));
}

/* "online" e "ready" são ambos conectado para o ConnMan: ready significa IP
 * obtido; online significa que ele também confirmou saída para a internet. Um
 * usuário atrás de portal cativo fica em ready para sempre, e chamar isso de
 * "desconectado" seria mentir. */
static gboolean esta_conectado(const MlServico *s)
{
    return g_strcmp0(s->estado, "online") == 0 ||
           g_strcmp0(s->estado, "ready") == 0;
}

static const char *estado_legivel(const MlServico *s)
{
    if (g_strcmp0(s->estado, "online") == 0)      return "conectado";
    if (g_strcmp0(s->estado, "ready") == 0)       return "conectado (sem saída confirmada)";
    if (g_strcmp0(s->estado, "association") == 0) return "associando…";
    if (g_strcmp0(s->estado, "configuration") == 0) return "obtendo endereço…";
    if (g_strcmp0(s->estado, "disconnect") == 0)  return "desconectando…";
    if (g_strcmp0(s->estado, "failure") == 0)     return "falhou";
    return "disponível";
}

/* Como o endereçamento aparece na linha da rede. É informação de PRIMEIRA
 * ordem num gerenciador de rede — "conectado" sem dizer com que endereço é
 * metade da resposta —, e é também o único jeito de o usuário ver que o
 * "manual" que ele pediu de fato entrou. */
static char *resumo_ip(const MlServico *s)
{
    if (g_strcmp0(s->ip_metodo, "off") == 0)
        return g_strdup("IPv4 desligado");

    /* O endereço EM USO na frente do método, e não o configurado: em DHCP o
     * configurado não existe, e "DHCP" sozinho não responde a pergunta que
     * leva alguém a abrir um gerenciador de rede. Sem endereço a linha diz
     * isso com todas as letras — um campo em branco seria lido como zero. */
    if (s->ip_atual)
        return g_strdup_printf("%s via %s", s->ip_atual,
                               g_strcmp0(s->ip_metodo, "dhcp") == 0
                                   ? "DHCP" : s->ip_metodo);
    /* Qualquer método fora de dhcp/manual/off sai com o NOME que o daemon deu,
     * inclusive um que esta versão não conheça. Traduzir o desconhecido para
     * "DHCP" seria a mentira mais fácil de escrever e a mais difícil de
     * perceber. */
    if (g_strcmp0(s->ip_metodo, "dhcp") == 0)
        return g_strdup("DHCP, sem endereço");
    if (s->ip_endereco)
        return g_strdup_printf("%s %s (não aplicado)", s->ip_metodo, s->ip_endereco);
    return g_strdup_printf("%s, sem endereço", s->ip_metodo);
}

static GtkWidget *linha_de_servico(MlApp *app, MlServico *s)
{
    GtkWidget *linha, *caixa, *textos, *nome, *detalhe, *botao, *botao_ip;
    char *sub, *ip;

    linha = gtk_list_box_row_new();
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(linha), FALSE);

    caixa = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_margin_top(caixa, 8);
    gtk_widget_set_margin_bottom(caixa, 8);
    gtk_widget_set_margin_start(caixa, 12);
    gtk_widget_set_margin_end(caixa, 12);

    textos = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_hexpand(textos, TRUE);

    nome = gtk_label_new(s->nome);
    gtk_widget_set_halign(nome, GTK_ALIGN_START);
    gtk_widget_add_css_class(nome, "heading");
    /* ELIPSE, e não é enfeite: um GtkLabel sem elipse exige a largura inteira
     * do texto como mínimo, e uma caixa horizontal atende esse mínimo
     * EMPURRANDO os irmãos para fora da janela. Foi o que aconteceu na
     * primeira prova gráfica — o botão Desconectar saiu pela borda direita,
     * e a janela continuou "funcionando" sem que houvesse como desconectar.
     * Um SSID longo faz o mesmo, e SSID longo não é caso raro. */
    gtk_label_set_ellipsize(GTK_LABEL(nome), PANGO_ELLIPSIZE_END);
    gtk_box_append(GTK_BOX(textos), nome);

    /* A linha de detalhe carrega tudo o que distingue uma rede de outra:
     * cabo ou rádio, aberta ou protegida, a força do sinal e como ela endereça.
     * Sem ela, duas redes de nome parecido são indistinguíveis. */
    ip = resumo_ip(s);
    if (g_strcmp0(s->tipo, "ethernet") == 0) {
        sub = g_strdup_printf("cabo · %s · %s", estado_legivel(s), ip);
    } else {
        sub = g_strdup_printf("%s · %s%s · %u%%",
                              s->tipo,
                              (s->seguranca && !g_str_equal(s->seguranca, "none"))
                                  ? s->seguranca : "aberta",
                              s->favorita ? " · conhecida" : "",
                              s->forca);
        char *comEstado = g_strdup_printf("%s · %s · %s", sub, estado_legivel(s), ip);
        g_free(sub);
        sub = comEstado;
    }
    g_free(ip);
    detalhe = gtk_label_new(sub);
    g_free(sub);
    gtk_label_set_ellipsize(GTK_LABEL(detalhe), PANGO_ELLIPSIZE_END);
    gtk_widget_set_halign(detalhe, GTK_ALIGN_START);
    gtk_widget_add_css_class(detalhe, "dim-label");
    gtk_box_append(GTK_BOX(textos), detalhe);
    gtk_box_append(GTK_BOX(caixa), textos);

    /* Botão de IP em TODA linha, inclusive nas desconectadas: o ConnMan guarda
     * a configuração no perfil do serviço, então dá para deixar um endereço
     * fixo pronto ANTES de conectar. Escondê-lo até haver conexão obrigaria a
     * conectar por DHCP primeiro só para depois trocar. */
    MlAcao *ai = g_new0(MlAcao, 1);
    ai->app = app;
    ai->caminho = g_strdup(s->caminho);
    botao_ip = gtk_button_new_with_label("IP…");
    gtk_widget_set_tooltip_text(botao_ip, "Endereço, máscara, gateway e DNS");
    gtk_widget_set_valign(botao_ip, GTK_ALIGN_CENTER);
    g_signal_connect_data(botao_ip, "clicked",
                          G_CALLBACK(ao_clicar_ip), ai, acao_free, 0);
    gtk_box_append(GTK_BOX(caixa), botao_ip);

    MlAcao *a = g_new0(MlAcao, 1);
    a->app = app;
    a->caminho = g_strdup(s->caminho);

    if (esta_conectado(s)) {
        botao = gtk_button_new_with_label("Desconectar");
        g_signal_connect_data(botao, "clicked",
                              G_CALLBACK(ao_clicar_desconectar), a, acao_free, 0);
    } else {
        botao = gtk_button_new_with_label("Conectar");
        gtk_widget_add_css_class(botao, "suggested-action");
        g_signal_connect_data(botao, "clicked",
                              G_CALLBACK(ao_clicar_conectar), a, acao_free, 0);
    }
    gtk_widget_set_valign(botao, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(caixa), botao);

    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(linha), caixa);
    return linha;
}

void ml_janela_erro(MlApp *app, const char *texto)
{
    char *m = g_strdup_printf("⚠ %s", texto);
    gtk_label_set_text(GTK_LABEL(app->rotulo_estado), m);
    g_free(m);
    gtk_widget_set_visible(app->rotulo_estado, TRUE);
}

/* ------------------------------------------------------------------------ *
 * O editor de IP.
 *
 * Nenhum GtkDialog: ele está depreciado desde o GTK 4.10, e esta árvore
 * compila com -Werror. GtkWindow modal e transiente faz o mesmo sem aviso.
 * ------------------------------------------------------------------------ */

typedef struct {
    MlApp     *app;
    char      *caminho;
    GtkWindow *janela;
    GtkWidget *metodo;      /* GtkDropDown */
    GtkWidget *manual;      /* grade com endereço/máscara/gateway */
    GtkWidget *endereco;
    GtkWidget *mascara;
    GtkWidget *gateway;
    GtkWidget *dns;
    GtkWidget *aviso;
} MlEditor;

static void editor_free(gpointer dados)
{
    MlEditor *e = dados;
    g_free(e->caminho);
    g_free(e);
}

/* A ordem destes dois vetores é a mesma, e é o que liga o índice do GtkDropDown
 * ao valor que o ConnMan entende. "auto" e "fixed" não estão aqui: o primeiro é
 * de IPv6 e o segundo é somente-leitura — quem os define é o driver, e oferecê-
 * los para escrita seria um botão que o daemon recusa. */
static const char * const ML_METODOS[] = { "dhcp", "manual", "off", NULL };
static const char * const ML_ROTULOS[] = {
    "Automático (DHCP)", "Manual", "Desligado", NULL
};

static gboolean ip4_valido(const char *t)
{
    struct in_addr v4;
    return inet_pton(AF_INET, t, &v4) == 1;
}

static gboolean ip_qualquer_valido(const char *t)
{
    struct in6_addr v6;
    return ip4_valido(t) || inet_pton(AF_INET6, t, &v6) == 1;
}

/* Aceita "255.255.255.0" ou "24". As duas formas existem no mundo real e o
 * ConnMan lê as duas.
 *
 * A máscara pontilhada ainda tem de ser CONTÍGUA: 255.0.255.0 passa por
 * inet_pton, o ConnMan aceita, e o resultado é uma rota que não funciona e
 * ninguém sabe por quê. O teste do complemento pega isso — uma máscara válida
 * é 1…10…0, logo seu complemento é 0…01…1, e x & (x+1) == 0 só vale para essa
 * forma. */
static gboolean mascara_valida(const char *t)
{
    struct in_addr v4;
    char *fim = NULL;
    long p;

    if (inet_pton(AF_INET, t, &v4) == 1) {
        guint32 inv = ~g_ntohl(v4.s_addr);
        return (inv & (inv + 1)) == 0;
    }
    if (!*t)
        return FALSE;
    p = strtol(t, &fim, 10);
    return fim && *fim == '\0' && p >= 0 && p <= 32;
}

static void reclamar(MlEditor *e, const char *texto)
{
    gtk_label_set_text(GTK_LABEL(e->aviso), texto);
    gtk_widget_set_visible(e->aviso, TRUE);
}

static void ao_mudar_metodo(GObject *dd, GParamSpec *spec, gpointer dados)
{
    MlEditor *e = dados;
    (void)spec;
    /* Índice 1 é "manual" — ver ML_METODOS. Em DHCP e desligado os campos de
     * endereço continuam VISÍVEIS mas insensíveis, e isso é deliberado: sumir
     * com eles faria a janela pular de tamanho e esconderia o que está gravado
     * no perfil, que o usuário pode querer conferir antes de trocar. */
    gtk_widget_set_sensitive(e->manual,
                             gtk_drop_down_get_selected(GTK_DROP_DOWN(dd)) == 1);
}

static void ao_cancelar(GtkButton *b, gpointer dados)
{
    MlEditor *e = dados;
    (void)b;
    gtk_window_destroy(e->janela);
}

static void ao_aplicar(GtkButton *b, gpointer dados)
{
    MlEditor *e = dados;
    guint i = gtk_drop_down_get_selected(GTK_DROP_DOWN(e->metodo));
    const char *metodo = i < G_N_ELEMENTS(ML_METODOS) - 1 ? ML_METODOS[i] : "dhcp";
    const char *endereco = gtk_editable_get_text(GTK_EDITABLE(e->endereco));
    const char *mascara  = gtk_editable_get_text(GTK_EDITABLE(e->mascara));
    const char *gateway  = gtk_editable_get_text(GTK_EDITABLE(e->gateway));
    const char *dns      = gtk_editable_get_text(GTK_EDITABLE(e->dns));
    (void)b;

    /* Validar AQUI e não deixar o ConnMan reclamar: o erro dele é
     * "net.connman.Error.InvalidArguments", que não diz qual campo está errado
     * nem por quê. Um usuário que digitou 192.168.1 no lugar de 192.168.1.10
     * merece ler isso, e não um nome de erro D-Bus. */
    if (g_str_equal(metodo, "manual")) {
        if (!ip4_valido(endereco)) {
            reclamar(e, "Endereço inválido: use quatro números, como 192.168.1.10.");
            return;
        }
        if (!mascara_valida(mascara)) {
            reclamar(e, "Máscara inválida: use 255.255.255.0 ou 24.");
            return;
        }
        /* Gateway vazio é legítimo — segmento isolado, sem saída — e por isso
         * não é obrigatório. Só se preenchido é que precisa ser um endereço. */
        if (*gateway && !ip4_valido(gateway)) {
            reclamar(e, "Gateway inválido: deixe em branco se não houver.");
            return;
        }
    }

    if (*dns) {
        char **partes = g_strsplit_set(dns, " ,;\t", -1);
        for (int k = 0; partes[k]; k++) {
            if (!*partes[k])
                continue;
            if (!ip_qualquer_valido(partes[k])) {
                char *m = g_strdup_printf("DNS inválido: %s", partes[k]);
                reclamar(e, m);
                g_free(m);
                g_strfreev(partes);
                return;
            }
        }
        g_strfreev(partes);
    }

    ml_servico_configurar_ip(e->app, e->caminho, metodo,
                             endereco, mascara, gateway, dns);
    gtk_window_destroy(e->janela);
}

static GtkWidget *campo(GtkWidget *grade, int linha, const char *rotulo,
                        const char *valor, const char *dica)
{
    GtkWidget *r = gtk_label_new(rotulo);
    GtkWidget *entrada = gtk_entry_new();

    gtk_widget_set_halign(r, GTK_ALIGN_END);
    gtk_editable_set_text(GTK_EDITABLE(entrada), valor ? valor : "");
    gtk_entry_set_placeholder_text(GTK_ENTRY(entrada), dica);
    gtk_widget_set_hexpand(entrada, TRUE);
    gtk_grid_attach(GTK_GRID(grade), r, 0, linha, 1, 1);
    gtk_grid_attach(GTK_GRID(grade), entrada, 1, linha, 1, 1);
    return entrada;
}

void ml_janela_editar_ip(MlApp *app, const MlServico *s)
{
    MlEditor *e;
    GtkWidget *raiz, *cabeca, *rot_metodo, *nota, *botoes, *cancelar, *aplicar;
    char *titulo, *dns;
    guint sel = 0;

    e = g_new0(MlEditor, 1);
    e->app = app;
    e->caminho = g_strdup(s->caminho);

    e->janela = GTK_WINDOW(gtk_window_new());
    titulo = g_strdup_printf("IP — %s", s->nome);
    gtk_window_set_title(e->janela, titulo);
    g_free(titulo);
    gtk_window_set_transient_for(e->janela, app->janela);
    gtk_window_set_modal(e->janela, TRUE);
    gtk_window_set_default_size(e->janela, 440, -1);
    /* O editor morre com a janela; nenhuma lista o guarda. Se o usuário fechar
     * pelo X em vez de Cancelar, isto é o que libera a memória. */
    g_object_set_data_full(G_OBJECT(e->janela), "miniluv-editor", e, editor_free);

    raiz = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(raiz, 16);
    gtk_widget_set_margin_bottom(raiz, 16);
    gtk_widget_set_margin_start(raiz, 16);
    gtk_widget_set_margin_end(raiz, 16);
    gtk_window_set_child(e->janela, raiz);

    /* "fixed" é somente-leitura na API do ConnMan: quem o define é o próprio
     * driver — é o caso de uma interface de tethering. Oferecer campos
     * editáveis aqui seria desenhar um botão que o daemon recusa. Mostra-se o
     * que está valendo, e diz-se por que não dá para mudar. */
    if (g_strcmp0(s->ip_metodo, "fixed") == 0) {
        char *texto = g_strdup_printf(
            "Esta conexão usa endereçamento fixo, definido pelo próprio driver:\n"
            "\n    endereço  %s\n    máscara   %s\n    gateway   %s\n\n"
            "O ConnMan publica esta configuração como somente-leitura, então "
            "não há o que editar aqui.\n\nEm uso agora: %s",
            s->ip_endereco ? s->ip_endereco : "—",
            s->ip_mascara  ? s->ip_mascara  : "—",
            s->ip_gateway  ? s->ip_gateway  : "—",
            s->ip_atual    ? s->ip_atual    : "nenhum endereço IPv4");
        nota = gtk_label_new(texto);
        g_free(texto);
        gtk_label_set_wrap(GTK_LABEL(nota), TRUE);
        gtk_widget_set_halign(nota, GTK_ALIGN_START);
        gtk_box_append(GTK_BOX(raiz), nota);

        cancelar = gtk_button_new_with_label("Fechar");
        gtk_widget_set_halign(cancelar, GTK_ALIGN_END);
        g_signal_connect(cancelar, "clicked", G_CALLBACK(ao_cancelar), e);
        gtk_box_append(GTK_BOX(raiz), cancelar);

        gtk_window_present(e->janela);
        return;
    }

    cabeca = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    rot_metodo = gtk_label_new("Endereçamento IPv4");
    gtk_widget_set_hexpand(rot_metodo, TRUE);
    gtk_widget_set_halign(rot_metodo, GTK_ALIGN_START);
    e->metodo = gtk_drop_down_new_from_strings(ML_ROTULOS);
    for (guint i = 0; ML_METODOS[i]; i++)
        if (g_strcmp0(s->ip_metodo, ML_METODOS[i]) == 0)
            sel = i;
    gtk_drop_down_set_selected(GTK_DROP_DOWN(e->metodo), sel);
    gtk_box_append(GTK_BOX(cabeca), rot_metodo);
    gtk_box_append(GTK_BOX(cabeca), e->metodo);
    gtk_box_append(GTK_BOX(raiz), cabeca);

    e->manual = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(e->manual), 8);
    gtk_grid_set_column_spacing(GTK_GRID(e->manual), 12);
    e->endereco = campo(e->manual, 0, "Endereço", s->ip_endereco, "192.168.1.10");
    e->mascara  = campo(e->manual, 1, "Máscara",  s->ip_mascara,  "255.255.255.0");
    e->gateway  = campo(e->manual, 2, "Gateway",  s->ip_gateway,  "192.168.1.1");
    gtk_widget_set_sensitive(e->manual, sel == 1);
    gtk_box_append(GTK_BOX(raiz), e->manual);

    /* DNS fora da grade manual DE PROPÓSITO: o ConnMan aceita
     * Nameservers.Configuration com o IPv4 em DHCP, e é um pedido comum —
     * endereço automático, resolvedor escolhido. Prendê-lo ao modo manual
     * tiraria essa combinação sem motivo. */
    {
        GtkWidget *grade_dns = gtk_grid_new();
        gtk_grid_set_column_spacing(GTK_GRID(grade_dns), 12);
        dns = s->dns ? g_strjoinv(" ", s->dns) : g_strdup("");
        e->dns = campo(grade_dns, 0, "DNS", dns, "vazio = o que o DHCP mandar");
        g_free(dns);
        gtk_box_append(GTK_BOX(raiz), grade_dns);
    }

    /* O que está valendo AGORA, acima dos campos do que se pede. Sem esta
     * linha, quem abre o diálogo em DHCP vê três campos vazios e nenhuma
     * indicação de que a máquina tem endereço — e a leitura natural disso é
     * que a rede não está configurada. */
    {
        char *agora = s->ip_atual
            ? g_strdup_printf("Em uso agora: %s%s%s", s->ip_atual,
                              s->dns && s->dns[0] ? "  ·  DNS " : "",
                              s->dns && s->dns[0] ? s->dns[0] : "")
            : g_strdup("Em uso agora: nenhum endereço IPv4.");
        GtkWidget *rot_agora = gtk_label_new(agora);
        g_free(agora);
        gtk_label_set_wrap(GTK_LABEL(rot_agora), TRUE);
        gtk_widget_set_halign(rot_agora, GTK_ALIGN_START);
        gtk_widget_add_css_class(rot_agora, "dim-label");
        gtk_box_append(GTK_BOX(raiz), rot_agora);
    }

    e->aviso = gtk_label_new("");
    gtk_label_set_wrap(GTK_LABEL(e->aviso), TRUE);
    gtk_widget_set_halign(e->aviso, GTK_ALIGN_START);
    gtk_widget_add_css_class(e->aviso, "error");
    gtk_widget_set_visible(e->aviso, FALSE);
    gtk_box_append(GTK_BOX(raiz), e->aviso);

    /* O aviso da própria documentação do ConnMan: "the service will become
     * unavailable until the new configuration has been successfully
     * installed". A conexão CAI e volta. Quem está editando por SSH precisa
     * saber disso antes de clicar, e não depois. */
    nota = gtk_label_new("Aplicar derruba e refaz a conexão desta rede.");
    gtk_label_set_wrap(GTK_LABEL(nota), TRUE);
    gtk_widget_set_halign(nota, GTK_ALIGN_START);
    gtk_widget_add_css_class(nota, "dim-label");
    gtk_box_append(GTK_BOX(raiz), nota);

    botoes = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(botoes, GTK_ALIGN_END);
    cancelar = gtk_button_new_with_label("Cancelar");
    g_signal_connect(cancelar, "clicked", G_CALLBACK(ao_cancelar), e);
    aplicar = gtk_button_new_with_label("Aplicar");
    gtk_widget_add_css_class(aplicar, "suggested-action");
    g_signal_connect(aplicar, "clicked", G_CALLBACK(ao_aplicar), e);
    gtk_box_append(GTK_BOX(botoes), cancelar);
    gtk_box_append(GTK_BOX(botoes), aplicar);
    gtk_box_append(GTK_BOX(raiz), botoes);

    g_signal_connect(e->metodo, "notify::selected",
                     G_CALLBACK(ao_mudar_metodo), e);

    gtk_window_present(e->janela);
}

/* Comparador da ordenação. Função de arquivo e não aninhada: função aninhada é
 * extensão do GCC, e esta árvore compila com o gcc-pass2 mas não tem por que
 * depender de extensão onde C padrão resolve. */
static int comparar_servicos(gconstpointer x, gconstpointer y)
{
    const MlServico *a = x;
    const MlServico *b = y;
    gboolean cabo_a = g_strcmp0(a->tipo, "ethernet") == 0;
    gboolean cabo_b = g_strcmp0(b->tipo, "ethernet") == 0;

    if (cabo_a != cabo_b)
        return cabo_a ? -1 : 1;
    if (a->forca != b->forca)
        return (int)b->forca - (int)a->forca;
    return g_strcmp0(a->nome, b->nome);
}

void ml_janela_atualizar(MlApp *app)
{
    GtkWidget *filho;

    if (!app->lista)
        return;

    while ((filho = gtk_widget_get_first_child(app->lista)))
        gtk_list_box_remove(GTK_LIST_BOX(app->lista), filho);

    /* Cabo antes de Wi-Fi, e dentro de cada tipo o mais forte primeiro. Ordem
     * estável importa: a lista se redesenha a cada ServicesChanged, e uma
     * ordem que dança faz o usuário clicar no botão errado. */
    g_ptr_array_sort_values(app->servicos, comparar_servicos);

    for (guint i = 0; i < app->servicos->len; i++)
        gtk_list_box_append(GTK_LIST_BOX(app->lista),
                            linha_de_servico(app, g_ptr_array_index(app->servicos, i)));

    if (app->servicos->len == 0) {
        GtkWidget *vazio = gtk_label_new(
            app->tech_wifi
                ? "Nenhuma rede encontrada."
                : "Nenhuma rede, e não há rádio Wi-Fi nesta máquina.");
        gtk_widget_add_css_class(vazio, "dim-label");
        gtk_widget_set_margin_top(vazio, 24);
        gtk_widget_set_margin_bottom(vazio, 24);
        gtk_list_box_append(GTK_LIST_BOX(app->lista), vazio);
    }

    gtk_widget_set_sensitive(app->interruptor_wifi, app->tech_wifi != NULL);
}

void ml_janela_construir(MlApp *app)
{
    GtkWidget *raiz, *cabecalho, *rotulo_wifi, *rolagem;

    app->janela = GTK_WINDOW(gtk_application_window_new(app->app));
    gtk_window_set_title(app->janela, "miniluv — redes");
    /* 700 e nao 460: a linha de detalhe carrega tipo, seguranca, estado e
     * endereco, e ao lado dela vao DOIS botoes. Medido na prova grafica, o
     * conteudo de uma unica linha de cabo pede ~650 px; abaixo disso a janela
     * abre com botao cortado. A elipse acima impede o estrago quando ainda
     * assim nao couber, mas o tamanho certo e o que evita precisar dela. */
    gtk_window_set_default_size(app->janela, 700, 560);

    raiz = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    cabecalho = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_top(cabecalho, 12);
    gtk_widget_set_margin_bottom(cabecalho, 12);
    gtk_widget_set_margin_start(cabecalho, 12);
    gtk_widget_set_margin_end(cabecalho, 12);
    rotulo_wifi = gtk_label_new("Wi-Fi");
    gtk_widget_set_hexpand(rotulo_wifi, TRUE);
    gtk_widget_set_halign(rotulo_wifi, GTK_ALIGN_START);
    app->interruptor_wifi = gtk_switch_new();
    gtk_switch_set_active(GTK_SWITCH(app->interruptor_wifi), TRUE);
    g_signal_connect(app->interruptor_wifi, "notify::active",
                     G_CALLBACK(ao_alternar_wifi), app);
    gtk_box_append(GTK_BOX(cabecalho), rotulo_wifi);
    gtk_box_append(GTK_BOX(cabecalho), app->interruptor_wifi);
    gtk_box_append(GTK_BOX(raiz), cabecalho);

    app->rotulo_estado = gtk_label_new("");
    gtk_label_set_wrap(GTK_LABEL(app->rotulo_estado), TRUE);
    gtk_widget_set_margin_start(app->rotulo_estado, 12);
    gtk_widget_set_margin_end(app->rotulo_estado, 12);
    gtk_widget_set_margin_bottom(app->rotulo_estado, 8);
    gtk_widget_add_css_class(app->rotulo_estado, "error");
    gtk_widget_set_visible(app->rotulo_estado, FALSE);
    gtk_box_append(GTK_BOX(raiz), app->rotulo_estado);

    app->lista = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(app->lista), GTK_SELECTION_NONE);
    gtk_widget_add_css_class(app->lista, "boxed-list");

    rolagem = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(rolagem, TRUE);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(rolagem), app->lista);
    gtk_box_append(GTK_BOX(raiz), rolagem);

    gtk_window_set_child(app->janela, raiz);
}
