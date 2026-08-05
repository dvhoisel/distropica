/*
 * A janela: uma lista, um interruptor, uma linha de estado.
 *
 * O critério de desenho é o mesmo do resto desta distro — dizer a verdade em
 * vez de parecer bem. Uma lista vazia num gerenciador de rede é ambígua: pode
 * ser "não há redes", "o rádio está desligado" ou "o daemon morreu". Aqui cada
 * um desses estados tem texto próprio.
 */
#include "miniluv.h"

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

static GtkWidget *linha_de_servico(MlApp *app, MlServico *s)
{
    GtkWidget *linha, *caixa, *textos, *nome, *detalhe, *botao;
    char *sub;

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
    gtk_box_append(GTK_BOX(textos), nome);

    /* A linha de detalhe carrega tudo o que distingue uma rede de outra:
     * cabo ou rádio, aberta ou protegida, e a força do sinal. Sem ela, duas
     * redes de nome parecido são indistinguíveis. */
    if (g_strcmp0(s->tipo, "ethernet") == 0) {
        sub = g_strdup_printf("cabo · %s", estado_legivel(s));
    } else {
        sub = g_strdup_printf("%s · %s%s · %u%%",
                              s->tipo,
                              (s->seguranca && !g_str_equal(s->seguranca, "none"))
                                  ? s->seguranca : "aberta",
                              s->favorita ? " · conhecida" : "",
                              s->forca);
        char *comEstado = g_strdup_printf("%s · %s", sub, estado_legivel(s));
        g_free(sub);
        sub = comEstado;
    }
    detalhe = gtk_label_new(sub);
    g_free(sub);
    gtk_widget_set_halign(detalhe, GTK_ALIGN_START);
    gtk_widget_add_css_class(detalhe, "dim-label");
    gtk_box_append(GTK_BOX(textos), detalhe);
    gtk_box_append(GTK_BOX(caixa), textos);

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
    gtk_window_set_default_size(app->janela, 460, 560);

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
