/*
 * O agente: como o ConnMan pede a senha.
 *
 * Esta é a parte que torna a interface útil, e a que quase sempre fica frágil.
 * O daemon não sabe pedir nada ao usuário; ele chama de volta um objeto D-Bus
 * que a interface registrou, e ESPERA a resposta. Três consequências que o
 * código precisa respeitar:
 *
 *  1. A chamada tem de ser respondida de forma assíncrona. Abrir um diálogo
 *     modal e responder ao voltar significaria bloquear o loop de eventos
 *     dentro de um handler de método — a janela congelaria e o próprio diálogo
 *     não desenharia.
 *  2. `Cancel()` pode chegar a qualquer momento, inclusive com o diálogo
 *     aberto. Ignorá-lo deixa uma janela órfã pedindo senha de uma rede que já
 *     desistiu.
 *  3. `ReportError()` chega DEPOIS de a conexão parecer ter dado certo. Senha
 *     errada não falha no Connect; falha aqui.
 */
#include "miniluv.h"

typedef struct {
    MlApp *app;
    GDBusMethodInvocation *chamada;  /* a resposta pendente */
    GtkWidget *dialogo;
    GtkWidget *entrada;
    char *campo;                     /* "Passphrase", "Identity", … */
} MlPedido;

static MlPedido *pedido_aberto;  /* no máximo um por vez; o ConnMan serializa */

static const char introspeccao[] =
    "<node>"
    "  <interface name='net.connman.Agent'>"
    "    <method name='Release'/>"
    "    <method name='Cancel'/>"
    "    <method name='ReportError'>"
    "      <arg type='o' name='service' direction='in'/>"
    "      <arg type='s' name='error' direction='in'/>"
    "    </method>"
    "    <method name='RequestInput'>"
    "      <arg type='o' name='service' direction='in'/>"
    "      <arg type='a{sv}' name='fields' direction='in'/>"
    "      <arg type='a{sv}' name='reply' direction='out'/>"
    "    </method>"
    "  </interface>"
    "</node>";

static void pedido_encerrar(MlPedido *p)
{
    if (pedido_aberto == p)
        pedido_aberto = NULL;
    if (p->dialogo)
        gtk_window_destroy(GTK_WINDOW(p->dialogo));
    g_free(p->campo);
    g_free(p);
}

static void ao_responder(GtkWidget *botao, gpointer dados)
{
    MlPedido *p = dados;
    const char *texto;
    GVariantBuilder b;

    (void)botao;
    texto = gtk_editable_get_text(GTK_EDITABLE(p->entrada));

    g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&b, "{sv}", p->campo, g_variant_new_string(texto));
    g_dbus_method_invocation_return_value(p->chamada,
                                          g_variant_new("(a{sv})", &b));
    p->chamada = NULL;
    pedido_encerrar(p);
}

static void ao_cancelar(GtkWidget *botao, gpointer dados)
{
    MlPedido *p = dados;

    (void)botao;
    /* O erro Canceled é do vocabulário do agente (agent-api.txt): o ConnMan o
     * entende como desistência do usuário e NÃO marca a rede como falha. Um
     * erro genérico faria a rede aparecer como quebrada por engano. */
    g_dbus_method_invocation_return_dbus_error(
        p->chamada, "net.connman.Agent.Error.Canceled", "cancelado pelo usuario");
    p->chamada = NULL;
    pedido_encerrar(p);
}

static void abrir_dialogo(MlPedido *p, const char *rede, gboolean segredo)
{
    GtkWidget *caixa, *rotulo, *linha, *ok, *cancelar;
    char *titulo;

    p->dialogo = gtk_window_new();
    titulo = g_strdup_printf("Conectar a %s", rede ? rede : "rede");
    gtk_window_set_title(GTK_WINDOW(p->dialogo), titulo);
    g_free(titulo);
    gtk_window_set_modal(GTK_WINDOW(p->dialogo), TRUE);
    gtk_window_set_transient_for(GTK_WINDOW(p->dialogo), p->app->janela);
    gtk_window_set_default_size(GTK_WINDOW(p->dialogo), 360, -1);

    caixa = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(caixa, 16);
    gtk_widget_set_margin_bottom(caixa, 16);
    gtk_widget_set_margin_start(caixa, 16);
    gtk_widget_set_margin_end(caixa, 16);

    rotulo = gtk_label_new(g_str_equal(p->campo, "Passphrase")
                           ? "Senha da rede:" : p->campo);
    gtk_widget_set_halign(rotulo, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(caixa), rotulo);

    p->entrada = gtk_password_entry_new();
    if (!segredo) {
        /* Identity e Username não são segredo; esconder o que se digita ali
         * atrapalha sem proteger nada. */
        p->entrada = gtk_entry_new();
    } else {
        gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(p->entrada), TRUE);
    }
    gtk_box_append(GTK_BOX(caixa), p->entrada);

    linha = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(linha, GTK_ALIGN_END);
    cancelar = gtk_button_new_with_label("Cancelar");
    ok = gtk_button_new_with_label("Conectar");
    gtk_widget_add_css_class(ok, "suggested-action");
    gtk_box_append(GTK_BOX(linha), cancelar);
    gtk_box_append(GTK_BOX(linha), ok);
    gtk_box_append(GTK_BOX(caixa), linha);

    g_signal_connect(ok, "clicked", G_CALLBACK(ao_responder), p);
    g_signal_connect(cancelar, "clicked", G_CALLBACK(ao_cancelar), p);
    g_signal_connect_swapped(p->entrada, "activate", G_CALLBACK(ao_responder), p);

    gtk_window_set_child(GTK_WINDOW(p->dialogo), caixa);
    gtk_window_present(GTK_WINDOW(p->dialogo));
    gtk_widget_grab_focus(p->entrada);
}

/* Qual campo o ConnMan quer. O dicionário varia com o tipo de segurança: PSK
 * pede Passphrase; 802.1X pede Identity e depois Passphrase; rede oculta pede
 * Name. Percorrer o dicionário em vez de assumir Passphrase é o que faz a
 * interface funcionar em rede corporativa. */
static const char *escolher_campo(GVariant *campos, gboolean *segredo)
{
    static const char *ordem[] = { "Passphrase", "Identity", "Username",
                                   "Password", "Name", NULL };
    for (int i = 0; ordem[i]; i++) {
        GVariant *v = g_variant_lookup_value(campos, ordem[i], NULL);
        if (v) {
            g_variant_unref(v);
            *segredo = (g_str_equal(ordem[i], "Passphrase") ||
                        g_str_equal(ordem[i], "Password"));
            return ordem[i];
        }
    }
    *segredo = TRUE;
    return "Passphrase";
}

static const char *nome_do_servico(MlApp *app, const char *caminho)
{
    for (guint i = 0; i < app->servicos->len; i++) {
        MlServico *s = g_ptr_array_index(app->servicos, i);
        if (g_strcmp0(s->caminho, caminho) == 0)
            return s->nome;
    }
    return NULL;
}

static void metodo_chamado(GDBusConnection *conn, const char *remetente,
                           const char *caminho, const char *interface,
                           const char *metodo, GVariant *params,
                           GDBusMethodInvocation *chamada, gpointer dados)
{
    MlApp *app = dados;

    (void)conn; (void)remetente; (void)caminho; (void)interface;

    if (g_str_equal(metodo, "RequestInput")) {
        const char *servico;
        GVariant *campos;
        gboolean segredo = TRUE;
        MlPedido *p;

        g_variant_get(params, "(&o@a{sv})", &servico, &campos);

        p = g_new0(MlPedido, 1);
        p->app = app;
        p->chamada = chamada;
        p->campo = g_strdup(escolher_campo(campos, &segredo));
        pedido_aberto = p;
        abrir_dialogo(p, nome_do_servico(app, servico), segredo);
        g_variant_unref(campos);
        return;  /* a resposta sai quando o usuário decidir */
    }

    if (g_str_equal(metodo, "Cancel")) {
        /* Chega quando o daemon desiste — timeout, rede sumiu, outro pedido
         * tomou a vez. Sem isto ficaria um diálogo órfão pedindo a senha de
         * uma rede que já não está sendo tentada. */
        if (pedido_aberto && pedido_aberto->chamada) {
            g_dbus_method_invocation_return_dbus_error(
                pedido_aberto->chamada,
                "net.connman.Agent.Error.Canceled", "cancelado pelo daemon");
            pedido_aberto->chamada = NULL;
        }
        if (pedido_aberto)
            pedido_encerrar(pedido_aberto);
        g_dbus_method_invocation_return_value(chamada, NULL);
        return;
    }

    if (g_str_equal(metodo, "ReportError")) {
        const char *servico, *erro;
        g_variant_get(params, "(&o&s)", &servico, &erro);
        /* AQUI é onde senha errada aparece. O Connect devolve sucesso e só
         * depois o daemon reporta "invalid-key". Uma interface que não
         * implementa ReportError deixa o usuário achando que conectou. */
        ml_janela_erro(app, erro);
        g_dbus_method_invocation_return_value(chamada, NULL);
        return;
    }

    /* Release: o daemon está dispensando o agente. */
    g_dbus_method_invocation_return_value(chamada, NULL);
}

static const GDBusInterfaceVTable vtable = { metodo_chamado, NULL, NULL, { 0 } };

gboolean ml_agente_registrar(MlApp *app, GError **erro)
{
    GDBusNodeInfo *no;

    no = g_dbus_node_info_new_for_xml(introspeccao, erro);
    if (!no)
        return FALSE;

    app->id_agente = g_dbus_connection_register_object(
        app->barramento, ML_AGENT_PATH, no->interfaces[0], &vtable,
        app, NULL, erro);
    g_dbus_node_info_unref(no);
    if (app->id_agente == 0)
        return FALSE;

    /* RegisterAgent é síncrono de propósito: sem agente registrado, conectar a
     * qualquer rede protegida falha em silêncio, e é melhor descobrir isso na
     * partida do que no primeiro clique. */
    GVariant *r = g_dbus_proxy_call_sync(
        app->manager, "RegisterAgent",
        g_variant_new("(o)", ML_AGENT_PATH),
        G_DBUS_CALL_FLAGS_NONE, 10000, NULL, erro);
    if (!r)
        return FALSE;
    g_variant_unref(r);
    return TRUE;
}

void ml_agente_desregistrar(MlApp *app)
{
    if (!app->manager || app->id_agente == 0)
        return;
    /* Sem esperar resposta: estamos saindo, e o daemon limpa agentes de
     * clientes que sumiram do barramento de qualquer modo. */
    g_dbus_proxy_call(app->manager, "UnregisterAgent",
                      g_variant_new("(o)", ML_AGENT_PATH),
                      G_DBUS_CALL_FLAGS_NONE, 5000, NULL, NULL, NULL);
    g_dbus_connection_unregister_object(app->barramento, app->id_agente);
    app->id_agente = 0;
}
