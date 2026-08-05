/*
 * Conversa com o ConnMan pelo barramento de SISTEMA.
 *
 * Tudo aqui é assíncrono de propósito. A tentação é usar as variantes _sync
 * porque o código fica menor; o preço é a janela congelar enquanto o daemon
 * associa a um ponto de acesso, que leva segundos e às vezes falha por timeout.
 * Uma interface de rede que trava enquanto conecta é pior que nenhuma.
 */
#include "miniluv.h"

void ml_servico_free(MlServico *s)
{
    if (!s)
        return;
    g_free(s->caminho);
    g_free(s->nome);
    g_free(s->tipo);
    g_free(s->estado);
    g_free(s->seguranca);
    g_free(s->ip_metodo);
    g_free(s->ip_endereco);
    g_free(s->ip_mascara);
    g_free(s->ip_gateway);
    g_strfreev(s->dns);
    g_free(s->ip_atual);
    g_free(s);
}

/* Lê um dict a{sv} de propriedades de serviço no formato que o ConnMan usa.
 * Campos ausentes são normais: um serviço de cabo não tem Strength nem
 * Security, e um Wi-Fi oculto pode não ter Name. Nada aqui pode assumir
 * presença — o ConnMan omite o que não se aplica. */
static MlServico *servico_de_dict(const char *caminho, GVariant *props)
{
    MlServico *s = g_new0(MlServico, 1);
    GVariantIter it;
    const char *chave;
    GVariant *valor;

    s->caminho = g_strdup(caminho);
    g_variant_iter_init(&it, props);
    while (g_variant_iter_next(&it, "{&sv}", &chave, &valor)) {
        if (g_str_equal(chave, "Name") && g_variant_is_of_type(valor, G_VARIANT_TYPE_STRING))
            s->nome = g_variant_dup_string(valor, NULL);
        else if (g_str_equal(chave, "Type") && g_variant_is_of_type(valor, G_VARIANT_TYPE_STRING))
            s->tipo = g_variant_dup_string(valor, NULL);
        else if (g_str_equal(chave, "State") && g_variant_is_of_type(valor, G_VARIANT_TYPE_STRING))
            s->estado = g_variant_dup_string(valor, NULL);
        else if (g_str_equal(chave, "Strength") && g_variant_is_of_type(valor, G_VARIANT_TYPE_BYTE))
            s->forca = g_variant_get_byte(valor);
        else if (g_str_equal(chave, "Favorite") && g_variant_is_of_type(valor, G_VARIANT_TYPE_BOOLEAN))
            s->favorita = g_variant_get_boolean(valor);
        else if (g_str_equal(chave, "IPv4.Configuration") &&
                 g_variant_is_of_type(valor, G_VARIANT_TYPE_VARDICT)) {
            /* Configuration e nao IPv4: o primeiro e o que o administrador
             * PEDIU, o segundo e o que o sistema tem agora. Editar deve
             * partir do pedido, senao um DHCP em curso apareceria como
             * configuracao manual com o endereco que por acaso chegou. */
            const char *v;
            if (g_variant_lookup(valor, "Method", "&s", &v))
                s->ip_metodo = g_strdup(v);
            if (g_variant_lookup(valor, "Address", "&s", &v))
                s->ip_endereco = g_strdup(v);
            if (g_variant_lookup(valor, "Netmask", "&s", &v))
                s->ip_mascara = g_strdup(v);
            if (g_variant_lookup(valor, "Gateway", "&s", &v))
                s->ip_gateway = g_strdup(v);
        }
        else if (g_str_equal(chave, "IPv4") &&
                 g_variant_is_of_type(valor, G_VARIANT_TYPE_VARDICT)) {
            /* O dict vem VAZIO enquanto o servico nao tem endereco — desligado,
             * associando, DHCP sem resposta. Ausencia aqui e informacao, e nao
             * erro: significa "ainda nao ha IP". */
            const char *v;
            if (g_variant_lookup(valor, "Address", "&s", &v))
                s->ip_atual = g_strdup(v);
        }
        else if (g_str_equal(chave, "Nameservers.Configuration") &&
                 g_variant_is_of_type(valor, G_VARIANT_TYPE_STRING_ARRAY)) {
            s->dns = g_variant_dup_strv(valor, NULL);
        }
        else if (g_str_equal(chave, "Security") &&
                 g_variant_is_of_type(valor, G_VARIANT_TYPE_STRING_ARRAY)) {
            /* Security é array de strings; a primeira basta para exibir. */
            gsize n = 0;
            const char **v = g_variant_get_strv(valor, &n);
            if (n > 0)
                s->seguranca = g_strdup(v[0]);
            g_free(v);
        }
        g_variant_unref(valor);
    }

    /* Wi-Fi oculto não publica Name. Mostrar vazio seria uma linha em branco
     * que o usuário não sabe o que é. */
    if (!s->nome)
        s->nome = g_strdup(g_strcmp0(s->tipo, "ethernet") == 0 ? "Cabo" : "(rede oculta)");
    if (!s->tipo)
        s->tipo = g_strdup("desconhecido");
    if (!s->estado)
        s->estado = g_strdup("idle");
    if (!s->ip_metodo)
        s->ip_metodo = g_strdup("dhcp");
    return s;
}

static void absorver_lista(MlApp *app, GVariant *lista)
{
    GVariantIter it;
    const char *caminho;
    GVariant *props;

    g_ptr_array_set_size(app->servicos, 0);
    g_variant_iter_init(&it, lista);
    while (g_variant_iter_next(&it, "(&o@a{sv})", &caminho, &props)) {
        g_ptr_array_add(app->servicos, servico_de_dict(caminho, props));
        g_variant_unref(props);
    }
}

static void servicos_prontos(GObject *fonte, GAsyncResult *res, gpointer dados)
{
    MlApp *app = dados;
    GError *erro = NULL;
    GVariant *r = g_dbus_proxy_call_finish(G_DBUS_PROXY(fonte), res, &erro);

    if (!r) {
        /* Não é fatal: o connmand pode ter reiniciado. A janela mostra o
         * motivo em vez de uma lista vazia sem explicação — lista vazia é
         * indistinguível de "não há redes", que é a mentira mais fácil de
         * contar numa interface de rede. */
        ml_janela_erro(app, erro->message);
        g_error_free(erro);
        return;
    }

    GVariant *lista = g_variant_get_child_value(r, 0);
    absorver_lista(app, lista);
    g_variant_unref(lista);
    g_variant_unref(r);
    ml_janela_atualizar(app);
}

void ml_recarregar_servicos(MlApp *app)
{
    if (!app->manager)
        return;
    g_dbus_proxy_call(app->manager, "GetServices", NULL,
                      G_DBUS_CALL_FLAGS_NONE, -1, NULL,
                      servicos_prontos, app);
}

/* ServicesChanged chega a cada varredura e a cada mudança de estado. Recarregar
 * a lista inteira é mais simples e mais robusto que aplicar o delta do sinal, e
 * o custo é irrelevante: são dezenas de entradas, não milhares. */
static void ao_mudar_servicos(GDBusConnection *conn, const char *remetente,
                              const char *caminho, const char *interface,
                              const char *sinal, GVariant *params, gpointer dados)
{
    (void)conn; (void)remetente; (void)caminho; (void)interface;
    (void)sinal; (void)params;
    ml_recarregar_servicos(dados);
}

static void chamada_simples_pronta(GObject *fonte, GAsyncResult *res, gpointer dados)
{
    MlApp *app = dados;
    GError *erro = NULL;
    GVariant *r = g_dbus_connection_call_finish(G_DBUS_CONNECTION(fonte), res, &erro);

    if (!r) {
        /* O ConnMan devolve erros nomeados que dizem exatamente o que houve —
         * "AlreadyConnected", "InvalidKey", "OperationTimeout". Engoli-los e
         * mostrar a lista como se nada tivesse acontecido é o defeito clássico
         * dessas interfaces: o usuário clica, nada muda, e nada explica. */
        ml_janela_erro(app, erro->message);
        g_error_free(erro);
        return;
    }
    g_variant_unref(r);
    ml_recarregar_servicos(app);
}

/* Connect pode demorar: associação, 4-way handshake e DHCP acontecem antes da
 * resposta. 120 s é o teto do próprio ConnMan para o agente; usar o default
 * (-1, "sem limite") deixaria a chamada pendurada para sempre se o daemon
 * morresse no meio. */
void ml_servico_conectar(MlApp *app, const char *caminho)
{
    g_dbus_connection_call(app->barramento, ML_SERVICO, caminho,
                           ML_SERVICE_IF, "Connect", NULL, NULL,
                           G_DBUS_CALL_FLAGS_NONE, 120000, NULL,
                           chamada_simples_pronta, app);
}

void ml_servico_desconectar(MlApp *app, const char *caminho)
{
    g_dbus_connection_call(app->barramento, ML_SERVICO, caminho,
                           ML_SERVICE_IF, "Disconnect", NULL, NULL,
                           G_DBUS_CALL_FLAGS_NONE, 30000, NULL,
                           chamada_simples_pronta, app);
}

/* Grava a configuracao de IPv4 e os DNS.
 *
 * Duas chamadas separadas e nao uma: sao duas propriedades distintas do
 * ConnMan, e juntá-las numa transacao imaginaria esconderia que a segunda pode
 * falhar sozinha. Se o endereco entrar e o DNS nao, o usuario precisa saber.
 *
 * A doc avisa que "changing these settings will cause a state change of the
 * service; the service will become unavailable until the new configuration has
 * been successfully installed" — ou seja, a rede CAI e volta. O
 * ml_recarregar_servicos do callback mostra essa transicao em vez de congelar
 * a lista no estado antigo.
 */
void ml_servico_configurar_ip(MlApp *app, const char *caminho,
                              const char *metodo, const char *endereco,
                              const char *mascara, const char *gateway,
                              const char *dns)
{
    GVariantBuilder b;

    g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&b, "{sv}", "Method", g_variant_new_string(metodo));
    if (g_str_equal(metodo, "manual")) {
        /* Em manual os tres campos vao juntos. Mandar Address sem Netmask faz
         * o ConnMan recusar com InvalidArguments, e a mensagem nao diz qual
         * campo faltou. */
        g_variant_builder_add(&b, "{sv}", "Address",
                              g_variant_new_string(endereco ? endereco : ""));
        g_variant_builder_add(&b, "{sv}", "Netmask",
                              g_variant_new_string(mascara ? mascara : ""));
        g_variant_builder_add(&b, "{sv}", "Gateway",
                              g_variant_new_string(gateway ? gateway : ""));
    }
    g_dbus_connection_call(app->barramento, ML_SERVICO, caminho,
                           ML_SERVICE_IF, "SetProperty",
                           g_variant_new("(sv)", "IPv4.Configuration",
                                         g_variant_builder_end(&b)),
                           NULL, G_DBUS_CALL_FLAGS_NONE, 30000, NULL,
                           chamada_simples_pronta, app);

    /* DNS: lista separada por espaco ou virgula, na ordem de prioridade. Uma
     * lista VAZIA e um pedido legitimo — significa "volte a usar o que o DHCP
     * mandar" —, entao nao se pula a chamada quando o campo esta em branco. */
    {
        GVariantBuilder d;
        g_variant_builder_init(&d, G_VARIANT_TYPE("as"));
        if (dns && *dns) {
            char **partes = g_strsplit_set(dns, " ,;\t", -1);
            for (int i = 0; partes[i]; i++)
                if (*partes[i])
                    g_variant_builder_add(&d, "s", partes[i]);
            g_strfreev(partes);
        }
        g_dbus_connection_call(app->barramento, ML_SERVICO, caminho,
                               ML_SERVICE_IF, "SetProperty",
                               g_variant_new("(sv)", "Nameservers.Configuration",
                                             g_variant_builder_end(&d)),
                               NULL, G_DBUS_CALL_FLAGS_NONE, 30000, NULL,
                               chamada_simples_pronta, app);
    }
}

void ml_wifi_ligar(MlApp *app, gboolean ligado)
{
    if (!app->tech_wifi)
        return;
    g_dbus_connection_call(app->barramento, ML_SERVICO, app->tech_wifi,
                           ML_TECH_IF, "SetProperty",
                           g_variant_new("(sv)", "Powered",
                                         g_variant_new_boolean(ligado)),
                           NULL, G_DBUS_CALL_FLAGS_NONE, 30000, NULL,
                           chamada_simples_pronta, app);
}

/* Descobre o caminho da tecnologia wifi. Sem isso o interruptor não tem o que
 * comandar; numa máquina sem rádio ele fica desabilitado, que é honesto. */
static void tecnologias_prontas(GObject *fonte, GAsyncResult *res, gpointer dados)
{
    MlApp *app = dados;
    GError *erro = NULL;
    GVariant *r = g_dbus_proxy_call_finish(G_DBUS_PROXY(fonte), res, &erro);

    if (!r) {
        g_error_free(erro);
        return;
    }

    GVariant *lista = g_variant_get_child_value(r, 0);
    GVariantIter it;
    const char *caminho;
    GVariant *props;

    g_variant_iter_init(&it, lista);
    while (g_variant_iter_next(&it, "(&o@a{sv})", &caminho, &props)) {
        const char *tipo = NULL;
        GVariant *v = g_variant_lookup_value(props, "Type", G_VARIANT_TYPE_STRING);
        if (v)
            tipo = g_variant_get_string(v, NULL);
        if (g_strcmp0(tipo, "wifi") == 0) {
            g_free(app->tech_wifi);
            app->tech_wifi = g_strdup(caminho);
        }
        if (v)
            g_variant_unref(v);
        g_variant_unref(props);
    }
    g_variant_unref(lista);
    g_variant_unref(r);
    ml_janela_atualizar(app);
}

gboolean ml_conectar_barramento(MlApp *app, GError **erro)
{
    app->barramento = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, erro);
    if (!app->barramento)
        return FALSE;

    /* G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START: o ConnMan é daemon de sistema
     * iniciado pelo rcS, não serviço ativável. Deixar o proxy tentar iniciá-lo
     * mascararia "o daemon não subiu" como um erro genérico de D-Bus. */
    app->manager = g_dbus_proxy_new_sync(app->barramento,
                                         G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
                                         NULL, ML_SERVICO, "/", ML_MANAGER_IF,
                                         NULL, erro);
    if (!app->manager)
        return FALSE;

    app->id_sinal = g_dbus_connection_signal_subscribe(
        app->barramento, ML_SERVICO, ML_MANAGER_IF, "ServicesChanged",
        "/", NULL, G_DBUS_SIGNAL_FLAGS_NONE, ao_mudar_servicos, app, NULL);

    g_dbus_proxy_call(app->manager, "GetTechnologies", NULL,
                      G_DBUS_CALL_FLAGS_NONE, -1, NULL,
                      tecnologias_prontas, app);
    return TRUE;
}
