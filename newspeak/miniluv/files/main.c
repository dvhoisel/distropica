/*
 * Ponto de entrada.
 *
 * A ordem aqui não é arbitrária. Barramento, depois agente, depois janela:
 * registrar o agente ANTES de mostrar qualquer coisa garante que o primeiro
 * clique numa rede protegida já encontre quem responda ao pedido de senha. A
 * ordem inversa produz um defeito intermitente — funciona se o usuário demorar
 * a clicar, falha se for rápido.
 */
#include "miniluv.h"

static void ao_ativar(GtkApplication *gapp, gpointer dados)
{
    MlApp *app = dados;
    GError *erro = NULL;

    (void)gapp;

    /* Segunda invocação: a janela já existe, só traz para a frente. É o que
     * torna o lançador do painel idempotente — clicar duas vezes não abre duas
     * janelas nem registra dois agentes. */
    if (app->janela) {
        gtk_window_present(app->janela);
        return;
    }

    ml_janela_construir(app);

    if (!ml_conectar_barramento(app, &erro)) {
        /* Sem barramento não há o que gerenciar, e a janela existe justamente
         * para DIZER isso. Sair em silêncio deixaria o usuário clicando num
         * ícone que não faz nada — o defeito que a 0.10 já teve com o iwgtk. */
        char *m = g_strdup_printf(
            "Não consegui falar com o ConnMan: %s\n\n"
            "O daemon sobe no boot pelo /etc/rc.d/rcS.d/09-connman.sh. "
            "Se ele não estiver rodando, não há gerenciador de rede.",
            erro->message);
        ml_janela_erro(app, m);
        g_free(m);
        g_clear_error(&erro);
        gtk_window_present(app->janela);
        return;
    }

    if (!ml_agente_registrar(app, &erro)) {
        /* Não é fatal: redes abertas e cabo continuam funcionando. Mas rede
         * protegida vai falhar sem explicação, então isso precisa ser dito
         * agora, e não descoberto no primeiro clique. */
        char *m = g_strdup_printf(
            "Agente de senha não registrado: %s\n"
            "Redes protegidas não vão conectar.", erro->message);
        ml_janela_erro(app, m);
        g_free(m);
        g_clear_error(&erro);
    }

    ml_recarregar_servicos(app);
    gtk_window_present(app->janela);
}

static void ao_encerrar(GApplication *gapp, gpointer dados)
{
    MlApp *app = dados;

    (void)gapp;
    ml_agente_desregistrar(app);
    if (app->id_sinal && app->barramento)
        g_dbus_connection_signal_unsubscribe(app->barramento, app->id_sinal);
    g_clear_object(&app->manager);
    g_clear_object(&app->barramento);
    g_clear_pointer(&app->servicos, g_ptr_array_unref);
    g_free(app->tech_wifi);
}

int main(int argc, char **argv)
{
    MlApp app = { 0 };
    int status;

    app.servicos = g_ptr_array_new_with_free_func((GDestroyNotify)ml_servico_free);
    app.app = gtk_application_new("br.com.distropica.miniluv",
                                  G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app.app, "activate", G_CALLBACK(ao_ativar), &app);
    g_signal_connect(app.app, "shutdown", G_CALLBACK(ao_encerrar), &app);

    status = g_application_run(G_APPLICATION(app.app), argc, argv);
    g_object_unref(app.app);
    return status;
}
