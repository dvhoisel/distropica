/*
 * miniluv — o Ministério do Amor.
 *
 * Interface gráfica do ConnMan: cabo e Wi-Fi na mesma janela. Escrita porque
 * não existe uma. O connman-gtk está arquivado desde 2021 com último release
 * em 2015; o connman-ui é GTK3 com systray; o cmst é Qt. Medido antes de
 * decidir escrever: nenhum cliente GTK4 do ConnMan existe.
 *
 * Fala D-Bus pelo GDBus, que já vem no glib — nenhuma dependência além do que
 * a árvore tem para o iwgtk, que é o molde estrutural desta ferramenta.
 *
 * O nome fecha o conjunto: minitrue é o Ministério da Verdade e trata dos
 * registros; minipax é o da Paz e instala; miniluv é o do Amor, que em 1984 é
 * o ministério que decide quem fala com quem — que é exatamente o que um
 * gerenciador de conexão faz.
 */
#ifndef MINILUV_H
#define MINILUV_H

#include <gtk/gtk.h>

#define ML_SERVICO      "net.connman"
#define ML_MANAGER_IF   "net.connman.Manager"
#define ML_SERVICE_IF   "net.connman.Service"
#define ML_TECH_IF      "net.connman.Technology"
#define ML_AGENT_IF     "net.connman.Agent"
#define ML_AGENT_PATH   "/br/com/distropica/miniluv/agente"

/* Uma rede ou interface, como o ConnMan a descreve. O caminho D-Bus é a
 * identidade; nome pode repetir e não serve de chave. */
typedef struct {
    char *caminho;      /* objeto D-Bus, ex. /net/connman/service/wifi_..._psk */
    char *nome;         /* SSID, ou "Wired" */
    char *tipo;         /* "wifi", "ethernet", … */
    char *estado;       /* "idle", "association", "online", "failure", … */
    char *seguranca;    /* "psk", "none", "ieee8021x", … */
    guint8 forca;       /* 0–100; 0 para cabo */
    gboolean favorita;  /* já conectada alguma vez */
} MlServico;

typedef struct {
    GtkApplication *app;
    GtkWindow      *janela;
    GtkWidget      *lista;
    GtkWidget      *rotulo_estado;
    GtkWidget      *interruptor_wifi;

    GDBusConnection *barramento;
    GDBusProxy      *manager;
    guint            id_agente;      /* registro do objeto do agente */
    guint            id_sinal;       /* subscrição de ServicesChanged */
    GPtrArray       *servicos;       /* MlServico* */
    char            *tech_wifi;      /* caminho da tecnologia wifi, ou NULL */
} MlApp;

void ml_servico_free(MlServico *s);

/* connman.c */
gboolean ml_conectar_barramento(MlApp *app, GError **erro);
void     ml_recarregar_servicos(MlApp *app);
void     ml_servico_conectar(MlApp *app, const char *caminho);
void     ml_servico_desconectar(MlApp *app, const char *caminho);
void     ml_wifi_ligar(MlApp *app, gboolean ligado);

/* agente.c */
gboolean ml_agente_registrar(MlApp *app, GError **erro);
void     ml_agente_desregistrar(MlApp *app);

/* janela.c */
void ml_janela_construir(MlApp *app);
void ml_janela_atualizar(MlApp *app);
void ml_janela_erro(MlApp *app, const char *texto);

#endif /* MINILUV_H */
