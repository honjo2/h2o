#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include "h2o.h"
#include "h2o/configurator.h"

struct proxy_configurator_t {
    h2o_configurator_t super;
    h2o_proxy_config_vars_t *vars;
    h2o_proxy_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static SSL_CTX *create_ssl_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_options(ctx, SSL_CTX_get_options(ctx) | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    return ctx;
}

static void update_ssl_ctx(SSL_CTX **ctx, X509_STORE *cert_store, int verify_mode)
{
    assert(*ctx != NULL);
    
    /* inherit the properties that weren't specified */
    if (cert_store == NULL)
        cert_store = (*ctx)->cert_store;
    CRYPTO_add(&cert_store->references, 1, CRYPTO_LOCK_X509_STORE);
    if (verify_mode == -1)
        verify_mode = (*ctx)->verify_mode;
    
    /* free the existing context */
    if (*ctx != NULL)
        SSL_CTX_free(*ctx);
    
    /* create new ctx */
    *ctx = create_ssl_ctx();
    if ((*ctx)->cert_store != NULL)
        X509_STORE_free((*ctx)->cert_store);
    (*ctx)->cert_store = cert_store;
    SSL_CTX_set_verify(*ctx, verify_mode, NULL);
}

static int on_config_reverse_url(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)cmd->configurator;
    h2o_url_t parsed;
    
    if (h2o_url_parse(node->data.scalar, SIZE_MAX, &parsed) != 0) {
        h2o_configurator_errprintf(cmd, node, "failed to parse URL: %s\n", node->data.scalar);
        return -1;
    }
    /* register */
    h2o_s3tile_proxy_register_reverse_proxy(ctx->pathconf, &parsed, self->vars);
    
    return 0;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)_self;
    
    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    ++self->vars;
    
    if (ctx->pathconf == NULL && ctx->hostconf == NULL) {
        /* is global conf, setup the default SSL context */
        self->vars->ssl_ctx = create_ssl_ctx();
        char *ca_bundle = h2o_configurator_get_cmd_path("share/h2o/ca-bundle.crt");
        if (SSL_CTX_load_verify_locations(self->vars->ssl_ctx, ca_bundle, NULL) != 1)
            fprintf(stderr, "Warning: failed to load the default certificates file at %s. Proxying to HTTPS servers may fail.\n",
                    ca_bundle);
        free(ca_bundle);
        SSL_CTX_set_verify(self->vars->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        CRYPTO_add(&self->vars->ssl_ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
    }
    
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct proxy_configurator_t *self = (void *)_self;
    
    if (ctx->pathconf == NULL && ctx->hostconf == NULL) {
        /* is global conf */
        ctx->globalconf->proxy.io_timeout = self->vars->io_timeout;
        ctx->globalconf->proxy.ssl_ctx = self->vars->ssl_ctx;
    } else {
        SSL_CTX_free(self->vars->ssl_ctx);
    }
    
    --self->vars;
    return 0;
}

void h2o_s3tile_proxy_register_configurator(h2o_globalconf_t *conf)
{
    struct proxy_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));
    
    /* set default vars */
    c->vars = c->_vars_stack;
    c->vars->io_timeout = H2O_DEFAULT_PROXY_IO_TIMEOUT;
    c->vars->keepalive_timeout = 2000;
    c->vars->websocket.enabled = 0; /* have websocket proxying disabled by default; until it becomes non-experimental */
    c->vars->websocket.timeout = H2O_DEFAULT_PROXY_WEBSOCKET_TIMEOUT;
    
    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    h2o_configurator_define_command(
                                    &c->super, "s3tile.proxy.reverse.url",
                                    H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR | H2O_CONFIGURATOR_FLAG_DEFERRED, on_config_reverse_url);
}