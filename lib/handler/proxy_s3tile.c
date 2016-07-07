#include <sys/un.h>
#include <openssl/md5.h>
#include "h2o.h"
#include "h2o/socketpool.h"

struct rp_handler_t {
    h2o_handler_t super;
    h2o_url_t upstream;         /* host should be NULL-terminated */
    h2o_socketpool_t *sockpool; /* non-NULL if config.use_keepalive == 1 */
    h2o_proxy_config_vars_t config;
};

static void md5_short(char *ret, char *key, size_t len) {
    MD5_CTX c;
    unsigned char md[MD5_DIGEST_LENGTH];
    int r, i;
    
    r = MD5_Init(&c);
    if(r != 1) {
        perror("init");
        exit(1);
    }
    
    r = MD5_Update(&c, key, len);
    if(r != 1) {
        perror("update");
        exit(1);
    }
    
    r = MD5_Final(md, &c);
    if(r != 1) {
        perror("final");
        exit(1);
    }
    
    for(i = 0; i < 2; i++)
        sprintf(&ret[i * 2], "%02x", (unsigned int)md[i]);
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct rp_handler_t *self = (void *)_self;
    h2o_req_overrides_t *overrides = h2o_mem_alloc_pool(&req->pool, sizeof(*overrides));
    const h2o_url_scheme_t *scheme;
    h2o_iovec_t *authority;
    
    /* setup overrides */
    *overrides = (h2o_req_overrides_t){};
    if (self->sockpool != NULL) {
        overrides->socketpool = self->sockpool;
    } else if (self->config.preserve_host) {
        overrides->hostport.host = self->upstream.host;
        overrides->hostport.port = h2o_url_get_port(&self->upstream);
    }
    overrides->location_rewrite.match = &self->upstream;
    overrides->location_rewrite.path_prefix = req->pathconf->path;
    overrides->client_ctx = h2o_context_get_handler_context(req->conn->ctx, &self->super);
    
    /* determine the scheme and authority */
    if (self->config.preserve_host) {
        scheme = req->scheme;
        authority = &req->authority;
    } else {
        scheme = self->upstream.scheme;
        authority = &self->upstream.authority;
    }
    
    char *path = req->path_normalized.base;
    
    size_t dname_s = 0;
    size_t dname_e = 0;
    size_t z_s = 0;
    size_t z_e = 0;
    size_t x_s = 0;
    size_t x_e = 0;
    size_t y_s = 0;
    size_t y_e = 0;
    size_t ext_s = 0;
    size_t ext_e = 0;
    size_t slash_c = 0;
    size_t pathonly_e = 0;
    
    size_t i;
    size_t len = strlen(path);
    size_t start = req->pathconf->path.len;
    
    for (i = start; i < len; ++i) {
        if (path[i] == '/') {
            if (slash_c == 0) {
                if (path[i+1] == '/')
                    continue;
                dname_s = i + 1;
            }
            if (slash_c == 1) {
                dname_e = i;
                z_s = i + 1;
            }
            if (slash_c == 2) {
                z_e = i;
                x_s = i + 1;
            }
            if (slash_c == 3) {
                x_e = i;
                y_s = i + 1;
            }
            slash_c++;
        } else if (path[i] == '.') {
            y_e = i;
            ext_s = i + 1;
        } else if (path[i] == '?') {
            pathonly_e = i;
        } else if (path[i] == ' ') {
            ext_e = i;
            break;
        }
    }
    
    size_t hashkey_l = (pathonly_e > 0 ? pathonly_e : ext_e) - dname_s;
    char hashkey_c[hashkey_l + 1];
    strncpy(hashkey_c, path+dname_s, hashkey_l);
    hashkey_c[hashkey_l] = '\0';
    
    char hashed[5];
    md5_short(hashed, hashkey_c, hashkey_l);
    
    if (dname_s == 0 || dname_e == 0 || z_s == 0 || z_e == 0 || x_s == 0 || x_e == 0 || y_s == 0 || y_e == 0 || ext_s == 0 || ext_e == 0)
        return 1;
    
    if (dname_e - dname_s < 1 || z_e - z_s < 1 || x_e - x_s < 1 || y_e - y_s < 1 || ext_e - ext_s < 1)
        return 1;
    
    size_t dname_l = dname_e-dname_s;
    char dname_c[dname_l + 1];
    strncpy(dname_c, path+dname_s, dname_l);
    dname_c[dname_l] = '\0';
    
    size_t z_l = z_e-z_s;
    char z_c[z_l + 1];
    strncpy(z_c, path+z_s, z_l);
    z_c[z_l] = '\0';
    
    size_t x_l = x_e-x_s;
    char x_c[x_l + 1];
    strncpy(x_c, path+x_s, x_l);
    x_c[x_l] = '\0';
    
    size_t y_l = y_e-y_s;
    char y_c[y_l + 1];
    strncpy(y_c, path+y_s, y_l);
    y_c[y_l] = '\0';
    
    size_t ext_l = ext_e-ext_s;
    char ext_c[ext_l + 1];
    strncpy(ext_c, path+ext_s, ext_l);
    ext_c[ext_l] = '\0';
    
    h2o_iovec_t prefix = h2o_iovec_init(hashed, 4);
    
    h2o_iovec_t parts[12]; // [/] [honjo2-testtile] [/] [8f18] [-] [17] [/] [116417] [/] [51630] [.] [png]
    size_t num_parts = 0;
    
    h2o_iovec_t slash_t = h2o_iovec_init(H2O_STRLIT("/"));
    
    parts[num_parts++] = slash_t;
    parts[num_parts++] = h2o_iovec_init(H2O_STRLIT(dname_c));
    parts[num_parts++] = slash_t;
    parts[num_parts++] = prefix;
    parts[num_parts++] = h2o_iovec_init(H2O_STRLIT("-"));
    parts[num_parts++] = h2o_iovec_init(H2O_STRLIT(z_c));
    parts[num_parts++] = slash_t;
    parts[num_parts++] = h2o_iovec_init(H2O_STRLIT(x_c));
    parts[num_parts++] = slash_t;
    parts[num_parts++] = h2o_iovec_init(H2O_STRLIT(y_c));
    parts[num_parts++] = h2o_iovec_init(H2O_STRLIT("."));
    parts[num_parts++] = h2o_iovec_init(H2O_STRLIT(ext_c));
    
    h2o_iovec_t ret = h2o_concat_list(&req->pool, parts, num_parts);
//    printf("===== ret=%s\n", ret.base);
    
    h2o_reprocess_request(req, req->method, scheme, *authority,
                          ret, overrides, 0);
    
    return 0;
}

static void on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void *)_self;
    
    /* use the loop of first context for handling socketpool timeouts */
    if (self->sockpool != NULL && self->sockpool->timeout == UINT64_MAX)
        h2o_socketpool_set_timeout(self->sockpool, ctx->loop, self->config.keepalive_timeout);
    
    /* setup a specific client context only if we need to */
    if (ctx->globalconf->proxy.io_timeout == self->config.io_timeout && !self->config.websocket.enabled &&
        self->config.ssl_ctx == ctx->globalconf->proxy.ssl_ctx)
        return;
    
    h2o_http1client_ctx_t *client_ctx = h2o_mem_alloc(sizeof(*ctx));
    client_ctx->loop = ctx->loop;
    client_ctx->getaddr_receiver = &ctx->receivers.hostinfo_getaddr;
    if (ctx->globalconf->proxy.io_timeout == self->config.io_timeout) {
        client_ctx->io_timeout = &ctx->proxy.io_timeout;
    } else {
        client_ctx->io_timeout = h2o_mem_alloc(sizeof(*client_ctx->io_timeout));
        h2o_timeout_init(client_ctx->loop, client_ctx->io_timeout, self->config.io_timeout);
    }
    if (self->config.websocket.enabled) {
        /* FIXME avoid creating h2o_timeout_t for every path-level context in case the timeout values are the same */
        client_ctx->websocket_timeout = h2o_mem_alloc(sizeof(*client_ctx->websocket_timeout));
        h2o_timeout_init(client_ctx->loop, client_ctx->websocket_timeout, self->config.websocket.timeout);
    } else {
        client_ctx->websocket_timeout = NULL;
    }
    client_ctx->ssl_ctx = self->config.ssl_ctx;
    
    h2o_context_set_handler_context(ctx, &self->super, client_ctx);
}

static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct rp_handler_t *self = (void *)_self;
    h2o_http1client_ctx_t *client_ctx = h2o_context_get_handler_context(ctx, &self->super);
    
    if (client_ctx == NULL)
        return;
    
    if (client_ctx->io_timeout != &ctx->proxy.io_timeout) {
        h2o_timeout_dispose(client_ctx->loop, client_ctx->io_timeout);
        free(client_ctx->io_timeout);
    }
    if (client_ctx->websocket_timeout != NULL) {
        h2o_timeout_dispose(client_ctx->loop, client_ctx->websocket_timeout);
        free(client_ctx->websocket_timeout);
    }
    free(client_ctx);
}

static void on_handler_dispose(h2o_handler_t *_self)
{
    struct rp_handler_t *self = (void *)_self;
    
    if (self->config.ssl_ctx != NULL)
        SSL_CTX_free(self->config.ssl_ctx);
    free(self->upstream.host.base);
    free(self->upstream.path.base);
    if (self->sockpool != NULL) {
        h2o_socketpool_dispose(self->sockpool);
        free(self->sockpool);
    }
}

void h2o_s3tile_proxy_register_reverse_proxy(h2o_pathconf_t *pathconf, h2o_url_t *upstream, h2o_proxy_config_vars_t *config)
{
    struct rp_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));
    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
    self->super.dispose = on_handler_dispose;
    self->super.on_req = on_req;
    if (config->keepalive_timeout != 0) {
        self->sockpool = h2o_mem_alloc(sizeof(*self->sockpool));
        struct sockaddr_un sa;
        const char *to_sa_err;
        int is_ssl = upstream->scheme == &H2O_URL_SCHEME_HTTPS;
        if ((to_sa_err = h2o_url_host_to_sun(upstream->host, &sa)) == h2o_url_host_to_sun_err_is_not_unix_socket) {
            h2o_socketpool_init_by_hostport(self->sockpool, upstream->host, h2o_url_get_port(upstream), is_ssl,
                                            SIZE_MAX /* FIXME */);
        } else {
            assert(to_sa_err == NULL);
            h2o_socketpool_init_by_address(self->sockpool, (void *)&sa, sizeof(sa), is_ssl, SIZE_MAX /* FIXME */);
        }
    }
    h2o_url_copy(NULL, &self->upstream, upstream);
    h2o_strtolower(self->upstream.host.base, self->upstream.host.len);
    self->config = *config;
    if (self->config.ssl_ctx != NULL)
        CRYPTO_add(&self->config.ssl_ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
}