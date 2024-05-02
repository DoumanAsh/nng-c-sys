//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is distributed under the terms of the GPLv3, a
// copy of which should be located as the file COPYING in the
// same directory as this file.  A copy of the license may also be
// found online at https://opensource.org/licenses/GPL-3.0
//
// Commercial users may obtain a commercial license without GPLv3
// restrictions.  Please contact info@staysail.tech for details.
//
// SPDX-License-Identifier: GPL-3.0-only
//

// NB: This file is *optional*.  If you prefer not to be bound by the terms
// of the GPLv3, you may configure NNG without this module.  There are
// alternative libraries for TLS that offer more liberal licensing, or you
// may purchase a commercial license from the license holder by contacting
// Staysail Systems, Inc. at info@staysail.tech.

// Caveats:
//
// 1. WolfSSL has a lot of optional configurations.  We recommend enabling
//    the OpenSSL extra flag to ensure that full support of TLS versions
//    and options are present.
// 2. WolfSSL does not support limiting the "maximum" TLS version.
// 3. WolfSSL does not support checking the validation state of connections.
//    Thus if NNG_TLS_AUTH_MODE_OPTIONAL is requested, then the check
//    for verification will return false because we don't know.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/ssl.h>

#include <nng/nng.h>
#include <nng/supplemental/tls/engine.h>

struct nng_tls_engine_conn {
	void *       tls; // parent conn
	WOLFSSL_CTX *ctx;
	WOLFSSL *    ssl;
	int          auth_mode;
};

struct nng_tls_engine_config {
	WOLFSSL_CTX *ctx;
	char *       pass;
	char *       server_name;
	int          auth_mode;
};

static int
wolf_net_send(WOLFSSL *ssl, char *buf, int len, void *ctx)
{
	size_t sz = len;
	int    rv;
	(void) ssl;

	rv = nng_tls_engine_send(ctx, (const uint8_t *) buf, &sz);
	switch (rv) {
	case 0:
		return ((int) sz);
	case NNG_EAGAIN:
		return (WOLFSSL_CBIO_ERR_WANT_WRITE);
	case NNG_ECLOSED:
		return (WOLFSSL_CBIO_ERR_CONN_CLOSE);
	case NNG_ECONNSHUT:
		return (WOLFSSL_CBIO_ERR_CONN_RST);
	default:
		return (WOLFSSL_CBIO_ERR_GENERAL);
	}
}

static int
wolf_net_recv(WOLFSSL *ssl, char *buf, int len, void *ctx)
{
	size_t sz = len;
	int    rv;
	(void) ssl;

	rv = nng_tls_engine_recv(ctx, (uint8_t *) buf, &sz);
	switch (rv) {
	case 0:
		return ((int) sz);
	case NNG_EAGAIN:
		return (WOLFSSL_CBIO_ERR_WANT_READ);
	case NNG_ECLOSED:
		return (WOLFSSL_CBIO_ERR_CONN_CLOSE);
	case NNG_ECONNSHUT:
		return (WOLFSSL_CBIO_ERR_CONN_RST);
	default:
		return (WOLFSSL_CBIO_ERR_GENERAL);
	}
}

static void
wolf_conn_fini(nng_tls_engine_conn *ec)
{
	wolfSSL_free(ec->ssl);
}

static int
wolf_conn_init(nng_tls_engine_conn *ec, void *tls, nng_tls_engine_config *cfg)
{
	ec->tls       = tls;
	ec->auth_mode = cfg->auth_mode;

	if ((ec->ssl = wolfSSL_new(cfg->ctx)) == NULL) {
		return (NNG_ENOMEM); // most likely
	}
	if (cfg->server_name != NULL) {
		if (wolfSSL_check_domain_name(ec->ssl, cfg->server_name) !=
		    WOLFSSL_SUCCESS) {
			wolfSSL_free(ec->ssl);
			ec->ssl = NULL;
			return (NNG_ENOMEM);
		}
	}
	wolfSSL_SetIOReadCtx(ec->ssl, ec->tls);
	wolfSSL_SetIOWriteCtx(ec->ssl, ec->tls);
	return (0);
}

static void
wolf_conn_close(nng_tls_engine_conn *ec)
{
	(void) wolfSSL_shutdown(ec->ssl);
}

static int
wolf_conn_recv(nng_tls_engine_conn *ec, uint8_t *buf, size_t *szp)
{
	int rv;
	if ((rv = wolfSSL_read(ec->ssl, buf, (int) *szp)) < 0) {
		rv = wolfSSL_get_error(ec->ssl, rv);
		switch (rv) {

		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return (NNG_EAGAIN);
		case SSL_ERROR_SSL:
			return (NNG_ECRYPTO);
		case SSL_ERROR_SYSCALL:
			return (NNG_ESYSERR);
		default:
			return (NNG_EINTERNAL);
		}
	}
	*szp = (size_t) rv;
	return (0);
}

static int
wolf_conn_send(nng_tls_engine_conn *ec, const uint8_t *buf, size_t *szp)
{
	int rv;

	if ((rv = wolfSSL_write(ec->ssl, buf, (int) (*szp))) <= 0) {
		rv = wolfSSL_get_error(ec->ssl, rv);
		switch (rv) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return (NNG_EAGAIN);
		case SSL_ERROR_SSL:
			return (NNG_ECRYPTO);
		case SSL_ERROR_SYSCALL:
			return (NNG_ESYSERR);
		default:
			return (NNG_EINTERNAL);
		}
	}
	*szp = (size_t) rv;
	return (0);
}

static int
wolf_conn_handshake(nng_tls_engine_conn *ec)
{
	int rv;

	rv = wolfSSL_negotiate(ec->ssl);
	if (rv != WOLFSSL_SUCCESS) {
		rv = wolfSSL_get_error(ec->ssl, rv);
		switch (rv) {
		case WOLFSSL_SUCCESS:
			return (0);
		case WOLFSSL_ERROR_WANT_WRITE:
		case WOLFSSL_ERROR_WANT_READ:
			return (NNG_EAGAIN);
		default:
			// This can fail if we do not have a certificate
			// for the peer.  This will manifest as a failure
			// during nng_dialer_start typically.
			return (NNG_ECRYPTO);
		}
	}
	return (0);
}

static bool
wolf_conn_verified(nng_tls_engine_conn *ec)
{
	switch (ec->auth_mode) {
	case NNG_TLS_AUTH_MODE_NONE:
		return (false);
	case NNG_TLS_AUTH_MODE_REQUIRED:
		return (true);
	case NNG_TLS_AUTH_MODE_OPTIONAL:
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
		if (wolfSSL_get_peer_certificate(ec->ssl) != NULL) {
			return (true);
		}
#endif
		// If we don't have support for verification, we will
		// just return false, because we can't do anything else.
		return (false);
	default:
		// The client might have supplied us a cert, but wolfSSL
		// is not configured to provide us that information.
		// We ignore it.
		return (false);
	}
}

static void
wolf_config_fini(nng_tls_engine_config *cfg)
{
	wolfSSL_CTX_free(cfg->ctx);
	if (cfg->server_name != NULL) {
		nng_strfree(cfg->server_name);
	}
	if (cfg->pass != NULL) {
		nng_strfree(cfg->pass);
	}
}

static int
wolf_config_init(nng_tls_engine_config *cfg, enum nng_tls_mode mode)
{
	int             auth_mode;
	int             nng_auth;
	WOLFSSL_METHOD *method;

	if (mode == NNG_TLS_MODE_SERVER) {
		method    = wolfSSLv23_server_method();
		auth_mode = SSL_VERIFY_NONE;
		nng_auth = NNG_TLS_AUTH_MODE_NONE;
	} else {
		method    = wolfSSLv23_client_method();
		auth_mode = SSL_VERIFY_PEER;
		nng_auth = NNG_TLS_AUTH_MODE_REQUIRED;
	}

	cfg->ctx = wolfSSL_CTX_new(method);
	if (cfg->ctx == NULL) {
		return (NNG_ENOMEM);
	}

	// By default we require TLS 1.2.
	wolfSSL_CTX_SetMinVersion(cfg->ctx, WOLFSSL_TLSV1_2);
	wolfSSL_CTX_set_verify(cfg->ctx, auth_mode, NULL);

	wolfSSL_SetIORecv(cfg->ctx, wolf_net_recv);
	wolfSSL_SetIOSend(cfg->ctx, wolf_net_send);

	cfg->auth_mode = nng_auth;
	return (0);
}

static int
wolf_config_server(nng_tls_engine_config *cfg, const char *name)
{
	char *dup;
	if ((dup = nng_strdup(name)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (cfg->server_name) {
		nng_strfree(cfg->server_name);
	}
	cfg->server_name = dup;
	return (0);
}

static int
wolf_config_auth_mode(nng_tls_engine_config *cfg, nng_tls_auth_mode mode)
{
	cfg->auth_mode = mode;
	switch (mode) {
	case NNG_TLS_AUTH_MODE_NONE:
		wolfSSL_CTX_set_verify(cfg->ctx, SSL_VERIFY_NONE, NULL);
		return (0);
	case NNG_TLS_AUTH_MODE_OPTIONAL:
		wolfSSL_CTX_set_verify(cfg->ctx, SSL_VERIFY_PEER, NULL);
		return (0);
	case NNG_TLS_AUTH_MODE_REQUIRED:
		wolfSSL_CTX_set_verify(cfg->ctx,
		    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		return (0);
	}
	return (NNG_EINVAL);
}

static int
wolf_config_ca_chain(
    nng_tls_engine_config *cfg, const char *certs, const char *crl)
{
	size_t len;
	int    rv;

	// Certs and CRL are in PEM data, with terminating NUL byte.
	len = strlen(certs);

	rv = wolfSSL_CTX_load_verify_buffer(
	    cfg->ctx, (void *) certs, len, SSL_FILETYPE_PEM);
	if (rv != SSL_SUCCESS) {
		return (NNG_ECRYPTO);
	}
	if (crl == NULL) {
		return (0);
	}

#ifdef NNG_WOLFSSL_HAVE_CRL
	len = strlen(crl);
	rv  = wolfSSL_CTX_LoadCRLBuffer(
            cfg->ctx, (void *) crl, len, SSL_FILETYPE_PEM);
	if (rv != SSL_SUCCESS) {
		return (NNG_ECRYPTO);
	}
#endif

	return (0);
}

#if NNG_WOLFSSL_HAVE_PASSWORD
static int
wolf_get_password(char *passwd, int size, int rw, void *ctx)
{
	// password is *not* NUL terminated in wolf
	nng_tls_engine_config *cfg = ctx;
	size_t                 len;

	(void) rw;

	if (cfg->pass == NULL) {
		return (0);
	}
	len = strlen(cfg->pass); // Our "ctx" is really the password.
	if (len > (size_t) size) {
		len = size;
	}
	memcpy(passwd, cfg->pass, len);
	return (len);
}
#endif

static int
wolf_config_own_cert(nng_tls_engine_config *cfg, const char *cert,
    const char *key, const char *pass)
{
	int   rv;
	char *dup = NULL;

#if NNG_WOLFSSL_HAVE_PASSWORD
	if (pass != NULL) {
		if ((dup = nng_strdup(pass)) == NULL) {
			return (NNG_ENOMEM);
		}
	}
	if (cfg->pass != NULL) {
		nng_strfree(cfg->pass);
	}
	cfg->pass = dup;
	wolfSSL_CTX_set_default_passwd_cb_userdata(cfg->ctx, cfg);
	wolfSSL_CTX_set_default_passwd_cb(cfg->ctx, wolf_get_password);
#else
	(void) pass;
#endif

	rv = wolfSSL_CTX_use_certificate_buffer(
	    cfg->ctx, (void *) cert, strlen(cert), SSL_FILETYPE_PEM);
	if (rv != SSL_SUCCESS) {
		return (NNG_EINVAL);
	}
	rv = wolfSSL_CTX_use_PrivateKey_buffer(
	    cfg->ctx, (void *) key, strlen(key), SSL_FILETYPE_PEM);
	if (rv != SSL_SUCCESS) {
		return (NNG_EINVAL);
	}
	return (0);
}

static int
wolf_config_version(nng_tls_engine_config *cfg, nng_tls_version min_ver,
    nng_tls_version max_ver)
{
	int rv;

	if ((min_ver > max_ver) || (max_ver > NNG_TLS_1_3)) {
		return (NNG_ENOTSUP);
	}
	switch (min_ver) {
	case NNG_TLS_1_0:
		rv = wolfSSL_CTX_SetMinVersion(cfg->ctx, WOLFSSL_TLSV1);
		break;
	case NNG_TLS_1_1:
		rv = wolfSSL_CTX_SetMinVersion(cfg->ctx, WOLFSSL_TLSV1_1);
		break;
	case NNG_TLS_1_2:
		rv = wolfSSL_CTX_SetMinVersion(cfg->ctx, WOLFSSL_TLSV1_2);
		break;
	case NNG_TLS_1_3:
		rv = wolfSSL_CTX_SetMinVersion(cfg->ctx, WOLFSSL_TLSV1_3);
		break;
	default:
		return (NNG_ENOTSUP);
	}

	// wolfSSL does not let us restrict the maximum version.

	if (rv != WOLFSSL_SUCCESS) {
		// This happens if the library is missing support for the
		// version.  By default WolfSSL builds with only TLS v1.2
		// and newer enabled.
		return (NNG_ENOTSUP);
	}
	return (0);
}

static nng_tls_engine_config_ops wolf_config_ops = {
	.init     = wolf_config_init,
	.fini     = wolf_config_fini,
	.size     = sizeof(nng_tls_engine_config),
	.auth     = wolf_config_auth_mode,
	.ca_chain = wolf_config_ca_chain,
	.own_cert = wolf_config_own_cert,
	.server   = wolf_config_server,
	.version  = wolf_config_version,
};

static nng_tls_engine_conn_ops wolf_conn_ops = {
	.size      = sizeof(nng_tls_engine_conn),
	.init      = wolf_conn_init,
	.fini      = wolf_conn_fini,
	.close     = wolf_conn_close,
	.recv      = wolf_conn_recv,
	.send      = wolf_conn_send,
	.handshake = wolf_conn_handshake,
	.verified  = wolf_conn_verified,
};

static nng_tls_engine wolf_engine = {
	.version     = NNG_TLS_ENGINE_VERSION,
	.config_ops  = &wolf_config_ops,
	.conn_ops    = &wolf_conn_ops,
	.name        = "wolf",
	.description = "wolfSSL " LIBWOLFSSL_VERSION_STRING,
	.fips_mode   = false, // commercial users only
};

int
nng_tls_engine_init_wolf(void)
{
	switch (wolfSSL_Init()) {
	case WOLFSSL_SUCCESS:
		break;
	default:
		// Best guess...
		wolfSSL_Cleanup();
		return (NNG_EINTERNAL);
	}
	return (nng_tls_engine_register(&wolf_engine));
}

void
nng_tls_engine_fini_wolf(void)
{
	(void) wolfSSL_Cleanup();
}