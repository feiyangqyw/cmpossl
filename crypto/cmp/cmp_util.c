/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#include <string.h>
#include <openssl/cmp_util.h>
#include <openssl/trace.h>
#include <openssl/err.h>
#include <openssl/cmperr.h>
#include <openssl/x509v3.h>

/*
 * functions for logging via the trace API
 */

static size_t trace_cb(const char *buf, size_t cnt,
                       int category, int cmd, void *vdata)
{
    BIO *bio = vdata;
    const char *label = NULL;
    size_t ret;

    switch (cmd) {
    case OSSL_TRACE_CTRL_BEGIN:
        label = "BEGIN";
        break;
    case OSSL_TRACE_CTRL_END:
        label = "END";
        break;
    }

    if (label != NULL) {
        union {
            pthread_t tid;
            unsigned long ltid;
        } tid;

        tid.tid = pthread_self();
        BIO_printf(bio, "%s TRACE[%s]:%lx\n",
                   label, OSSL_trace_get_category_name(category), tid.ltid);
    }

    ret = (size_t)BIO_puts(bio, buf);
    if (cmd == OSSL_TRACE_CTRL_END) { /* OSSL_trace_end() flushes too early */
        if (BIO_flush(bio) <= 0)
            ret = 0;
    }
    return ret;
}

int OSSL_CMP_log_open(void)
{
#ifndef OPENSSL_NO_STDIO
    BIO *bio_out = bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO *bio_err = bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (bio_out== NULL || bio_err == NULL)
        goto err;

    if (OSSL_trace_set_callback(OSSL_TRACE_CATEGORY_FATAL, trace_cb, bio_err)
        && OSSL_trace_set_callback(OSSL_TRACE_CATEGORY_ERR, trace_cb, bio_err)
        && OSSL_trace_set_callback(OSSL_TRACE_CATEGORY_WARN, trace_cb, bio_out)
        && OSSL_trace_set_callback(OSSL_TRACE_CATEGORY_INFO, trace_cb, bio_out)
        && OSSL_trace_set_callback(OSSL_TRACE_CATEGORY_DEBUG, trace_cb, bio_out)
       )
        return 1;

 err:
    BIO_free(bio_out);
    BIO_free(bio_err);
#endif
    return 0;
}

void OSSL_CMP_log_close(void)
{
    /*
     * here bio_out and bio_err, as allocated above, should better be freeed,
     * but this is currently not supported by the trace API.
     */
}

int OSSL_CMP_puts(const char *component, const char *file, int lineno,
                  OSSL_CMP_severity level, const char *msg)
{
    char *lvl = NULL;
    size_t msg_len;
    int msg_nl;
    char loc[256];
    int len = 0;
    size_t trc_len = 0; /* default 0 means failure */

    if (component == NULL)
        component = "(no component)";
    if (file == NULL)
        file = "(no file)";
    if (msg == NULL)
        msg = "(no message)";

#ifndef NDEBUG
    len  = snprintf(loc+len , sizeof(loc)-len, "%s():", component);
    len += snprintf(loc+len , sizeof(loc)-len, "%s:", file);
    len += snprintf(loc+len , sizeof(loc)-len, "%d:", lineno);
#else
    if (level == OSSL_LOG_DEBUG)
        return 1;
    len += snprintf(loc+len , sizeof(loc)-len, "CMP");
#endif

    switch(level) {
    case OSSL_LOG_EMERG  : lvl = "EMERGENCY"; break;
    case OSSL_LOG_ALERT  : lvl = "ALERT"; break;
    case OSSL_LOG_CRIT   : lvl = "CRITICAL" ; break;
    case OSSL_LOG_ERR    : lvl = "ERROR"; break;
    case OSSL_LOG_WARNING: lvl = "WARNING" ; break;
    case OSSL_LOG_NOTICE : lvl = "NOTICE" ; break;
    case OSSL_LOG_INFO   : lvl = "INFO" ; break;
#ifndef NDEBUG
    case OSSL_LOG_DEBUG  : lvl = "DEBUG"; break;
#endif
    default: break;
    }

    if (lvl != NULL)
        (void)snprintf(loc+len , sizeof(loc)-len, " %s", lvl);
    msg_len = strlen(msg);
    msg_nl = msg_len > 0 && msg[msg_len-1] == '\n';

    do {
        int category
            = level == OSSL_LOG_ERR     ? OSSL_TRACE_CATEGORY_ERR
            : level == OSSL_LOG_WARNING ? OSSL_TRACE_CATEGORY_WARN
            : level == OSSL_LOG_INFO    ? OSSL_TRACE_CATEGORY_INFO
            : level == OSSL_LOG_DEBUG   ? OSSL_TRACE_CATEGORY_DEBUG
            :                             OSSL_TRACE_CATEGORY_FATAL;
        BIO *trc_out = OSSL_trace_begin(category);

        if (trc_out != NULL) {
            trc_len = BIO_printf(trc_out, "%s: %s%s", loc, msg,
                                 msg_nl != 0 ? "" : "\n");
            OSSL_trace_end(category, trc_out);
        }
    } while (0);

    return trc_len;
}

int OSSL_CMP_log_printf(OSSL_cmp_log_cb_t log_fn,
                        const char *func, const char *file, int lineno,
                        OSSL_CMP_severity level, const char *fmt, va_list argp)
{
    char component_func[256];
    char msg[1024];
    int res;

    if (log_fn == NULL)
        log_fn = OSSL_CMP_puts;
    BIO_snprintf(component_func, sizeof(component_func), "OpenSSL:%s", func);
    BIO_vsnprintf(msg, sizeof(msg), fmt, argp);
    res = (*log_fn)(component_func, file, lineno, level, msg);
    return res;
}

/*
 * auxiliary function for error reporting via the OpenSSL error queue
 */

void OSSL_CMP_add_error_txt(const char *separator, const char *txt)
{
    const char *file;
    int line;
    const char *data;
    int flags;
    unsigned long err = ERR_peek_last_error();

    if (separator == NULL)
        separator = "";
    if (err == 0)
        ERR_PUT_error(ERR_LIB_CMP, 0, err, "", 0);

#define MAX_DATA_LEN 4096-100 /* workaround for ERR_print_errors_cb() limit */
    do {
        const char *curr, *next;
        int len;
        char *tmp;

        ERR_peek_last_error_line_data(&file, &line, &data, &flags);
        if (!(flags & ERR_TXT_STRING)) {
            data = "";
            separator = "";
        }
        len = (int)strlen(data);
        curr = next = txt;
        while (*next != '\0'
                   && len + strlen(separator) + (next - txt) < MAX_DATA_LEN) {
            curr = next;
            if (*separator != '\0') {
                next = strstr(curr, separator);
                if (next != NULL)
                    next += strlen(separator);
                else
                    next = curr + strlen(curr);
            } else
                next = curr + 1;
        }
        if (*next != '\0') { /* split error msg if error data gets too long */
            if (curr != txt) {
                tmp = OPENSSL_strndup(txt, curr - txt);
                ERR_add_error_data(3, data, separator, tmp);
                OPENSSL_free(tmp);
            }
            ERR_PUT_error(ERR_LIB_CMP, 0 /* func */, err, file, line);
            txt = curr;
        } else {
            ERR_add_error_data(3, data, separator, txt);
            txt = next;
        }
    } while (*txt != '\0');
}

/*
 * functions manipulating lists of certificates etc.
 */

/* this is similar to ERR_print_errors_cb, but uses the CMP-specific cb type */
void OSSL_CMP_print_errors_cb(OSSL_cmp_log_cb_t log_fn)
{
    unsigned long err;
    char component[256];
    char msg[4096];
    const char *file, *data;
    int line, flags;

    if (log_fn == NULL)
        log_fn = OSSL_CMP_puts;
    while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        if (!(flags & ERR_TXT_STRING))
            data = NULL;
        BIO_snprintf(component, sizeof(component), "OpenSSL:%s",
                     /* ERR_lib_error_string(err), */
                     ERR_func_error_string(err));
        BIO_snprintf(msg, sizeof(msg), "%s%s%s", ERR_reason_error_string(err),
                     data == NULL ? "" : " : ", data == NULL ? "" : data);
        if (log_fn(component, file, line, OSSL_LOG_ERR, msg) <= 0)
            break;              /* abort outputting the error report */
    }
}

int OSSL_CMP_sk_X509_add1_cert(STACK_OF(X509) *sk, X509 *cert,
                               int not_duplicate, int prepend)
{
    if (not_duplicate) {
        /*
         * not using sk_X509_set_cmp_func() and sk_X509_find()
         * because this re-orders the certs on the stack
         */
        int i;

        for (i = 0; i < sk_X509_num(sk); i++) {
            if (X509_cmp(sk_X509_value(sk, i), cert) == 0)
                return 1;
        }
    }
    if (!sk_X509_insert(sk, cert, prepend ? 0 : -1))
        return 0;
    return X509_up_ref(cert);
}

int OSSL_CMP_sk_X509_add1_certs(STACK_OF(X509) *sk, const STACK_OF(X509) *certs,
                                int no_self_signed, int no_duplicates)
{
    int i;

    if (sk == NULL)
        return 0;

    if (certs == NULL)
        return 1;
    for (i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);
        if (!no_self_signed || X509_check_issued(cert, cert) != X509_V_OK) {
            if (!OSSL_CMP_sk_X509_add1_cert(sk, cert, no_duplicates, 0))
                return 0;
        }
    }
    return 1;
}

int OSSL_CMP_X509_STORE_add1_certs(X509_STORE *store, STACK_OF(X509) *certs,
                                   int only_self_signed)
{
    int i;

    if (store == NULL)
        return 0;

    if (certs == NULL)
        return 1;
    for (i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);
        if (!only_self_signed || X509_check_issued(cert, cert) == X509_V_OK)
            if (!X509_STORE_add_cert(store, cert)) /* ups cert ref counter */
                return 0;
    }
    return 1;
}

STACK_OF(X509) *OSSL_CMP_X509_STORE_get1_certs(X509_STORE *store)
{
    int i;
    STACK_OF(X509) *sk;
    STACK_OF(X509_OBJECT) *objs;

    if (store == NULL)
        return NULL;
    if ((sk = sk_X509_new_null()) == NULL)
        return NULL;
    objs = X509_STORE_get0_objects(store);
    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        X509 *cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));
        if (cert != NULL) {
            if (!sk_X509_push(sk, cert)) {
                sk_X509_pop_free(sk, X509_free);
                return NULL;
            }
            X509_up_ref(cert);
        }
    }
    return sk;
}

X509_EXTENSIONS *OSSL_CMP_X509_EXTENSIONS_dup(const X509_EXTENSIONS *extin)
{
    X509_EXTENSIONS *exts;
    int i;

    if (extin == NULL)
        return NULL;

    if ((exts = sk_X509_EXTENSION_new_null()) == NULL)
        return NULL;
    for (i = 0; i < sk_X509_EXTENSION_num(extin); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(extin, i);
        if (!sk_X509_EXTENSION_push(exts, X509_EXTENSION_dup(ext)))
        {
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            return NULL;
        }
    }
    return exts;
}

int OSSL_CMP_ASN1_OCTET_STRING_set1(ASN1_OCTET_STRING **tgt,
                                    const ASN1_OCTET_STRING *src)
{
    if (tgt == NULL) {
        CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1, CMP_R_NULL_ARGUMENT);
        goto err;
    }
    if (*tgt == src) /* self-assignment */
        return 1;
    ASN1_OCTET_STRING_free(*tgt);

    if (src != NULL) {
        if ((*tgt = ASN1_OCTET_STRING_dup(src)) == NULL) {
            CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else {
        *tgt = NULL;
    }

    return 1;
 err:
    return 0;
}

int OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(ASN1_OCTET_STRING **tgt,
                                          const unsigned char *bytes, size_t len)
{
    ASN1_OCTET_STRING *new = NULL;
    int res = 0;

    if (tgt == NULL) {
        CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1_BYTES, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    if (bytes != NULL) {
        if ((new = ASN1_OCTET_STRING_new()) == NULL
                || !(ASN1_OCTET_STRING_set(new, bytes, (int)len))) {
            CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1_BYTES,
                   ERR_R_MALLOC_FAILURE);
            goto err;
        }

    }
    res = OSSL_CMP_ASN1_OCTET_STRING_set1(tgt, new);

 err:
    ASN1_OCTET_STRING_free(new);
    return res;
}
