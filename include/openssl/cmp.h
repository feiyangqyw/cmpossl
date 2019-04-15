/*-
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP (RFC 4210) implementation by M. Peylo, M. Viljanen, and D. von Oheimb.
 */

#ifndef OSSL_HEADER_CMP_H
# define OSSL_HEADER_CMP_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_CMP
#  include <openssl/crmf.h>
#  include <openssl/cmperr.h>

/* explicit #includes not strictly needed since implied by the above: */
#  include <openssl/ossl_typ.h>
#  include <openssl/safestack.h>
#  include <openssl/x509.h>
#  include <openssl/x509v3.h>

#  define OSSL_CMP_PVNO 2

#  ifdef  __cplusplus
extern "C" {
#  endif

/*-
 *   PKIFailureInfo ::= BIT STRING {
 *   -- since we can fail in more than one way!
 *   -- More codes may be added in the future if/when required.
 *       badAlg              (0),
 *       -- unrecognized or unsupported Algorithm Identifier
 *       badMessageCheck     (1),
 *       -- integrity check failed (e.g., signature did not verify)
 *       badRequest          (2),
 *       -- transaction not permitted or supported
 *       badTime             (3),
 *       -- messageTime was not sufficiently close to the system time,
 *       -- as defined by local policy
 *       badCertId           (4),
 *       -- no certificate could be found matching the provided criteria
 *       badDataFormat       (5),
 *       -- the data submitted has the wrong format
 *       wrongAuthority      (6),
 *       -- the authority indicated in the request is different from the
 *       -- one creating the response token
 *       incorrectData       (7),
 *       -- the requester's data is incorrect (for notary services)
 *       missingTimeStamp    (8),
 *       -- when the timestamp is missing but should be there
 *       -- (by policy)
 *       badPOP              (9),
 *       -- the proof-of-possession failed
 *       certRevoked         (10),
 *          -- the certificate has already been revoked
 *       certConfirmed       (11),
 *          -- the certificate has already been confirmed
 *       wrongIntegrity      (12),
 *          -- invalid integrity, password based instead of signature or
 *          -- vice versa
 *       badRecipientNonce   (13),
 *          -- invalid recipient nonce, either missing or wrong value
 *       timeNotAvailable    (14),
 *          -- the TSA's time source is not available
 *       unacceptedPolicy    (15),
 *          -- the requested TSA policy is not supported by the TSA.
 *       unacceptedExtension (16),
 *          -- the requested extension is not supported by the TSA.
 *       addInfoNotAvailable (17),
 *          -- the additional information requested could not be
 *          -- understood or is not available
 *       badSenderNonce      (18),
 *          -- invalid sender nonce, either missing or wrong size
 *       badCertTemplate     (19),
 *          -- invalid cert. template or missing mandatory information
 *       signerNotTrusted    (20),
 *          -- signer of the message unknown or not trusted
 *       transactionIdInUse  (21),
 *          -- the transaction identifier is already in use
 *       unsupportedVersion  (22),
 *          -- the version of the message is not supported
 *       notAuthorized       (23),
 *          -- the sender was not authorized to make the preceding
 *          -- request or perform the preceding action
 *       systemUnavail       (24),
 *       -- the request cannot be handled due to system unavailability
 *       systemFailure       (25),
 *       -- the request cannot be handled due to system failure
 *       duplicateCertReq    (26)
 *       -- certificate cannot be issued because a duplicate
 *       -- certificate already exists
 *   }
 */
#  define OSSL_CMP_PKIFAILUREINFO_badAlg 0
#  define OSSL_CMP_PKIFAILUREINFO_badMessageCheck 1
#  define OSSL_CMP_PKIFAILUREINFO_badRequest 2
#  define OSSL_CMP_PKIFAILUREINFO_badTime 3
#  define OSSL_CMP_PKIFAILUREINFO_badCertId 4
#  define OSSL_CMP_PKIFAILUREINFO_badDataFormat 5
#  define OSSL_CMP_PKIFAILUREINFO_wrongAuthority 6
#  define OSSL_CMP_PKIFAILUREINFO_incorrectData 7
#  define OSSL_CMP_PKIFAILUREINFO_missingTimeStamp 8
#  define OSSL_CMP_PKIFAILUREINFO_badPOP 9
#  define OSSL_CMP_PKIFAILUREINFO_certRevoked 10
#  define OSSL_CMP_PKIFAILUREINFO_certConfirmed 11
#  define OSSL_CMP_PKIFAILUREINFO_wrongIntegrity 12
#  define OSSL_CMP_PKIFAILUREINFO_badRecipientNonce 13
#  define OSSL_CMP_PKIFAILUREINFO_timeNotAvailable 14
#  define OSSL_CMP_PKIFAILUREINFO_unacceptedPolicy 15
#  define OSSL_CMP_PKIFAILUREINFO_unacceptedExtension 16
#  define OSSL_CMP_PKIFAILUREINFO_addInfoNotAvailable 17
#  define OSSL_CMP_PKIFAILUREINFO_badSenderNonce 18
#  define OSSL_CMP_PKIFAILUREINFO_badCertTemplate 19
#  define OSSL_CMP_PKIFAILUREINFO_signerNotTrusted 20
#  define OSSL_CMP_PKIFAILUREINFO_transactionIdInUse 21
#  define OSSL_CMP_PKIFAILUREINFO_unsupportedVersion 22
#  define OSSL_CMP_PKIFAILUREINFO_notAuthorized 23
#  define OSSL_CMP_PKIFAILUREINFO_systemUnavail 24
#  define OSSL_CMP_PKIFAILUREINFO_systemFailure 25
#  define OSSL_CMP_PKIFAILUREINFO_duplicateCertReq 26
#  define OSSL_CMP_PKIFAILUREINFO_MAX 26
#  define OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN \
    ( (1<<(OSSL_CMP_PKIFAILUREINFO_MAX+1)) - 1)
#  if OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN > INT_MAX
#   error  CMP_PKIFAILUREINFO_MAX bit pattern does not fit in type int
#  endif

typedef ASN1_BIT_STRING OSSL_CMP_PKIFAILUREINFO;

#  define OSSL_CMP_CTX_FAILINFO_badAlg (1 << 0)
#  define OSSL_CMP_CTX_FAILINFO_badMessageCheck (1 << 1)
#  define OSSL_CMP_CTX_FAILINFO_badRequest (1 << 2)
#  define OSSL_CMP_CTX_FAILINFO_badTime (1 << 3)
#  define OSSL_CMP_CTX_FAILINFO_badCertId (1 << 4)
#  define OSSL_CMP_CTX_FAILINFO_badDataFormat (1 << 5)
#  define OSSL_CMP_CTX_FAILINFO_wrongAuthority (1 << 6)
#  define OSSL_CMP_CTX_FAILINFO_incorrectData (1 << 7)
#  define OSSL_CMP_CTX_FAILINFO_missingTimeStamp (1 << 8)
#  define OSSL_CMP_CTX_FAILINFO_badPOP (1 << 9)
#  define OSSL_CMP_CTX_FAILINFO_certRevoked (1 << 10)
#  define OSSL_CMP_CTX_FAILINFO_certConfirmed (1 << 11)
#  define OSSL_CMP_CTX_FAILINFO_wrongIntegrity (1 << 12)
#  define OSSL_CMP_CTX_FAILINFO_badRecipientNonce (1 << 13)
#  define OSSL_CMP_CTX_FAILINFO_timeNotAvailable (1 << 14)
#  define OSSL_CMP_CTX_FAILINFO_unacceptedPolicy (1 << 15)
#  define OSSL_CMP_CTX_FAILINFO_unacceptedExtension (1 << 16)
#  define OSSL_CMP_CTX_FAILINFO_addInfoNotAvailable (1 << 17)
#  define OSSL_CMP_CTX_FAILINFO_badSenderNonce (1 << 18)
#  define OSSL_CMP_CTX_FAILINFO_badCertTemplate (1 << 19)
#  define OSSL_CMP_CTX_FAILINFO_signerNotTrusted (1 << 20)
#  define OSSL_CMP_CTX_FAILINFO_transactionIdInUse (1 << 21)
#  define OSSL_CMP_CTX_FAILINFO_unsupportedVersion (1 << 22)
#  define OSSL_CMP_CTX_FAILINFO_notAuthorized (1 << 23)
#  define OSSL_CMP_CTX_FAILINFO_systemUnavail (1 << 24)
#  define OSSL_CMP_CTX_FAILINFO_systemFailure (1 << 25)
#  define OSSL_CMP_CTX_FAILINFO_duplicateCertReq (1 << 26)

/*-
 *   PKIStatus ::= INTEGER {
 *       accepted                (0),
 *       -- you got exactly what you asked for
 *       grantedWithMods        (1),
 *       -- you got something like what you asked for; the
 *       -- requester is responsible for ascertaining the differences
 *       rejection              (2),
 *       -- you don't get it, more information elsewhere in the message
 *       waiting                (3),
 *       -- the request body part has not yet been processed; expect to
 *       -- hear more later (note: proper handling of this status
 *       -- response MAY use the polling req/rep PKIMessages specified
 *       -- in Section 5.3.22; alternatively, polling in the underlying
 *       -- transport layer MAY have some utility in this regard)
 *       revocationWarning      (4),
 *       -- this message contains a warning that a revocation is
 *       -- imminent
 *       revocationNotification (5),
 *       -- notification that a revocation has occurred
 *       keyUpdateWarning       (6)
 *       -- update already done for the oldCertId specified in
 *       -- CertReqMsg
 *   }
 */
#  define OSSL_CMP_PKISTATUS_accepted 0
#  define OSSL_CMP_PKISTATUS_grantedWithMods 1
#  define OSSL_CMP_PKISTATUS_rejection 2
#  define OSSL_CMP_PKISTATUS_waiting 3
#  define OSSL_CMP_PKISTATUS_revocationWarning 4
#  define OSSL_CMP_PKISTATUS_revocationNotification 5
#  define OSSL_CMP_PKISTATUS_keyUpdateWarning 6

typedef ASN1_INTEGER OSSL_CMP_PKISTATUS;
DECLARE_ASN1_ITEM(OSSL_CMP_PKISTATUS)

#  define OSSL_CMP_CERTORENCCERT_CERTIFICATE 0
#  define OSSL_CMP_CERTORENCCERT_ENCRYPTEDCERT 1

/* data type declarations */
typedef struct OSSL_cmp_ctx_st OSSL_CMP_CTX;
typedef struct OSSL_cmp_pkiheader_st OSSL_CMP_PKIHEADER;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_PKIHEADER)
typedef struct OSSL_cmp_msg_st OSSL_CMP_MSG;
DECLARE_ASN1_ENCODE_FUNCTIONS(OSSL_CMP_MSG, OSSL_CMP_MSG, OSSL_CMP_MSG)
typedef struct OSSL_cmp_certstatus_st OSSL_CMP_CERTSTATUS;
DEFINE_STACK_OF(OSSL_CMP_CERTSTATUS)
typedef struct OSSL_cmp_itav_st OSSL_CMP_ITAV;
DEFINE_STACK_OF(OSSL_CMP_ITAV)
typedef struct OSSL_cmp_revrepcontent_st OSSL_CMP_REVREPCONTENT;
typedef struct OSSL_cmp_pkisi_st OSSL_CMP_PKISI;
DEFINE_STACK_OF(OSSL_CMP_PKISI)
typedef struct OSSL_cmp_certrepmessage_st OSSL_CMP_CERTREPMESSAGE;
DEFINE_STACK_OF(OSSL_CMP_CERTREPMESSAGE)
typedef struct OSSL_cmp_pollrep_st OSSL_CMP_POLLREP;
typedef STACK_OF(OSSL_CMP_POLLREP) OSSL_CMP_POLLREPCONTENT;
typedef struct OSSL_cmp_certresponse_st OSSL_CMP_CERTRESPONSE;
DEFINE_STACK_OF(OSSL_CMP_CERTRESPONSE)
typedef STACK_OF(ASN1_UTF8STRING) OSSL_CMP_PKIFREETEXT;

/*
 * logging
 */

/* declarations resemble those from bio/bss_log.c and syslog.h */
typedef enum {OSSL_LOG_EMERG, OSSL_LOG_ALERT, OSSL_LOG_CRIT, OSSL_LOG_ERR,
              OSSL_LOG_WARNING, OSSL_LOG_NOTICE, OSSL_LOG_INFO, OSSL_LOG_DEBUG}
    OSSL_CMP_severity;

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901)
# define OSSL_CMP_FUNC __func__
#elif defined(__STDC__) && defined(PEDANTIC)
# define OSSL_CMP_FUNC "(PEDANTIC disallows function name)"
#elif defined(WIN32) || defined(__GNUC__) || defined(__GNUG__)
# define OSSL_CMP_FUNC __FUNCTION__
#elif defined(__FUNCSIG__)
# define OSSL_CMP_FUNC __FUNCSIG__
#else
# define OSSL_CMP_FUNC "(unknown function)"
#endif
#define OSSL_CMP_FUNC_FILE_LINE OSSL_CMP_FUNC, OPENSSL_FILE, OPENSSL_LINE
#define OSSL_CMP_FL_EMERG OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_EMERG
#define OSSL_CMP_FL_ALERT OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_ALERT
#define OSSL_CMP_FL_CRIT  OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_CRIT
#define OSSL_CMP_FL_ERR   OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_ERR
#define OSSL_CMP_FL_WARN  OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_WARNING
#define OSSL_CMP_FL_NOTE  OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_NOTICE
#define OSSL_CMP_FL_INFO  OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_INFO
#define OSSL_CMP_FL_DEBUG OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_DEBUG

int OSSL_CMP_puts(const char *component, const char *file, int lineno,
                  OSSL_CMP_severity level, const char *msg);
int OSSL_CMP_printf(const OSSL_CMP_CTX *ctx,
                    const char *func, const char *file, int lineno,
                    OSSL_CMP_severity level, const char *fmt, ...);
#define OSSL_CMP_alert(ctx, msg) OSSL_CMP_printf(ctx, OSSL_CMP_FL_ALERT, msg)
#define OSSL_CMP_err(ctx, msg)   OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR  , msg)
#define OSSL_CMP_warn(ctx, msg)  OSSL_CMP_printf(ctx, OSSL_CMP_FL_WARN , msg)
#define OSSL_CMP_info(ctx, msg)  OSSL_CMP_printf(ctx, OSSL_CMP_FL_INFO , msg)
#define OSSL_CMP_debug(ctx, msg) OSSL_CMP_printf(ctx, OSSL_CMP_FL_DEBUG, msg)
int  OSSL_CMP_log_init(void);
void OSSL_CMP_log_close(void);
void OSSL_CMP_print_errors(OSSL_CMP_CTX *ctx);

#  define OPENSSL_NO_OCSP /* TODO remove when chunk 8 is contributed */
/*
 * context DECLARATIONS
 */

typedef int (*OSSL_cmp_log_cb_t) (const char *component,
                                  const char *file, int lineno,
                                  OSSL_CMP_severity level, const char *msg);
typedef int (*OSSL_cmp_certConf_cb_t) (OSSL_CMP_CTX *ctx, const X509 *cert,
                                       int fail_info, const char **txt);
typedef BIO *(*OSSL_cmp_http_cb_t) (OSSL_CMP_CTX *ctx, BIO *hbio,
                                    unsigned long detail);
typedef int (*OSSL_cmp_transfer_cb_t) (OSSL_CMP_CTX *ctx,
                                       const OSSL_CMP_MSG *req,
                                       OSSL_CMP_MSG **res);

/*
 * function DECLARATIONS
 */
/* from cmp_asn.c */
void OSSL_CMP_ITAV_set0(OSSL_CMP_ITAV *itav, ASN1_OBJECT *type,
                        ASN1_TYPE *value);
ASN1_OBJECT *OSSL_CMP_ITAV_get0_type(const OSSL_CMP_ITAV *itav);
ASN1_TYPE *OSSL_CMP_ITAV_get0_value(const OSSL_CMP_ITAV *itav);
int OSSL_CMP_ITAV_stack_item_push0(STACK_OF(OSSL_CMP_ITAV) **itav_sk_p,
                                   OSSL_CMP_ITAV *itav);
void OSSL_CMP_ITAV_free(OSSL_CMP_ITAV *itav);
void OSSL_CMP_MSG_free(OSSL_CMP_MSG *msg);
void OSSL_CMP_PKISI_free(OSSL_CMP_PKISI *si);
DECLARE_ASN1_DUP_FUNCTION(OSSL_CMP_MSG)

/* from cmp_ctx.c */
int OSSL_CMP_sk_X509_add1_cert (STACK_OF(X509) *sk, X509 *cert,
                                int not_duplicate, int prepend);
int OSSL_CMP_sk_X509_add1_certs(STACK_OF(X509) *sk, const STACK_OF(X509) *certs,
                                int no_self_signed, int no_duplicates);
int OSSL_CMP_X509_STORE_add1_certs(X509_STORE *store, STACK_OF(X509) *certs,
                                   int only_self_signed);
int OSSL_CMP_ASN1_OCTET_STRING_set1(ASN1_OCTET_STRING **tgt,
                                    const ASN1_OCTET_STRING *src);
int OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(ASN1_OCTET_STRING **tgt,
                                          const unsigned char *bytes,
                                         size_t len);

OSSL_CMP_CTX *OSSL_CMP_CTX_create(void);
int OSSL_CMP_CTX_init(OSSL_CMP_CTX *ctx);
X509_STORE *OSSL_CMP_CTX_get0_trustedStore(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set0_trustedStore(OSSL_CMP_CTX *ctx, X509_STORE *store);
/*
 * There must not be a space between 'STACK_OF' and '(X509)', otherwise mkdef.pl
 * does not recognize it correctly which leads to the file not being global in
 * the shared object when building with GNU.
 */
STACK_OF(X509) *OSSL_CMP_CTX_get0_untrusted_certs(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set1_untrusted_certs(OSSL_CMP_CTX *ctx,
                                      const STACK_OF(X509) *certs);
void OSSL_CMP_CTX_delete(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set_log_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_log_cb_t cb);
int OSSL_CMP_CTX_set_certConf_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_certConf_cb_t cb);
int OSSL_CMP_CTX_set_certConf_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
void *OSSL_CMP_CTX_get_certConf_cb_arg(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set1_referenceValue(OSSL_CMP_CTX *ctx,
                                     const unsigned char *ref,
                                     size_t len);
int OSSL_CMP_CTX_set1_secretValue(OSSL_CMP_CTX *ctx, const unsigned char *sec,
                                  const size_t len);
int OSSL_CMP_CTX_set1_srvCert(OSSL_CMP_CTX *ctx, const X509 *cert);
int OSSL_CMP_CTX_set1_clCert(OSSL_CMP_CTX *ctx, const X509 *cert);
int OSSL_CMP_CTX_set1_oldClCert(OSSL_CMP_CTX *ctx, const X509 *cert);
int OSSL_CMP_CTX_set1_p10CSR(OSSL_CMP_CTX *ctx, const X509_REQ *csr);
int OSSL_CMP_CTX_set1_issuer(OSSL_CMP_CTX *ctx, const X509_NAME *name);
int OSSL_CMP_CTX_set1_subjectName(OSSL_CMP_CTX *ctx, const X509_NAME *name);
int OSSL_CMP_CTX_set1_recipient(OSSL_CMP_CTX *ctx, const X509_NAME *name);
int OSSL_CMP_CTX_subjectAltName_push1(OSSL_CMP_CTX *ctx, const GENERAL_NAME *name);
STACK_OF(X509) *OSSL_CMP_CTX_caPubs_get1(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set1_caPubs(OSSL_CMP_CTX *ctx, STACK_OF(X509) *caPubs);
int OSSL_CMP_CTX_policyOID_push1(OSSL_CMP_CTX *ctx, const char *policyOID);
int OSSL_CMP_CTX_geninfo_itav_push0(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav);
int OSSL_CMP_CTX_genm_itav_push0(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav);

int OSSL_CMP_CTX_set1_extraCertsOut(OSSL_CMP_CTX *ctx,
                                    STACK_OF(X509) *extraCertsOut);
int OSSL_CMP_CTX_extraCertsOut_push1(OSSL_CMP_CTX *ctx, const X509 *val);
STACK_OF(X509) *OSSL_CMP_CTX_extraCertsIn_get1(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set1_extraCertsIn(OSSL_CMP_CTX *ctx,
                                   STACK_OF(X509) *extraCertsIn);

int OSSL_CMP_CTX_set1_newClCert(OSSL_CMP_CTX *ctx, const X509 *cert);
X509 *OSSL_CMP_CTX_get0_newClCert(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set0_pkey(OSSL_CMP_CTX *ctx, const EVP_PKEY *pkey);
int OSSL_CMP_CTX_set1_pkey(OSSL_CMP_CTX *ctx, const EVP_PKEY *pkey);
int OSSL_CMP_CTX_set0_newPkey(OSSL_CMP_CTX *ctx, const EVP_PKEY *pkey);
int OSSL_CMP_CTX_set1_newPkey(OSSL_CMP_CTX *ctx, const EVP_PKEY *pkey);
EVP_PKEY *OSSL_CMP_CTX_get0_newPkey(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set1_transactionID(OSSL_CMP_CTX *ctx,
                                    const ASN1_OCTET_STRING *id);
int OSSL_CMP_CTX_set1_recipNonce(OSSL_CMP_CTX *ctx,
                                 const ASN1_OCTET_STRING *nonce);
int OSSL_CMP_CTX_set1_last_senderNonce(OSSL_CMP_CTX *ctx,
                                       const ASN1_OCTET_STRING *nonce);
int OSSL_CMP_CTX_set1_serverName(OSSL_CMP_CTX *ctx, const char *name);
int OSSL_CMP_CTX_set_serverPort(OSSL_CMP_CTX *ctx, int port);
int OSSL_CMP_CTX_set1_proxyName(OSSL_CMP_CTX *ctx, const char *name);
int OSSL_CMP_CTX_set_proxyPort(OSSL_CMP_CTX *ctx, int port);
int OSSL_CMP_CTX_set_http_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_http_cb_t cb);
int OSSL_CMP_CTX_set_http_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
void *OSSL_CMP_CTX_get_http_cb_arg(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set_transfer_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_transfer_cb_t cb);
int OSSL_CMP_CTX_set_transfer_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
void *OSSL_CMP_CTX_get_transfer_cb_arg(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set0_reqExtensions(OSSL_CMP_CTX *ctx, X509_EXTENSIONS *exts);
int OSSL_CMP_CTX_set1_reqExtensions(OSSL_CMP_CTX *ctx, X509_EXTENSIONS *exts);
int OSSL_CMP_CTX_reqExtensions_have_SAN(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set1_serverPath(OSSL_CMP_CTX *ctx, const char *path);
int OSSL_CMP_CTX_set_failInfoCode(OSSL_CMP_CTX *ctx,
                                  OSSL_CMP_PKIFAILUREINFO *fail_info);
int OSSL_CMP_CTX_failInfoCode_get(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_status_get(OSSL_CMP_CTX *ctx);
OSSL_CMP_PKIFREETEXT *OSSL_CMP_CTX_statusString_get(OSSL_CMP_CTX *ctx);
ASN1_OCTET_STRING *OSSL_CMP_CTX_get0_transactionID(const OSSL_CMP_CTX *ctx);
ASN1_OCTET_STRING *OSSL_CMP_CTX_get0_last_senderNonce(const OSSL_CMP_CTX *ctx);
ASN1_OCTET_STRING *OSSL_CMP_CTX_get0_recipNonce(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set1_expected_sender(OSSL_CMP_CTX *ctx, const X509_NAME *name);
#  define OSSL_CMP_CTX_OPT_MSGTIMEOUT 0
#  define OSSL_CMP_CTX_OPT_TOTALTIMEOUT 1
#  define OSSL_CMP_CTX_OPT_SUBJECTALTNAME_CRITICAL 2
#  define OSSL_CMP_CTX_PERMIT_TA_IN_EXTRACERTS_FOR_IR 3
#  define OSSL_CMP_CTX_OPT_POPOMETHOD 4
#  define OSSL_CMP_CTX_OPT_DIGEST_ALGNID 5
#  define OSSL_CMP_CTX_OPT_REVOCATION_REASON 6
#  define OSSL_CMP_CTX_OPT_IMPLICITCONFIRM 7
#  define OSSL_CMP_CTX_OPT_DISABLECONFIRM 8
#  define OSSL_CMP_CTX_OPT_UNPROTECTED_ERRORS 9
#  define OSSL_CMP_CTX_OPT_UNPROTECTED_SEND 10
#  define OSSL_CMP_CTX_OPT_VALIDITYDAYS 11
#  define OSSL_CMP_CTX_OPT_IGNORE_KEYUSAGE 12
#  define OSSL_CMP_CTX_OPT_SUBJECTALTNAME_NODEFAULT 13
#  define OSSL_CMP_CTX_OPT_POLICIES_CRITICAL 14
int OSSL_CMP_CTX_set_option(OSSL_CMP_CTX *ctx, int opt, int val);

#   ifdef  __cplusplus
}
#   endif
# endif /* !defined OPENSSL_NO_CMP */
#endif /* !defined OSSL_HEADER_CMP_H */
