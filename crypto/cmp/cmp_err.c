/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/cmperr.h>

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA CMP_str_functs[] = {
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_CAPUBS_GET1, 0),
     "OSSL_CMP_CTX_caPubs_get1"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_CREATE, 0),
     "OSSL_CMP_CTX_create"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_EXTRACERTSIN_GET1, 0),
     "OSSL_CMP_CTX_extraCertsIn_get1"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_EXTRACERTSOUT_PUSH1, 0),
     "OSSL_CMP_CTX_extraCertsOut_push1"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_INIT, 0), "OSSL_CMP_CTX_init"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_PUSH_FREETEXT, 0),
     "OSSL_CMP_CTX_push_freeText"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET0_NEWPKEY, 0),
     "OSSL_CMP_CTX_set0_newPkey"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET0_PKEY, 0),
     "OSSL_CMP_CTX_set0_pkey"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET0_REQEXTENSIONS, 0),
     "OSSL_CMP_CTX_set0_reqExtensions"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_CAPUBS, 0),
     "OSSL_CMP_CTX_set1_caPubs"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_CLCERT, 0),
     "OSSL_CMP_CTX_set1_clCert"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_EXPECTED_SENDER, 0),
     "OSSL_CMP_CTX_set1_expected_sender"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSIN, 0),
     "OSSL_CMP_CTX_set1_extraCertsIn"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSOUT, 0),
     "OSSL_CMP_CTX_set1_extraCertsOut"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_ISSUER, 0),
     "OSSL_CMP_CTX_set1_issuer"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_LAST_SENDERNONCE, 0),
     "OSSL_CMP_CTX_set1_last_senderNonce"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_NEWCLCERT, 0),
     "OSSL_CMP_CTX_set1_newClCert"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_NEWPKEY, 0),
     "OSSL_CMP_CTX_set1_newPkey"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_OLDCLCERT, 0),
     "OSSL_CMP_CTX_set1_oldClCert"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_P10CSR, 0),
     "OSSL_CMP_CTX_set1_p10CSR"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_PKEY, 0),
     "OSSL_CMP_CTX_set1_pkey"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_PROXYNAME, 0),
     "OSSL_CMP_CTX_set1_proxyName"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_RECIPIENT, 0),
     "OSSL_CMP_CTX_set1_recipient"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_RECIPNONCE, 0),
     "OSSL_CMP_CTX_set1_recipNonce"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_REFERENCEVALUE, 0),
     "OSSL_CMP_CTX_set1_referenceValue"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_SECRETVALUE, 0),
     "OSSL_CMP_CTX_set1_secretValue"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_SERVERNAME, 0),
     "OSSL_CMP_CTX_set1_serverName"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_SERVERPATH, 0),
     "OSSL_CMP_CTX_set1_serverPath"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_SRVCERT, 0),
     "OSSL_CMP_CTX_set1_srvCert"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_SUBJECTNAME, 0),
     "OSSL_CMP_CTX_set1_subjectName"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET1_TRANSACTIONID, 0),
     "OSSL_CMP_CTX_set1_transactionID"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET_PROXYPORT, 0),
     "OSSL_CMP_CTX_set_proxyPort"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SET_SERVERPORT, 0),
     "OSSL_CMP_CTX_set_serverPort"},
    {ERR_PACK(ERR_LIB_CMP, CMP_F_OSSL_CMP_CTX_SUBJECTALTNAME_PUSH1, 0),
     "OSSL_CMP_CTX_subjectAltName_push1"},
    {0, NULL}
};

static const ERR_STRING_DATA CMP_str_reasons[] = {
    {ERR_PACK(ERR_LIB_CMP, 0, CMP_R_INVALID_ARGS), "invalid args"},
    {ERR_PACK(ERR_LIB_CMP, 0, CMP_R_INVALID_CONTEXT), "invalid context"},
    {ERR_PACK(ERR_LIB_CMP, 0, CMP_R_MULTIPLE_SAN_SOURCES),
    "multiple san sources"},
    {ERR_PACK(ERR_LIB_CMP, 0, CMP_R_NULL_ARGUMENT), "null argument"},
    {0, NULL}
};

#endif

int ERR_load_CMP_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_func_error_string(CMP_str_functs[0].error) == NULL) {
        ERR_load_strings_const(CMP_str_functs);
        ERR_load_strings_const(CMP_str_reasons);
    }
#endif
    return 1;
}
