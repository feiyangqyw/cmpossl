/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CRMFERR_H
# define HEADER_CRMFERR_H

# ifdef  __cplusplus
extern "C"
# endif
int ERR_load_CRMF_strings(void);

/*
 * CRMF function codes.
 */
# define CRMF_F_CRMF_POPOSIGKEY_NEW                       100
# define CRMF_F_OSSL_CRMF_CERTID_GEN                      101
# define CRMF_F_OSSL_CRMF_CERTTEMPLATE_FILL               102
# define CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT     103
# define CRMF_F_OSSL_CRMF_MSGS_VERIFY_POPO                104
# define CRMF_F_OSSL_CRMF_MSG_CREATE_POPO                 105
# define CRMF_F_OSSL_CRMF_MSG_GET0_TMPL                   116
# define CRMF_F_OSSL_CRMF_MSG_GET_CERTREQID               112
# define CRMF_F_OSSL_CRMF_MSG_PKIPUBLICATIONINFO_PUSH0_SINGLEPUBINFO 115
# define CRMF_F_OSSL_CRMF_MSG_PUSH0_EXTENSION             106
# define CRMF_F_OSSL_CRMF_MSG_PUSH0_REGCTRL               107
# define CRMF_F_OSSL_CRMF_MSG_PUSH0_REGINFO               108
# define CRMF_F_OSSL_CRMF_MSG_SET0_EXTENSIONS             109
# define CRMF_F_OSSL_CRMF_MSG_SET0_SINGLEPUBINFO          118
# define CRMF_F_OSSL_CRMF_MSG_SET_CERTREQID               110
# define CRMF_F_OSSL_CRMF_MSG_SET_PKIPUBLICATIONINFO_ACTION 119
# define CRMF_F_OSSL_CRMF_MSG_SET_VALIDITY                111
# define CRMF_F_OSSL_CRMF_PBMP_NEW                        114
# define CRMF_F_OSSL_CRMF_PBM_NEW                         113

/*
 * CRMF reason codes.
 */
# define CRMF_R_BAD_PBM_ITERATIONCOUNT                    100
# define CRMF_R_CRMFERROR                                 101
# define CRMF_R_ERROR                                     102
# define CRMF_R_ERROR_DECODING_CERTIFICATE                103
# define CRMF_R_ERROR_DECRYPTING_CERTIFICATE              104
# define CRMF_R_ERROR_DECRYPTING_ENCCERT                  105
# define CRMF_R_ERROR_DECRYPTING_KEY                      106
# define CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY            107
# define CRMF_R_FAILURE_OBTAINING_RANDOM                  108
# define CRMF_R_ITERATIONCOUNT_BELOW_100                  109
# define CRMF_R_NULL_ARGUMENT                             111
# define CRMF_R_SETTING_MAC_ALGOR_FAILURE                 112
# define CRMF_R_SETTING_OWF_ALGOR_FAILURE                 113
# define CRMF_R_UNSUPPORTED_ALGORITHM                     114
# define CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY         115
# define CRMF_R_UNSUPPORTED_CIPHER                        116
# define CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO      117
# define CRMF_R_UNSUPPORTED_POPO_METHOD                   118
# define CRMF_R_UNSUPPORTED_POPO_NOT_ACCEPTED             119

#endif
