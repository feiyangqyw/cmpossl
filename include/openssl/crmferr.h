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
# define CRMF_F_CRMF_PASSWORDBASEDMAC_NEW                 113
# define CRMF_F_CRMF_PBMP_NEW                             114
# define CRMF_F_OSSL_CRMF_CERTID_GEN                      118
# define CRMF_F_OSSL_CRMF_CERTREQMESSAGES_VERIFY_POPO     119
# define CRMF_F_OSSL_CRMF_CERTREQMSG_CREATE_POPO          100
# define CRMF_F_OSSL_CRMF_CERTREQMSG_PUSH0_EXTENSION      101
# define CRMF_F_OSSL_CRMF_CERTREQMSG_PUSH0_REGCTRL        102
# define CRMF_F_OSSL_CRMF_CERTREQMSG_PUSH0_REGINFO        103
# define CRMF_F_OSSL_CRMF_CERTREQMSG_SET0_EXTENSIONS      104
# define CRMF_F_OSSL_CRMF_CERTREQMSG_SET1_ISSUER          105
# define CRMF_F_OSSL_CRMF_CERTREQMSG_SET1_PUBLICKEY       106
# define CRMF_F_OSSL_CRMF_CERTREQMSG_SET1_REGCTRL_OLDCERTID_FROM_CERT 107
# define CRMF_F_OSSL_CRMF_CERTREQMSG_SET1_SUBJECT         108
# define CRMF_F_OSSL_CRMF_CERTREQMSG_SET_CERTREQID        109
# define CRMF_F_OSSL_CRMF_CERTREQMSG_SET_VALIDITY         110
# define CRMF_F_OSSL_CRMF_CERTREQMSG_SET_VERSION2         111
# define CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_ENCCERT_GET1     112
# define CRMF_F_OSSL_CRMF_PASSWORDBASEDMAC_NEW            116
# define CRMF_F_OSSL_CRMF_PBMP_NEW                        117
# define CRMF_F_POPOSIGKEY_NEW                            115

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
# define CRMF_R_MALLOC_FAILURE                            110
# define CRMF_R_NULL_ARGUMENT                             111
# define CRMF_R_SETTING_MAC_ALRGOR_FAILURE                112
# define CRMF_R_SETTING_OWF_ALRGOR_FAILURE                113
# define CRMF_R_UNSUPPORTED_ALGORITHM                     114
# define CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY         115
# define CRMF_R_UNSUPPORTED_CIPHER                        116
# define CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO      117
# define CRMF_R_UNSUPPORTED_POPO_METHOD                   118
# define CRMF_R_UNSUPPORTED_POPO_NOT_ACCEPTED             119

#endif
