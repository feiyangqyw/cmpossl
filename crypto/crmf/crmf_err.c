/* crypto/crmf/crmf_err.c */
/* ====================================================================
 * Copyright (c) 1999-2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/crmf.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func) ERR_PACK(ERR_LIB_CRMF,func,0)
#define ERR_REASON(reason) ERR_PACK(ERR_LIB_CRMF,0,reason)

static ERR_STRING_DATA CRMF_str_functs[]=
    {
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_CALC_AND_SET_POPO),    "CRMF_CERTREQMSG_calc_and_set_popo"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_PUSH0_CONTROL),    "CRMF_CERTREQMSG_push0_control"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_PUSH0_EXTENSION),    "CRMF_CERTREQMSG_push0_extension"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_PUSH0_REGINFO),    "CRMF_CERTREQMSG_push0_regInfo"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_AUTHENTICATOR),    "CRMF_CERTREQMSG_set1_control_authenticator"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_OLDCERTID),    "CRMF_CERTREQMSG_set1_control_oldCertId"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_PKIARCHIVEOPTIONS),    "CRMF_CERTREQMSG_SET1_CONTROL_PKIARCHIVEOPTIONS"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_PKIPUBLICATIONINFO),    "CRMF_CERTREQMSG_SET1_CONTROL_PKIPUBLICATIONINFO"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_PROTOCOLENCRKEY),    "CRMF_CERTREQMSG_SET1_CONTROL_PROTOCOLENCRKEY"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_REGTOKEN),    "CRMF_CERTREQMSG_set1_control_regToken"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET1_PUBLICKEY),    "CRMF_CERTREQMSG_set1_publicKey"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET1_REGINFO_CERTREQ),    "CRMF_CERTREQMSG_SET1_REGINFO_CERTREQ"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET1_REGINFO_REGTOKEN),    "CRMF_CERTREQMSG_set1_regInfo_regToken"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET1_REGINFO_UTF8PAIRS),    "CRMF_CERTREQMSG_SET1_REGINFO_UTF8PAIRS"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET1_SUBJECT),    "CRMF_CERTREQMSG_set1_subject"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET_CERTREQID),    "CRMF_CERTREQMSG_set_certReqId"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET_VALIDITY),    "CRMF_CERTREQMSG_set_validity"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQMSG_SET_VERSION2),    "CRMF_CERTREQMSG_set_version2"},
{ERR_FUNC(CRMF_F_CRMF_CERTREQ_NEW), "CRMF_certreq_new"},
{ERR_FUNC(CRMF_F_CRMF_PASSWORDBASEDMAC_NEW),    "CRMF_passwordBasedMac_new"},
{ERR_FUNC(CRMF_F_CRMF_POPOSIGNINGKEY_NEW),    "CRMF_poposigningkey_new"},
{ERR_FUNC(CRMF_F_CRMF_SET1_CONTROL_AUTHENTICATOR),    "CRMF_SET1_CONTROL_AUTHENTICATOR"},
{ERR_FUNC(CRMF_F_CRMF_SET1_CONTROL_OLDCERTID),    "CRMF_SET1_CONTROL_OLDCERTID"},
{ERR_FUNC(CRMF_F_CRMF_SET1_CONTROL_PKIARCHIVEOPTIONS),    "CRMF_SET1_CONTROL_PKIARCHIVEOPTIONS"},
{ERR_FUNC(CRMF_F_CRMF_SET1_CONTROL_PKIPUBLICATIONINFO),    "CRMF_SET1_CONTROL_PKIPUBLICATIONINFO"},
{ERR_FUNC(CRMF_F_CRMF_SET1_CONTROL_PROTOCOLENCRKEY),    "CRMF_SET1_CONTROL_PROTOCOLENCRKEY"},
{ERR_FUNC(CRMF_F_CRMF_SET1_REGINFO_CERTREQ),    "CRMF_SET1_REGINFO_CERTREQ"},
{ERR_FUNC(CRMF_F_CRMF_SET1_REGINFO_UTF8PAIRS),    "CRMF_SET1_REGINFO_UTF8PAIRS"},
{ERR_FUNC(CRMF_F_CRMF_SET1_REGTOKEN_CERTREQ),    "CRMF_SET1_REGTOKEN_CERTREQ"},
{ERR_FUNC(CRMF_F_CRMF_SET1_SUBJECT),    "CRMF_SET1_SUBJECT"},
{ERR_FUNC(CRMF_F_CRMF_SET_CERTREQID),    "CRMF_SET_CERTREQID"},
{ERR_FUNC(CRMF_F_CRMF_SET_VERSION2),    "CRMF_SET_VERSION2"},
{0,NULL}
    };

static ERR_STRING_DATA CRMF_str_reasons[]=
    {
{ERR_REASON(CRMF_R_CRMFERROR)            ,"crmferror"},
{ERR_REASON(CRMF_R_ERROR_CALCULATING_AND_SETTING_POPO),"error calculating and setting popo"},
{ERR_REASON(CRMF_R_ERROR_SETTING_CONTROL_AUTHENTICATOR_ATAV),"error setting control authenticator atav"},
{ERR_REASON(CRMF_R_ERROR_SETTING_CONTROL_OLDCERTID_ATAV),"error setting control oldcertid atav"},
{ERR_REASON(CRMF_R_ERROR_SETTING_CONTROL_PKIARCHIVEOPTIONS_ATAV),"error setting control pkiarchiveoptions atav"},
{ERR_REASON(CRMF_R_ERROR_SETTING_CONTROL_PKIPUBLICATIONINFO_ATAV),"error setting control pkipublicationinfo atav"},
{ERR_REASON(CRMF_R_ERROR_SETTING_CONTROL_PROTOCOLENCRKEY_ATAV),"error setting control protocolencrkey atav"},
{ERR_REASON(CRMF_R_ERROR_SETTING_POPSIGNINGKEY),"error setting popsigningkey"},
{ERR_REASON(CRMF_R_ERROR_SETTING_PUBLIC_KEY),"error setting public key"},
{ERR_REASON(CRMF_R_ERROR_SETTING_REGINFO_CERTREQ_ATAV),"error setting reginfo certreq atav"},
{ERR_REASON(CRMF_R_ERROR_SETTING_REGINFO_UTF8PAIRS_ATAV),"error setting reginfo utf8pairs atav"},
{ERR_REASON(CRMF_R_ERROR_SETTING_REGTOKEN_ATAV),"error setting regtoken atav"},
{ERR_REASON(CRMF_R_ERROR_SETTING_REGTOKEN_CERTREQ_ATAV),"error setting regtoken certreq atav"},
{ERR_REASON(CRMF_R_ERROR_SETTING_VERSION_2),"error setting version 2"},
{ERR_REASON(CRMF_R_ITERATIONCOUNT_BELOW_100),"PBM OWF iteration count is less than 100"},
{ERR_REASON(CRMF_R_MALLOC_FAILURE),"out of memory"},
{ERR_REASON(CRMF_R_SETTING_MAC_ALRGOR_FAILURE),"error setting PBM MAC"},
{ERR_REASON(CRMF_R_SETTING_OWF_ALRGOR_FAILURE),"error setting PBM OWF"},
{ERR_REASON(CRMF_R_UNSUPPORTED_ALGORITHM),"unsupported algorithm"},
{ERR_REASON(CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY),"unsupported alg for popsigningkey"},
{ERR_REASON(CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO),"unsupported method for creating popo"},
{ERR_REASON(CRMF_R_NULL_ARGUMENT), "null argument"},
{0,NULL}
    };

#endif

int ERR_load_CRMF_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(CRMF_str_functs[0].error) == NULL)
        {
        ERR_load_strings(0,CRMF_str_functs);
        ERR_load_strings(0,CRMF_str_reasons);
        }
#endif
    return 1;
}