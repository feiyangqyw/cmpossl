/*
 * Copyright 2007-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CRMF implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

/* NAMING
 * The 0 versions use the supplied structure pointer directly in the parent and
 * it will be freed up when the parent is freed. In the above example crl would
 * be freed but rev would not.
 *
 * The 1 functions use a copy of the supplied structure pointer (or in some
 * cases increases its link count) in the parent and so both should be freed up.
 */

/*
 * This file contains the functions that handle the individual items inside
 * the CRMF structures
 */

#include <openssl/asn1t.h>

#include "crmf_int.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <openssl/crmf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/*
 * atyp = Attribute Type
 * valt = Value Type
 * ctrlinf = "regCtrl" or "regInfo"
 */
#define IMPLEMENT_CRMF_CTRL_FUNC(atyp, valt, ctrlinf)                     \
int OSSL_CRMF_MSG_set1_##ctrlinf##_##atyp(OSSL_CRMF_MSG *msg,             \
                                          const valt *in)                 \
{                                                                         \
    OSSL_CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;                         \
                                                                          \
    if (msg == NULL || in  == NULL)                                       \
        goto err;                                                         \
    if ((atav = OSSL_CRMF_ATTRIBUTETYPEANDVALUE_new()) == NULL)           \
        goto err;                                                         \
    if ((atav->type = OBJ_nid2obj(NID_id_##ctrlinf##_##atyp)) == NULL)    \
        goto err;                                                         \
    if ((atav->value.atyp = valt##_dup((valt *)in)) == NULL)              \
        goto err;                                                         \
    if (!OSSL_CRMF_MSG_push0_##ctrlinf(msg, atav))                        \
        goto err;                                                         \
    return 1;                                                             \
 err:                                                                     \
    OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(atav);                           \
    return 0;                                                             \
}


/*
 * Pushes the given control attribute into the controls stack of a CertRequest
 * (section 6)
 * returns 1 on success, 0 on error
 */
static int OSSL_CRMF_MSG_push0_regCtrl(OSSL_CRMF_MSG *crm,
                                       OSSL_CRMF_ATTRIBUTETYPEANDVALUE *ctrl)
{
    int new = 0;

    if (crm == NULL || crm->certReq == NULL || ctrl == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_PUSH0_REGCTRL, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if (crm->certReq->controls == NULL) {
        if ((crm->certReq->controls =
              sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_new_null()) == NULL)
            goto oom;
        new = 1;
    }
    if (!sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_push(crm->certReq->controls, ctrl))
        goto oom;

    return 1;
 oom:
    CRMFerr(CRMF_F_OSSL_CRMF_MSG_PUSH0_REGCTRL, ERR_R_MALLOC_FAILURE);

    if (new != 0) {
        sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(crm->certReq->controls);
        crm->certReq->controls = NULL;
    }
    return 0;
}

 /* id-regCtrl-regToken Control (section 6.1) */
IMPLEMENT_CRMF_CTRL_FUNC(regToken, ASN1_STRING, regCtrl)

 /* id-regCtrl-authenticator Control (section 6.2) */
#define ASN1_UTF8STRING_dup ASN1_STRING_dup
IMPLEMENT_CRMF_CTRL_FUNC(authenticator, ASN1_UTF8STRING, regCtrl)

int OSSL_CRMF_MSG_set0_SinglePubInfo(OSSL_CRMF_SINGLEPUBINFO *spi,
                                     int method, GENERAL_NAME *nm)
{
    if (spi == NULL
        || method < OSSL_CRMF_PUB_METHOD_DONTCARE
        || method > OSSL_CRMF_PUB_METHOD_LDAP) {
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_SET0_SINGLEPUBINFO,
                ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    if (!ASN1_INTEGER_set(spi->pubMethod, method))
        return 0;
    spi->pubLocation = nm;
    return 1;
}

int OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(
                                 OSSL_CRMF_PKIPUBLICATIONINFO *pi,
                                 OSSL_CRMF_SINGLEPUBINFO *spi)
{
    if (pi == NULL || spi == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_PKIPUBLICATIONINFO_PUSH0_SINGLEPUBINFO,
                CRMF_R_NULL_ARGUMENT);
        return 0;
    }
    if (pi->pubinfos == NULL)
        if ((pi->pubinfos = sk_OSSL_CRMF_SINGLEPUBINFO_new_null()) == NULL)
            goto oom;

    if (!(sk_OSSL_CRMF_SINGLEPUBINFO_push(pi->pubinfos, spi)))
        goto oom;
    return 1;

 oom:
    CRMFerr(CRMF_F_OSSL_CRMF_MSG_PKIPUBLICATIONINFO_PUSH0_SINGLEPUBINFO,
            ERR_R_MALLOC_FAILURE);
    return 0;
}

int OSSL_CRMF_MSG_set_PKIPublicationInfo_action(
                                 OSSL_CRMF_PKIPUBLICATIONINFO *pi, int action)
{
    if (pi == NULL
        || action < OSSL_CRMF_PUB_ACTION_DONTPUBLISH
        || action > OSSL_CRMF_PUB_ACTION_PLEASEPUBLISH) {
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_SET_PKIPUBLICATIONINFO_ACTION,
                ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    return ASN1_INTEGER_set(pi->action, action);
}

 /* id-regCtrl-pkiPublicationInfo Control (section 6.3) */
IMPLEMENT_CRMF_CTRL_FUNC(pkiPublicationInfo, OSSL_CRMF_PKIPUBLICATIONINFO,
                         regCtrl)

 /* id-regCtrl-oldCertID Control (section 6.5) from the given */
IMPLEMENT_CRMF_CTRL_FUNC(oldCertID, OSSL_CRMF_CERTID, regCtrl)

OSSL_CRMF_CERTID *OSSL_CRMF_CERTID_gen(const X509_NAME *issuer,
                                       const ASN1_INTEGER *serial)
{
    OSSL_CRMF_CERTID *cid = NULL;

    if (issuer == NULL || serial == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_CERTID_GEN, CRMF_R_NULL_ARGUMENT);
        return NULL;
    }

    if ((cid = OSSL_CRMF_CERTID_new()) == NULL)
        goto oom;

    if (!X509_NAME_set(&cid->issuer->d.directoryName, (X509_NAME *)issuer))
        goto oom;
    cid->issuer->type = GEN_DIRNAME;

    ASN1_INTEGER_free(cid->serialNumber);
    if ((cid->serialNumber = ASN1_INTEGER_dup(serial)) == NULL)
        goto oom;

    return cid;

 oom:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTID_GEN, ERR_R_MALLOC_FAILURE);
    OSSL_CRMF_CERTID_free(cid);
    return NULL;
}

 /* id-regCtrl-protocolEncrKey Control (section 6.6) */
 /*
  * For some reason X509_PUBKEY_dup() is not implemented in OpenSSL X509
  * TODO: check whether that should go elsewhere
  */
static IMPLEMENT_ASN1_DUP_FUNCTION(X509_PUBKEY)
IMPLEMENT_CRMF_CTRL_FUNC(protocolEncrKey, X509_PUBKEY, regCtrl)

/*
 * Pushes the attribute given in regInfo in to the CertReqMsg->regInfo stack.
 * (section 7)
 * returns 1 on success, 0 on error
 */
static int OSSL_CRMF_MSG_push0_regInfo(OSSL_CRMF_MSG *crm,
                                       OSSL_CRMF_ATTRIBUTETYPEANDVALUE *ri)
{
    int new = 0;

    if (crm == NULL || ri == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_PUSH0_REGINFO, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if (crm->regInfo == NULL) {
        if ((crm->regInfo =
             sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_new_null()) == NULL)
            goto oom;
        new = 1;
    }
    if (!sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_push(crm->regInfo, ri))
        goto oom;
    return 1;
 oom:
    CRMFerr(CRMF_F_OSSL_CRMF_MSG_PUSH0_REGINFO, ERR_R_MALLOC_FAILURE);

    if (new != 0) {
        sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(crm->regInfo);
        crm->regInfo = NULL;
    }
    return 0;
}

 /* id-regInfo-utf8Pairs to regInfo (section 7.1) */
IMPLEMENT_CRMF_CTRL_FUNC(utf8Pairs, ASN1_UTF8STRING, regInfo)

 /* id-regInfo-certReq to regInfo (section 7.2) */
IMPLEMENT_CRMF_CTRL_FUNC(certReq, OSSL_CRMF_CERTREQUEST, regInfo)


/* retrieves the certificate template of crm */
OSSL_CRMF_CERTTEMPLATE *OSSL_CRMF_MSG_get0_tmpl(const OSSL_CRMF_MSG *crm)
{
    if (crm == NULL || crm->certReq == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_GET0_TMPL, CRMF_R_NULL_ARGUMENT);
        return NULL;
    }
    return crm->certReq->certTemplate;
}


int OSSL_CRMF_MSG_set_validity(OSSL_CRMF_MSG *crm, time_t from, time_t to)
{
    OSSL_CRMF_OPTIONALVALIDITY *vld = NULL;
    ASN1_TIME *from_asn = NULL;
    ASN1_TIME *to_asn = NULL;
    OSSL_CRMF_CERTTEMPLATE *tmpl = OSSL_CRMF_MSG_get0_tmpl(crm);

    if (tmpl == NULL) { /* also crm == NULL implies this */
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_SET_VALIDITY, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if (from != 0 && ((from_asn = ASN1_TIME_set(NULL, from)) == NULL))
        goto oom;
    if (to != 0 && ((to_asn = ASN1_TIME_set(NULL, to)) == NULL))
        goto oom;
    if ((vld = OSSL_CRMF_OPTIONALVALIDITY_new()) == NULL)
        goto oom;

    vld->notBefore = from_asn;
    vld->notAfter = to_asn;

    tmpl->validity = vld;

    return 1;
 oom:
    CRMFerr(CRMF_F_OSSL_CRMF_MSG_SET_VALIDITY, ERR_R_MALLOC_FAILURE);
    ASN1_TIME_free(from_asn);
    ASN1_TIME_free(to_asn);
    return 0;
}


int OSSL_CRMF_MSG_set_certReqId(OSSL_CRMF_MSG *crm, int rid)
{
    if (crm == NULL || crm->certReq == NULL || crm->certReq->certReqId == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_SET_CERTREQID, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    return ASN1_INTEGER_set(crm->certReq->certReqId, rid);
}

/* get ASN.1 encoded integer, return -1 on error */
static int CRMF_ASN1_get_int(int func, const ASN1_INTEGER *a)
{
    int64_t res;

    if (!ASN1_INTEGER_get_int64(&res, a)) {
        CRMFerr(func, ASN1_R_INVALID_NUMBER);
        return -1;
    }
    if (res < INT_MIN) {
        CRMFerr(func, ASN1_R_TOO_SMALL);
        return -1;
    }
    if (res > INT_MAX) {
        CRMFerr(func, ASN1_R_TOO_LARGE);
        return -1;
    }
    return (int)res;
}

int OSSL_CRMF_MSG_get_certReqId(OSSL_CRMF_MSG *crm)
{
    if (crm == NULL
        || /* not really needed: */ crm->certReq == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_GET_CERTREQID, CRMF_R_NULL_ARGUMENT);
        return -1;
    }
    return CRMF_ASN1_get_int(CRMF_F_OSSL_CRMF_MSG_GET_CERTREQID,
                             crm->certReq->certReqId);
}


int OSSL_CRMF_MSG_set0_extensions(OSSL_CRMF_MSG *crm,
                                  X509_EXTENSIONS *exts)
{
    OSSL_CRMF_CERTTEMPLATE *tmpl = OSSL_CRMF_MSG_get0_tmpl(crm);

    if (tmpl == NULL) { /* also crm == NULL implies this */
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_SET0_EXTENSIONS, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if (sk_X509_EXTENSION_num(exts) <= 0) {
        sk_X509_EXTENSION_free(exts);
        exts = NULL; /* do not include empty extensions list */
    }

    tmpl->extensions = exts;
    return 1;
}


int OSSL_CRMF_MSG_push0_extension(OSSL_CRMF_MSG *crm,
                                  const X509_EXTENSION *ext)
{
    int new = 0;
    OSSL_CRMF_CERTTEMPLATE *tmpl = OSSL_CRMF_MSG_get0_tmpl(crm);

    if (tmpl == NULL || ext == NULL) { /* also crm == NULL implies this */
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_PUSH0_EXTENSION, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if (tmpl->extensions == NULL) {
        if ((tmpl->extensions = sk_X509_EXTENSION_new_null()) == NULL)
            goto oom;
        new = 1;
    }

    if (!sk_X509_EXTENSION_push(tmpl->extensions, (X509_EXTENSION *)ext))
        goto oom;
    return 1;
 oom:
    CRMFerr(CRMF_F_OSSL_CRMF_MSG_PUSH0_EXTENSION, ERR_R_MALLOC_FAILURE);

    if (new != 0) {
        sk_X509_EXTENSION_free(tmpl->extensions);
        tmpl->extensions = NULL;
    }
    return 0;
}

/* TODO: support cases 1+2 (besides case 3) defined in RFC 4211, section 4.1. */
static int CRMF_poposigningkey_init(OSSL_CRMF_POPOSIGNINGKEY *ps,
                                    OSSL_CRMF_CERTREQUEST *cr,
                                    const EVP_PKEY *pkey, int dgst)
{
    int len;
    size_t crlen, max_sig_size;
    unsigned int siglen;
    unsigned char *crder = NULL, *sig = NULL;
    int alg_nid = 0;
    int md_nid = 0;
    const EVP_MD *alg = NULL;
    EVP_MD_CTX *ctx = NULL;

    if (ps == NULL || cr == NULL || pkey == NULL) {
        CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_INIT, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    /* OpenSSL defaults all bit strings to be encoded as ASN.1 NamedBitList */
    ps->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    ps->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    len = i2d_OSSL_CRMF_CERTREQUEST(cr, &crder);
    if (len < 0 || crder == NULL)
        goto err;
    crlen = (size_t)len;

    max_sig_size = EVP_PKEY_size((EVP_PKEY *)pkey);
    sig = OPENSSL_malloc(max_sig_size);
    if (sig == NULL)
        goto err;

    if (!OBJ_find_sigid_by_algs(&alg_nid, dgst, EVP_PKEY_id(pkey))) {
        CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_INIT,
                CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY);
        goto err;
    }
    if (!(OBJ_find_sigid_algs(alg_nid, &md_nid, NULL)
          && (alg = EVP_get_digestbynid(md_nid)) != NULL)) {
        CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_INIT,
                CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY);
        goto err;
    }
    if (!X509_ALGOR_set0(ps->algorithmIdentifier, OBJ_nid2obj(alg_nid),
                         V_ASN1_NULL, NULL)
        || (ctx = EVP_MD_CTX_new()) == NULL
        || !(EVP_SignInit_ex(ctx, alg, NULL)))
        goto err;
    if (!(EVP_SignUpdate(ctx, crder, crlen)))
        goto err;
    if (!(EVP_SignFinal(ctx, sig, &siglen, (EVP_PKEY *)pkey)))
        goto err;

    if (!(ASN1_BIT_STRING_set(ps->signature, sig, siglen)))
        goto err;

    /* cleanup */
    OPENSSL_free(crder);
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(sig);
    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_INIT, CRMF_R_ERROR);
    OPENSSL_free(crder);
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(sig);
    return 0;
}


int OSSL_CRMF_MSG_create_popo(OSSL_CRMF_MSG *crm, const EVP_PKEY *pkey,
                              int dgst, int ppmtd)
{
    OSSL_CRMF_POPO *pp = NULL;

    if (crm == NULL
        || (ppmtd == OSSL_CRMF_POPO_SIGNATURE && pkey == NULL)) {
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_CREATE_POPO, CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    if ((pp = OSSL_CRMF_POPO_new()) == NULL)
        goto oom;
    pp->type = ppmtd;

    switch (ppmtd) {
    case OSSL_CRMF_POPO_NONE:
        OSSL_CRMF_POPO_free(pp);
        OSSL_CRMF_POPO_free(crm->popo);
        crm->popo = NULL;
        return 1;
    case OSSL_CRMF_POPO_RAVERIFIED:
        if ((pp->value.raVerified = ASN1_NULL_new()) == NULL)
            goto oom;
        break;

    case OSSL_CRMF_POPO_SIGNATURE:
        {
            OSSL_CRMF_POPOSIGNINGKEY *ps = OSSL_CRMF_POPOSIGNINGKEY_new();
            if (ps == NULL
                || !CRMF_poposigningkey_init(ps, crm->certReq, pkey, dgst)) {
                OSSL_CRMF_POPOSIGNINGKEY_free(ps);
                goto err;
            }
            pp->value.signature = ps;
        }
        break;

    case OSSL_CRMF_POPO_KEYENC:
        if ((pp->value.keyEncipherment = OSSL_CRMF_POPOPRIVKEY_new()) == NULL)
            goto oom;
        pp->value.keyEncipherment->type = OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE;
        if ((pp->value.keyEncipherment->value.subsequentMessage =
             ASN1_INTEGER_new()) == NULL
            ||
            !ASN1_INTEGER_set(pp->value.keyEncipherment->value.subsequentMessage,
                              OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT))
            goto oom;
        break;

    default:
        CRMFerr(CRMF_F_OSSL_CRMF_MSG_CREATE_POPO,
                CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO);
        goto err;
    }

    OSSL_CRMF_POPO_free(crm->popo);
    crm->popo = pp;

    return 1;
 oom:
    CRMFerr(CRMF_F_OSSL_CRMF_MSG_CREATE_POPO, ERR_R_MALLOC_FAILURE);
 err:
    OSSL_CRMF_POPO_free(pp);
    return 0;
}

/* returns 0 for equal, -1 for a < b, 1 for a > b, <= -2 on error */
static int X509_PUBKEY_cmp(X509_PUBKEY *a, X509_PUBKEY *b)
{
    X509_ALGOR *algA = NULL, *algB = NULL;
    int res = 0;

    if (a == b)
        return 0;
    if (a == NULL)
        return -1;
    if (b == NULL)
        return 1;
    if (!X509_PUBKEY_get0_param(NULL, NULL, NULL, &algA, a)
        ||
        !X509_PUBKEY_get0_param(NULL, NULL, NULL, &algB, b))
        return -2;
    if (algA == NULL || algB == NULL)
        return -3;
    if ((res = X509_ALGOR_cmp(algA, algB)) != 0)
        return res;
    return EVP_PKEY_cmp(X509_PUBKEY_get0(a), X509_PUBKEY_get0(b));
}

/* verifies the Proof-of-Possession of the request with the given rid in reqs */
int OSSL_CRMF_MSGS_verify_popo(const OSSL_CRMF_MSGS *reqs,
                               int rid, int acceptRAVerified)
{
    OSSL_CRMF_MSG *req = NULL;
    X509_PUBKEY *pubkey = NULL;
    OSSL_CRMF_POPOSIGNINGKEY *sig = NULL;

    if (reqs == NULL
        || (req = sk_OSSL_CRMF_MSG_value(reqs, rid)) == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_MSGS_VERIFY_POPO,
                CRMF_R_NULL_ARGUMENT);
        return 0;
    }

    switch (req->popo->type) {
    case OSSL_CRMF_POPO_RAVERIFIED:
        if (acceptRAVerified)
            return 1;
        break;
    case OSSL_CRMF_POPO_SIGNATURE:
        pubkey = req->certReq->certTemplate->publicKey;
        sig = req->popo->value.signature;
        if (sig->poposkInput != NULL) {
            /*-
             * According to RFC 4211: publicKey contains a copy of
             * the public key from the certificate template. This MUST be
             * exactly the same value as contained in the certificate template.
             */
            if (pubkey == NULL
                || sig->poposkInput->publicKey == NULL
                || X509_PUBKEY_cmp(pubkey, sig->poposkInput->publicKey)
                || ASN1_item_verify(ASN1_ITEM_rptr(OSSL_CRMF_POPOSIGNINGKEYINPUT),
                                    sig->algorithmIdentifier, sig->signature,
                                    sig->poposkInput,
                                    X509_PUBKEY_get0(pubkey)) < 1)
                break;
        } else {
            if (pubkey == NULL
                || req->certReq->certTemplate->subject == NULL
                || ASN1_item_verify(ASN1_ITEM_rptr(OSSL_CRMF_CERTREQUEST),
                                    sig->algorithmIdentifier, sig->signature,
                                    req->certReq,
                                    X509_PUBKEY_get0(pubkey)) < 1)
                break;
        }
        return 1;
    case OSSL_CRMF_POPO_KEYENC:
        if (req->popo->value.keyEncipherment->type
            != OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE)
            goto unsupported;
        if (ASN1_INTEGER_get
            (req->popo->value.keyEncipherment->value.subsequentMessage)
            != OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT)
            goto unsupported;
        /* TODO when implemented in CMP_certrep_new(): return 1 */
        goto unsupported;
    case OSSL_CRMF_POPO_KEYAGREE:
    default:
    unsupported:
        CRMFerr(CRMF_F_OSSL_CRMF_MSGS_VERIFY_POPO,
                CRMF_R_UNSUPPORTED_POPO_METHOD);
        return 0;
    }
    CRMFerr(CRMF_F_OSSL_CRMF_MSGS_VERIFY_POPO,
            CRMF_R_UNSUPPORTED_POPO_NOT_ACCEPTED);
    return 0;
}

/* retrieves the serialNumber of the given cert template or NULL on error */
ASN1_INTEGER *OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(OSSL_CRMF_CERTTEMPLATE *tmpl)
{
    return tmpl != NULL ? tmpl->serialNumber : NULL;
}

/* retrieves the issuer name of the given cert template or NULL on error */
X509_NAME *OSSL_CRMF_CERTTEMPLATE_get0_issuer(OSSL_CRMF_CERTTEMPLATE *tmpl)
{
    return tmpl != NULL ? tmpl->issuer : NULL;
}

/*-
 * fill in certificate template.
 * Any value argument that is NULL will leave the respective field unchanged.
 */
int OSSL_CRMF_CERTTEMPLATE_fill(OSSL_CRMF_CERTTEMPLATE *tmpl,
                                const EVP_PKEY *pubkey,
                                const X509_NAME *subject,
                                const X509_NAME *issuer,
                                const ASN1_INTEGER *serial)
{
    if (tmpl == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_CERTTEMPLATE_FILL, CRMF_R_NULL_ARGUMENT);
        return 0;
    }
    if (pubkey != NULL && !X509_PUBKEY_set(&tmpl->publicKey, (EVP_PKEY *)pubkey))
        goto oom;
    if (subject != NULL && !X509_NAME_set(&tmpl->subject, (X509_NAME *)subject))
        goto oom;
    if (issuer != NULL && !X509_NAME_set(&tmpl->issuer, (X509_NAME *)issuer))
        goto oom;
    if (serial != NULL) {
        ASN1_INTEGER_free(tmpl->serialNumber);
        if ((tmpl->serialNumber = ASN1_INTEGER_dup(serial)) == NULL)
            goto oom;
    }
    return 1;

 oom:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTTEMPLATE_FILL, ERR_R_MALLOC_FAILURE);
    return 0;
}


/*
 * Decrypts the certificate in the given encryptedValue
 * this is needed for the indirect PoP method as in RFC 4210 section 5.2.8.2
 *
 * returns a pointer to the decrypted certificate
 * returns NULL on error or if no certificate available
 */
X509 *OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(OSSL_CRMF_ENCRYPTEDVALUE *ecert,
                                            EVP_PKEY *pkey)
{
    X509 *cert = NULL; /* decrypted certificate */
    EVP_CIPHER_CTX *evp_ctx = NULL; /* context for symmetric encryption */
    unsigned char *ek = NULL; /* decrypted symmetric encryption key */
    const EVP_CIPHER *cipher = NULL; /* used cipher */
    unsigned char *iv = NULL; /* initial vector for symmetric encryption */
    unsigned char *outbuf = NULL; /* decryption output buffer */
    const unsigned char *p = NULL; /* needed for decoding ASN1 */
    int symmAlg = 0; /* NIDs for symmetric algorithm */
    int n, outlen = 0;
    EVP_PKEY_CTX *pkctx = NULL; /* private key context */

    if (ecert == NULL || ecert->symmAlg == NULL || ecert->encSymmKey == NULL
        || ecert->encValue == NULL || pkey == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_NULL_ARGUMENT);
        return NULL;
    }
    if ((symmAlg = OBJ_obj2nid(ecert->symmAlg->algorithm)) == 0) {
        CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_UNSUPPORTED_CIPHER);
        return NULL;
    }

    /* first the symmetric key needs to be decrypted */
    if ((pkctx = EVP_PKEY_CTX_new(pkey, NULL)) != NULL
        && EVP_PKEY_decrypt_init(pkctx)) {
        ASN1_BIT_STRING *encKey = ecert->encSymmKey;
        size_t eksize = 0;

        if (EVP_PKEY_decrypt(pkctx, NULL, &eksize, encKey->data, encKey->length)
                <= 0
            || (ek = OPENSSL_malloc(eksize)) == NULL
            || EVP_PKEY_decrypt(pkctx, ek, &eksize, encKey->data,
                                encKey->length) <= 0) {
            CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                    CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY);
            goto end;
        }
    } else {
        goto oom;
    }

    /* select symmetric cipher based on algorithm given in message */
    if ((cipher = EVP_get_cipherbynid(symmAlg)) == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_UNSUPPORTED_CIPHER);
        goto end;
    }
    if ((iv = OPENSSL_malloc(EVP_CIPHER_iv_length(cipher))) == NULL)
        goto oom;
    if (ASN1_TYPE_get_octetstring(ecert->symmAlg->parameter, iv,
                                   EVP_CIPHER_iv_length(cipher))
        != EVP_CIPHER_iv_length(cipher)) {
        CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_MALFORMED_IV);
        goto end;
    }

    /*
     * d2i_X509 changes the given pointer, so use p for decoding the message and
     * keep the original pointer in outbuf so the memory can be freed later
     */
    if ((p = outbuf = OPENSSL_malloc(ecert->encValue->length +
                                     EVP_CIPHER_block_size(cipher))) == NULL
        || (evp_ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto oom;
    EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

    if (!EVP_DecryptInit(evp_ctx, cipher, ek, iv)
        || !EVP_DecryptUpdate(evp_ctx, outbuf, &outlen,
                              ecert->encValue->data,
                              ecert->encValue->length)
        || !EVP_DecryptFinal(evp_ctx, outbuf + outlen, &n)) {
        CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_ERROR_DECRYPTING_CERTIFICATE);
        goto end;
    }
    outlen += n;

    /* convert decrypted certificate from DER to internal ASN.1 structure */
    if ((cert = d2i_X509(NULL, &p, outlen)) == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT,
                CRMF_R_ERROR_DECODING_CERTIFICATE);
    }
    goto end;

 oom:
    CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_GET1_ENCCERT, ERR_R_MALLOC_FAILURE);
 end:
    EVP_PKEY_CTX_free(pkctx);
    OPENSSL_free(outbuf);
    EVP_CIPHER_CTX_free(evp_ctx);
    OPENSSL_free(ek);
    OPENSSL_free(iv);
    return cert;
}
