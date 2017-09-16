/*
 * The MIT License (MIT)
 * Copyright (c) 2008-2015 Travis Geiselbrecht
 * Copyright (c) 2016, Spreadtrum Communications.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/base.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include "ec_type.h"

#include <sprd_ecc_types.h>
#include <sprd_rsa.h>
#include <sprd_crypto.h>
#include "openssl-engine.h"

#include <sys/types.h>
#include <trusty_ipc.h>
#include <trusty_uuid.h>
#include <trusty_syscalls.h>
#include <trace.h>
#include "hw_crypto.h"

#define SPRD_ECC_RS_MAX_SIZE 1024

static int sprd_get_engine_errno(int reason)
{
    switch(reason)
    {
    case SPRD_ECC_FALTAL_ERROR:
    case SPRD_ECC_LEN_ID_ERROR:
    case SPRD_ECC_LENGTH_ERROR:
    case SPRD_ECC_HASH_LEN_ERROR:
    case SPRD_CRYPTO_INVALID_KEY:
    case SPRD_CRYPTO_INVALID_TYPE:
    case SPRD_CRYPTO_INVALID_CONTEXT:
    case SPRD_CRYPTO_INVALID_PADDING:
    case SPRD_CRYPTO_INVALID_AUTHENTICATION:
    case SPRD_CRYPTO_INVALID_ARG:
    case SPRD_CRYPTO_INVALID_PACKET:
    case SPRD_CRYPTO_LENGTH_ERR:
    case SPRD_CRYPTO_ERR_STATE:
    case SPRD_CRYPTO_ERR_RESULT:
        return ERR_R_INTERNAL_ERROR;
    case SPRD_CRYPTO_NULL:
    case SPRD_ECC_NULL_POINTER_ERROR:
        return ERR_R_PASSED_NULL_PARAMETER;
    case SPRD_ECC_OVERFLOW_ERROR:
    case SPRD_CRYPTO_OUTOFMEM:
    case SPRD_CRYPTO_SHORT_BUFFER:
        return ERR_R_OVERFLOW;
    case SPRD_CRYPTO_DATA_TOO_LARGE_FOR_MODULUS:
        return RSA_R_DATA_TOO_LARGE_FOR_MODULUS;
    case SPRD_CRYPTO_NOSUPPORT:
    case SPRD_ECC_CURVEID_ERROR:
    default :
        return ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED;
    }
}

static sprd_ecc_curveid_t sprd_get_ecc_curveid(int curve_name)
{
    switch (curve_name)
    {
        case NID_secp160k1:
            return SPRD_ECC_CurveID_secp160k1;
        case NID_secp160r1:
            return SPRD_ECC_CurveID_secp160r1;
        case NID_secp160r2:
            return SPRD_ECC_CurveID_secp160r2;
        case NID_secp192k1:
            return SPRD_ECC_CurveID_secp192k1;
        case NID_secp224k1:
            return SPRD_ECC_CurveID_secp224k1;
        case NID_secp224r1:
            return SPRD_ECC_CurveID_secp224r1;
        case NID_secp256k1:
            return SPRD_ECC_CurveID_secp256k1;
        case NID_X9_62_prime256v1:
            return SPRD_ECC_CurveID_secp256r1;
        case NID_secp384r1:
            return SPRD_ECC_CurveID_secp384r1;
        case NID_secp521r1:
            return SPRD_ECC_CurveID_secp521r1;
        default:
            TLOG_E("SPRD ECC does not support the curve\n");
            OPENSSL_PUT_ERROR(EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return SPRD_ECC_CurevID_Last;
    }
}

static int sprd_engine_ecc_sign(const uint8_t *digest, size_t digest_len,
            uint8_t *sig, unsigned int *sig_len,ec_key_st_t *eckey)
{
    if (eckey == NULL || sig == NULL || sig_len == NULL)
    {
        TLOG_E("sprd_engine_ecc_sign params is NULL!\n");
        OPENSSL_PUT_ERROR(EC, ERR_R_PASSED_NULL_PARAMETER);
        return SPRD_ENGINE_FALIED;
    }
    sprd_ecc_params_t ecc_params;
    int result = SPRD_CRYPTO_OK;
    CBB cbb;
    ECDSA_SIG *s;
    size_t rs_len;
    uint8_t rs[SPRD_ECC_RS_MAX_SIZE];
    size_t len = 0 ;
    s = ECDSA_SIG_new();
    ecc_params.prikey = (sprd_ecc_prikey_t*)malloc(sizeof(sprd_ecc_prikey_t));
    ecc_params.prikey->ecc_curve = sprd_get_ecc_curveid(eckey->group->curve_name);
    if(ecc_params.prikey->ecc_curve == SPRD_ECC_CurevID_Last){
        TLOG_E("SPRD ECC does not support the curve (0x%X)\n",ecc_params.prikey->ecc_curve);
        OPENSSL_PUT_ERROR(EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        result = SPRD_ENGINE_FALIED;
        goto err;
    }
    ecc_params.prikey_len = BN_bn2bin(eckey->priv_key,(uint8_t*)ecc_params.prikey);
    ecc_params.digest=digest;
    ecc_params.digest_len=digest_len;
    ecc_params.sig=rs;
    ecc_params.sig_len=SPRD_ECC_RS_MAX_SIZE;
    result = ioctl(IO_DEVICE_CRYPTO, SPRD_ENGINE_ECC_SIGN, &ecc_params);
    if (result != SPRD_CRYPTO_OK)
    {
        TLOG_E("sprd_engine_ecc_sign failed!result = 0x%X\n", result);
        OPENSSL_PUT_ERROR(EC, sprd_get_engine_errno(result));
        result = SPRD_ENGINE_FALIED;
        goto err;
    }
    result = SPRD_ENGINE_SUCCESS;
    rs_len = ecc_params.sig_len;

    s->r = BN_bin2bn(&rs[0],rs_len/2,NULL);
    s->s=BN_bin2bn(&rs[rs_len/2],rs_len/2,NULL);
    CBB_zero(&cbb);
    if (!CBB_init_fixed(&cbb, sig, ECDSA_size(eckey)) ||
            !ECDSA_SIG_marshal(&cbb, s) ||
            !CBB_finish(&cbb, NULL, &len))
    {
        CBB_cleanup(&cbb);
        *sig_len = 0;
        result = SPRD_ENGINE_FALIED;
    }
    *sig_len = (unsigned)len;
err:
    ECDSA_SIG_free(s);
    free(ecc_params.prikey);
    return result;
}

static int sprd_engine_ecc_verify(const uint8_t *digest, size_t digest_len,
            const uint8_t *sig, size_t sig_len,ec_key_st_t *eckey)
{
    if (eckey == NULL || digest == NULL || sig == NULL)
    {
        TLOG_E("sprd_engine_ecc_verify params is NULL!\n");
        OPENSSL_PUT_ERROR(EC, ERR_R_PASSED_NULL_PARAMETER);
        return SPRD_ENGINE_FALIED;
    }
    sprd_ecc_params_t ecc_params;
    int result = SPRD_CRYPTO_OK;
    ECDSA_SIG *s;
    size_t der_len;
    uint8_t *der = NULL;
    uint8_t rs[SPRD_ECC_RS_MAX_SIZE];
    size_t rs_len1,rs_len2;
    s = ECDSA_SIG_from_bytes(sig, sig_len);
    if (!ECDSA_SIG_to_bytes(&der, &der_len, s) ||
        der_len != sig_len || memcmp(sig, der, sig_len) != 0) {
        /* This should never happen. crypto/bytestring is strictly DER. */
        OPENSSL_PUT_ERROR(EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        result = SPRD_ENGINE_FALIED;
        goto err2;
    }
    ecc_params.pubkey = (sprd_ecc_pubkey_t*)malloc(sizeof(sprd_ecc_pubkey_t));
    ecc_params.pubkey->ecc_curve = sprd_get_ecc_curveid(eckey->group->curve_name);
    if(ecc_params.pubkey->ecc_curve == SPRD_ECC_CurevID_Last){
        TLOG_E("SPRD ECC does not support the curve (%d)\n",ecc_params.pubkey->ecc_curve);
        OPENSSL_PUT_ERROR(EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        result = SPRD_ENGINE_FALIED;
        goto err;
    }
    ecc_params.pubkey_len = BN_bn2bin(&eckey->pub_key->X,(uint8_t*)ecc_params.pubkey->pubkey_x);
    BN_bn2bin(&eckey->pub_key->Y,(uint8_t*)ecc_params.pubkey->pubkey_y);
    rs_len1 = BN_bn2bin(s->r,&rs[0]);
    rs_len2 = BN_bn2bin(s->s,&rs[rs_len1]);
    ecc_params.sig=rs;
    ecc_params.sig_len=rs_len1+rs_len2;
    ecc_params.digest=digest;
    ecc_params.digest_len = digest_len;
    result = ioctl(IO_DEVICE_CRYPTO, SPRD_ENGINE_ECC_VERIFY, &ecc_params);
    if (result != SPRD_CRYPTO_OK)
    {
        TLOG_E("sprd_engine_ecc_verify failed!result = 0x%X\n", result);
        OPENSSL_PUT_ERROR(EC, sprd_get_engine_errno(result));
        result = SPRD_ENGINE_FALIED;
        goto err;
    }
    result = SPRD_ENGINE_SUCCESS;
err:
    free(ecc_params.pubkey);
err2:
    ECDSA_SIG_free(s);
    return result;
}
static int sprd_engine_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    if (rsa == NULL || e == NULL)
    {
        TLOG_E("sprd_engine_rsa_keygen params error!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_PASSED_NULL_PARAMETER);
        return SPRD_ENGINE_FALIED;
    }
    sprd_rsa_params_t rsa_params;
    int result = SPRD_CRYPTO_OK;

    rsa_params.key_e_len=BN_num_bytes(e);
    rsa_params.key_len = bits/8;
    rsa_params.key_e = (uint8_t *)malloc(rsa_params.key_e_len);
    rsa_params.key_d = (uint8_t *)malloc(rsa_params.key_len);
    rsa_params.key_n = (uint8_t *)malloc(rsa_params.key_len);
    memset(rsa_params.key_d,0,rsa_params.key_len);
    memset(rsa_params.key_n,0,rsa_params.key_len);
    BN_bn2bin(e,(uint8_t*)rsa_params.key_e);
    result = ioctl(IO_DEVICE_CRYPTO, SPRD_ENGINE_RSA_GEN, &rsa_params);
    if (result != SPRD_CRYPTO_OK)
    {
        TLOG_E("sprd_rsa_key_gen error(%x)\n", result);
        OPENSSL_PUT_ERROR(RSA, sprd_get_engine_errno(result));
        result = SPRD_ENGINE_FALIED;
        goto err;
    }
    rsa->d = BN_bin2bn(rsa_params.key_d,rsa_params.key_len,NULL);
    rsa->n = BN_bin2bn(rsa_params.key_n,rsa_params.key_len,NULL);
    rsa->e = BN_bin2bn(rsa_params.key_e,rsa_params.key_e_len,NULL);
    result = SPRD_ENGINE_SUCCESS;
err:
    free(rsa_params.key_d);
    free(rsa_params.key_n);
    free(rsa_params.key_e);
    return result;
}

static int sprd_engine_rsa_sign_raw(RSA *rsa, size_t *out_len, uint8_t *out,
            size_t max_out, const uint8_t *in,size_t in_len, int padding)
{
    if (rsa == NULL || out_len == NULL || out == NULL)
    {
        TLOG_E("sprd_engine_rsa_sign_raw params is NULL!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_PASSED_NULL_PARAMETER);
        return SPRD_ENGINE_FALIED;
    }
    int result = SPRD_ENGINE_FALIED;
    sprd_rsa_params_t rsa_params;
    sprd_rsa_keypair_t *priv_key = NULL;
    sprd_rsa_padding_t sprd_padding;
    memset(&rsa_params,0,sizeof(sprd_rsa_params_t));
    priv_key = (sprd_rsa_keypair_t *)malloc(sizeof(sprd_rsa_keypair_t));
    if (priv_key == NULL)
    {
        TLOG_E("sprd_engine_rsa_sign_raw malloc failed!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
        return SPRD_ENGINE_FALIED;
    }
    priv_key->d_len = BN_num_bytes(rsa->d);
    priv_key->d = (uint8_t *)malloc(priv_key->d_len);
    BN_bn2bin(rsa->d,priv_key->d);
    priv_key->e_len =BN_num_bytes(rsa->e);
    priv_key->e = (uint8_t *)malloc(priv_key->e_len);
    BN_bn2bin(rsa->e,priv_key->e);
    priv_key->n_len =BN_num_bytes(rsa->n);
    priv_key->n = (uint8_t *)malloc(priv_key->n_len);
    BN_bn2bin(rsa->n,priv_key->n);
    switch(padding)
    {
        case RSA_NO_PADDING:
            sprd_padding.type = SPRD_RSA_NOPAD;
            break;
        case RSA_PKCS1_PADDING:
            sprd_padding.type = SPRD_RSASSA_PKCS1_V1_5;
            break;
        default:
            TLOG_E("sprd_engine_rsa_sign_raw padding not support !\n");
            OPENSSL_PUT_ERROR(RSA, RSA_R_UNKNOWN_PADDING_TYPE);
            result = SPRD_ENGINE_FALIED;
            goto err;
    }
    rsa_params.priv_key=priv_key;
    rsa_params.dig=in;
    rsa_params.dig_size=in_len;
    rsa_params.sig=out;
    rsa_params.sig_size=priv_key->n_len;
    rsa_params.padding=sprd_padding;
    result= ioctl(IO_DEVICE_CRYPTO, SPRD_ENGINE_RSA_SIGN_RAW, &rsa_params);
    if (result != SPRD_CRYPTO_OK)
    {
        TLOG_E("sprd_engine_rsa_sign_raw failed!result = 0x%X\n",result);
        OPENSSL_PUT_ERROR(RSA, sprd_get_engine_errno(result));
        result = SPRD_ENGINE_FALIED;
        *out_len = 0;
        goto err;
    }
    result = SPRD_ENGINE_SUCCESS;
err:
    free(priv_key->d);
    free(priv_key->e);
    free(priv_key->n);
    free(priv_key);
    *out_len = rsa_params.sig_size;
    return result;
}

static int sprd_engine_rsa_verify_raw(RSA *rsa, size_t *out_len, uint8_t *out,
            size_t max_out, const uint8_t *in,size_t in_len, int padding)
{
    if (rsa == NULL || out_len == NULL || out == NULL || in == NULL)
    {
        TLOG_E("sprd_engine_rsa_verify_raw params is NULL!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_PASSED_NULL_PARAMETER);
        return SPRD_ENGINE_FALIED;
    }
    sprd_rsa_params_t rsa_params;
    sprd_rsa_pubkey_t *pub_key = NULL;
    sprd_rsa_padding_t sprd_padding;
    int result = SPRD_CRYPTO_OK;
    memset(&rsa_params,0,sizeof(sprd_rsa_params_t));
    pub_key = (sprd_rsa_pubkey_t *)malloc(sizeof(sprd_rsa_pubkey_t));
    if (pub_key == NULL)
    {
        TLOG_E("sprd_engine_rsa_verify_raw malloc failed!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
        return SPRD_ENGINE_FALIED;
    }
    pub_key->e_len = BN_num_bytes(rsa->e);
    pub_key->e = (uint8_t *)malloc(pub_key->e_len);
    BN_bn2bin(rsa->e,pub_key->e);
    pub_key->n_len = BN_num_bytes(rsa->n);
    pub_key->n = (uint8_t *)malloc(pub_key->n_len);
    BN_bn2bin(rsa->n,pub_key->n);

    switch(padding)
    {
        case RSA_NO_PADDING:
            sprd_padding.type = SPRD_RSA_NOPAD;
            break;
        case RSA_PKCS1_PADDING:
            sprd_padding.type = SPRD_RSASSA_PKCS1_V1_5;
            break;
        default:
            TLOG_E("sprd_engine_rsa_verify_raw padding not support!\n");
            OPENSSL_PUT_ERROR(RSA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            result = SPRD_ENGINE_FALIED;
            goto err;
    }
    rsa_params.pub_key=pub_key;
    rsa_params.dig=out;
    rsa_params.sig=in;
    rsa_params.sig_size=in_len;
    rsa_params.padding = sprd_padding;
    result =ioctl(IO_DEVICE_CRYPTO, SPRD_ENGINE_RSA_VERIFY_RAW, &rsa_params);
    if (result != SPRD_CRYPTO_OK)
    {
        TLOG_E("sprd_engine_rsa_verify_raw failed!result = 0x%X\n",result);
        OPENSSL_PUT_ERROR(RSA, sprd_get_engine_errno(result));
        result = SPRD_ENGINE_FALIED;
        goto err;
    }
    result = (rsa_params.result==SPRD_HW_VERIFY_SUCCESS);
err:
    free(pub_key->e);
    free(pub_key->n);
    free(pub_key);
    *out_len = rsa_params.dig_size;
    return result;
}
static int sprd_engine_rsa_sign(int hash_nid, const uint8_t *m,unsigned int m_length,
            uint8_t *sigret,unsigned int *siglen, const RSA *rsa)
{
    if (rsa == NULL || m == NULL || sigret == NULL || siglen == NULL)
    {
        TLOG_E("sprd_engine_rsa_sign params is NULL!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_PASSED_NULL_PARAMETER);
        return SPRD_ENGINE_FALIED;
    }
    sprd_rsa_params_t rsa_params;
    sprd_rsa_keypair_t *priv_key = NULL;
    sprd_rsa_padding_t sprd_padding;
    int result = SPRD_CRYPTO_OK;
    priv_key = (sprd_rsa_keypair_t *)malloc(sizeof(sprd_rsa_keypair_t));
    if (priv_key == NULL)
    {
        TLOG_E("sprd_engine_rsa_sign malloc failed!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
        return SPRD_ENGINE_FALIED;
    }
    priv_key->d_len = BN_num_bytes(rsa->d);
    priv_key->d = (uint8_t *)malloc(priv_key->d_len);
    BN_bn2bin(rsa->d,priv_key->d);
    priv_key->e_len =BN_num_bytes(rsa->e);
    priv_key->e = (uint8_t *)malloc(priv_key->e_len);
    BN_bn2bin(rsa->e,priv_key->e);
    priv_key->n_len =BN_num_bytes(rsa->n);
    priv_key->n = (uint8_t *)malloc(priv_key->n_len);
    BN_bn2bin(rsa->n,priv_key->n);
    sprd_padding.type = SPRD_RSASSA_PKCS1_V1_5;
    rsa_params.priv_key=priv_key;
    rsa_params.dig=m;
    rsa_params.dig_size=m_length;
    rsa_params.sig=sigret;
    rsa_params.sig_size=priv_key->n_len;
    rsa_params.padding=sprd_padding;
    result= ioctl(IO_DEVICE_CRYPTO, SPRD_ENGINE_RSA_SIGN_RAW, &rsa_params);
    if (result != SPRD_CRYPTO_OK)
    {
        TLOG_E("sprd_engine_rsa_sign failed!result = 0x%X\n",result);
        OPENSSL_PUT_ERROR(RSA, sprd_get_engine_errno(result));
        result = SPRD_ENGINE_FALIED;
        *siglen = 0;
        goto err;
    }
    result = SPRD_ENGINE_SUCCESS;
    *siglen = rsa_params.sig_size;
err:
    free(priv_key->d);
    free(priv_key->e);
    free(priv_key->n);
    free(priv_key);

    return result;
}

static int sprd_engine_rsa_verify(int hash_nid, const uint8_t *m,unsigned int m_length,
            const uint8_t *sigbuf,unsigned int siglen, const RSA *rsa)
{
    if (rsa == NULL || m == NULL || sigbuf == NULL)
    {
        TLOG_E("sprd_engine_rsa_verify params is NULL!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_PASSED_NULL_PARAMETER);
        return SPRD_ENGINE_FALIED;
    }
    sprd_rsa_params_t rsa_params;
    sprd_rsa_pubkey_t *pub_key = NULL;
    sprd_rsa_padding_t sprd_padding;
    int result = SPRD_CRYPTO_OK;
    memset(&rsa_params,0,sizeof(sprd_rsa_params_t));
    pub_key = (sprd_rsa_pubkey_t *)malloc(sizeof(sprd_rsa_pubkey_t));
    if (pub_key == NULL)
    {
        TLOG_E("sprd_engine_rsa_verify malloc failed!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
        return SPRD_ENGINE_FALIED;
    }

    sprd_padding.type=SPRD_RSASSA_PKCS1_V1_5;

    pub_key->e_len = BN_num_bytes(rsa->e);
    pub_key->e = (uint8_t *)malloc(pub_key->e_len);
    BN_bn2bin(rsa->e,pub_key->e);
    pub_key->n_len = BN_num_bytes(rsa->n);
    pub_key->n = (uint8_t *)malloc(pub_key->n_len);
    BN_bn2bin(rsa->n,pub_key->n);

    rsa_params.pub_key = pub_key;
    rsa_params.dig = m;
    rsa_params.dig_size = m_length;
    rsa_params.sig = sigbuf;
    rsa_params.sig_size = siglen;
    rsa_params.padding = sprd_padding;
    result = ioctl(IO_DEVICE_CRYPTO, SPRD_ENGINE_RSA_VERIFY_RAW, &rsa_params);
    if (result != SPRD_CRYPTO_OK)
    {
        TLOG_E("sprd_engine_rsa_verify failed!result = 0x%X\n",result);
        OPENSSL_PUT_ERROR(RSA, sprd_get_engine_errno(result));
        result = SPRD_ENGINE_FALIED;
        goto err;
    }
    result = (rsa_params.result == SPRD_HW_VERIFY_SUCCESS);
err:
    free(pub_key->e);
    free(pub_key->n);
    free(pub_key);
    return result;
}

static int sprd_engine_rsa_encrypt(RSA *rsa, size_t *out_len, uint8_t *out,
            size_t max_out, const uint8_t *in,size_t in_len, int padding)
{
    if (rsa == NULL || out == NULL || in == NULL)
    {
        TLOG_E("sprd_engine_rsa_encrypt params is NULL!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_PASSED_NULL_PARAMETER);
        return SPRD_ENGINE_FALIED;
    }
    sprd_rsa_params_t rsa_params;
    sprd_rsa_pubkey_t *pub_key;
    sprd_rsa_padding_t sprd_padding;
    int result = SPRD_CRYPTO_OK;
    if (padding != RSA_NO_PADDING)
    {
        TLOG_E("sprd_engine_rsa_encrypt driver only support RSA_NO_PADDING!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return SPRD_ENGINE_FALIED;
    }

    pub_key = (sprd_rsa_pubkey_t *)malloc(sizeof(sprd_rsa_pubkey_t));
    if(pub_key==NULL)
    {
        TLOG_E("sprd_engine_rsa_encrypt malloc failed!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
        return SPRD_ENGINE_FALIED;
    }
    pub_key->e_len = BN_num_bytes(rsa->e);
    pub_key->e = (uint8_t *)malloc(pub_key->e_len);
    BN_bn2bin(rsa->e,pub_key->e);
    pub_key->n_len = BN_num_bytes(rsa->n);
    pub_key->n = (uint8_t *)malloc(pub_key->n_len);
    BN_bn2bin(rsa->n,pub_key->n);

    /* driver only support SPRD_RSA_NOPAD */
    sprd_padding.type=SPRD_RSA_NOPAD;
    rsa_params.pub_key = pub_key;
    rsa_params.dig = in;
    rsa_params.dig_size=in_len;
    rsa_params.sig=out;
    rsa_params.padding = sprd_padding;
    result = ioctl(IO_DEVICE_CRYPTO, SPRD_ENGINE_RSA_ENCRYPT, &rsa_params);
    if (result != SPRD_CRYPTO_OK)
    {
        TLOG_E("sprd_engine_rsa_encrypt failed!result = 0x%X\n",result);
        OPENSSL_PUT_ERROR(RSA, sprd_get_engine_errno(result));
        *out_len = 0;
        result = SPRD_ENGINE_FALIED;
        goto err;
    }
    *out_len = rsa_params.sig_size;
    result = SPRD_ENGINE_SUCCESS;
err:
    free(pub_key->e);
    free(pub_key->n);
    free(pub_key);
    return result;
}

static int sprd_engine_rsa_decrypt(RSA *rsa, size_t *out_len, uint8_t *out,
            size_t max_out, const uint8_t *in,size_t in_len, int padding)
{
    if (rsa == NULL || out_len == NULL || out == NULL || in == NULL)
    {
        TLOG_E("sprd_engine_rsa_decrypt params is NULL!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_PASSED_NULL_PARAMETER);
        return SPRD_ENGINE_FALIED;
    }
    sprd_rsa_params_t rsa_params;
    sprd_rsa_keypair_t *priv_key = NULL;
    sprd_rsa_padding_t sprd_padding;
    int result = SPRD_CRYPTO_OK;
    if (padding != RSA_NO_PADDING)
    {
        TLOG_E("sprd_engine_rsa_decrypt driver only support RSA_NO_PADDING!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return SPRD_ENGINE_FALIED;
    }
    priv_key = (sprd_rsa_keypair_t *)malloc(sizeof(sprd_rsa_keypair_t));
    if (priv_key == NULL)
    {
        TLOG_E("sprd_engine_rsa_decrypt malloc failed!\n");
        OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
        return SPRD_ENGINE_FALIED;
    }
    priv_key->d_len = BN_num_bytes(rsa->d);
    priv_key->d = (uint8_t *)malloc(priv_key->d_len);
    BN_bn2bin(rsa->d,priv_key->d);
    priv_key->e_len =BN_num_bytes(rsa->e);
    priv_key->e = (uint8_t *)malloc(priv_key->e_len);
    BN_bn2bin(rsa->e,priv_key->e);
    priv_key->n_len =BN_num_bytes(rsa->n);
    priv_key->n = (uint8_t *)malloc(priv_key->n_len);
    BN_bn2bin(rsa->n,priv_key->n);
    /* driver only support SPRD_RSA_NOPAD */
    sprd_padding.type=SPRD_RSA_NOPAD;
    rsa_params.priv_key = priv_key;
    rsa_params.dig=out;
    rsa_params.sig=in;
    rsa_params.sig_size=in_len;
    rsa_params.padding=sprd_padding;
    result = ioctl(IO_DEVICE_CRYPTO, SPRD_ENGINE_RSA_DECRYPT, &rsa_params);
    if (result != SPRD_CRYPTO_OK)
    {
        TLOG_E("sprd_engine_rsa_decrypt failed!result = 0x%X\n",result);
        OPENSSL_PUT_ERROR(RSA, sprd_get_engine_errno(result));
        result = SPRD_ENGINE_FALIED;
        *out_len = 0;
        goto err;
    }
    result = SPRD_ENGINE_SUCCESS;
    *out_len = rsa_params.dig_size;
err:
    free(priv_key->d);
    free(priv_key->e);
    free(priv_key->n);
    free(priv_key);
    return result;
}

static RSA_METHOD rsa_mathod;
static ECDSA_METHOD ecdsa_method;
ENGINE *SPRD_ENGINE_Init(void)
{
    ENGINE *engine = ENGINE_new();
    if (engine == NULL)
    {
        TLOG_E("engine_init failed .Create engine failed.");
        return NULL;
    }

    ecdsa_method.common.is_static = 1;
    ecdsa_method.common.references = 0;
    ecdsa_method.flags = ECDSA_FLAG_OPAQUE;
    ecdsa_method.init = NULL;
    ecdsa_method.sign = sprd_engine_ecc_sign;
    ecdsa_method.finish = NULL;
    ecdsa_method.group_order_size = NULL;
    ecdsa_method.verify =sprd_engine_ecc_verify;
    ENGINE_set_ECDSA_method(engine, &ecdsa_method, sizeof(ECDSA_METHOD));

    rsa_mathod.common.is_static = 1;
    rsa_mathod.common.references = 0;
    rsa_mathod.flags = RSA_FLAG_OPAQUE|RSA_FLAG_SIGN_VER;
    rsa_mathod.init = NULL;
    rsa_mathod.finish = NULL;
    rsa_mathod.size = NULL;
    /*Fanilly,we will call sprd_engine_rsa_sign_raw function replace sprd_engine_rsa_sign.*/
    rsa_mathod.sign = NULL;//sprd_engine_rsa_sign;
    rsa_mathod.verify = NULL;//sprd_engine_rsa_verify;
    rsa_mathod.encrypt = sprd_engine_rsa_encrypt;
    rsa_mathod.sign_raw = sprd_engine_rsa_sign_raw;
    rsa_mathod.decrypt = sprd_engine_rsa_decrypt;
    rsa_mathod.verify_raw = sprd_engine_rsa_verify_raw;
    rsa_mathod.private_transform = NULL;
    rsa_mathod.mod_exp = NULL;
    rsa_mathod.bn_mod_exp = NULL;
    rsa_mathod.keygen = NULL;//sprd_engine_rsa_keygen;
    rsa_mathod.multi_prime_keygen = NULL;
    rsa_mathod.supports_digest = NULL;
    ENGINE_set_RSA_method(engine, &rsa_mathod, sizeof(RSA_METHOD));
    return engine;
}

void SPRD_ENGINE_Free(ENGINE *engine)
{
    if(engine !=NULL)
    {
        ENGINE_free(engine);
        engine=NULL;
    }
}
