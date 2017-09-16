/*
* Copyright (c) 2016, Spreadtrum Communications.
*
* The above copyright notice shall be
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
#ifndef EC_TYPE_H
#define EC_TYPE_H
typedef struct ec_point_st {
    const EC_METHOD *meth;

    BIGNUM X;
    BIGNUM Y;
    BIGNUM Z; /* Jacobian projective coordinates:
    * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
}ec_point_st_t /* EC_POINT */;

typedef struct ec_group_st {
    const EC_METHOD *meth;

    ec_point_st_t *generator;
    BIGNUM order;

    int curve_name; /* optional NID for named curve */

    const BN_MONT_CTX *mont_data; /* data for ECDSA inverse */

    /* The following members are handled by the method functions,
    * even if they appear generic */

    BIGNUM field; /* For curves over GF(p), this is the modulus. */

    BIGNUM a, b; /* Curve coefficients. */

    int a_is_minus3; /* enable optimized point arithmetics for special case */

    BN_MONT_CTX *mont; /* Montgomery structure. */

    BIGNUM one; /* The value one. */
}ec_group_st_t /* EC_GROUP */;

typedef struct ec_key_st {
    ec_group_st_t *group;

    ec_point_st_t *pub_key;
    BIGNUM *priv_key;

    unsigned int enc_flag;
    point_conversion_form_t conv_form;

    CRYPTO_refcount_t references;

    ECDSA_METHOD *ecdsa_meth;

    CRYPTO_EX_DATA ex_data;
}ec_key_st_t /* EC_KEY */;
#endif
