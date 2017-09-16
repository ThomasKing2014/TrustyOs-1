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
#ifndef SPRD_ENGINE_MATHOD_H
#define SPRD_ENGINE_MATHOD_H

#ifdef __cplusplus
extern "c" {
#endif

#define LOG_TAG "openssl-engine"

#define TLOG_E(fmt, ...) \
    fprintf(stderr, "\033[31m%s : %s %d: \033[0m" fmt"\n", LOG_TAG,__FUNCTION__, __LINE__,  ## __VA_ARGS__)

#if DEBUG_OPENSSL_ENGINE
#define TLOG_p(fmt, ...) \
    fprintf(stderr,  fmt,  ## __VA_ARGS__)
#define TLOG_I(fmt, ...) \
    fprintf(stderr, "\033[31m%s : %s %d: \033[0m" fmt"\n", LOG_TAG,__FUNCTION__, __LINE__,  ## __VA_ARGS__)
#else
#define TLOG_I(fmt, ...)
#endif

#define SPRD_HW_VERIFY_SUCCESS 0
#define SPRD_CRYPTO_OK 0
#define SPRD_ENGINE_SUCCESS 1
#define SPRD_ENGINE_FALIED 0

typedef struct _rsa_algo{
    int hash_nid;
    int sprd_algo;
}rsa_algo_t;

ENGINE *SPRD_ENGINE_Init(void);

void SPRD_ENGINE_Free(ENGINE *engine);
#ifdef __cplusplus
}
#endif

#endif /*SPRD_ENGINE_MATHOD_H*/
