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
extern "C" {
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
}
#include <new>
#include <cstddef>
#include <keymaster/logger.h>
#include "keybox_tools.h"

namespace keymaster {
static cert_elems_t cert_elems[]={
    {ELEMS_XML_VERSION, "xmlversion","", nullptr},
    {ELEMS_KEYBOXS_NUM, "<NumberOfKeyboxes>","</NumberOfKeyboxes>", nullptr},
    {ELEMS_DEVICE_ID, "KeyboxDeviceID","", nullptr},
    {ELEMS_KEY_ALGO, "Keyalgorithm","</Key>", nullptr},
    {ELEMS_KEY_FORMAT, "PrivateKeyformat","</PrivateKey>", nullptr},
    {ELEMS_PRIV_KEY, "PRIVATEKEY","END", nullptr},
    {ELEMS_CERT_NUM, "<NumberOfCertificates>", "</NumberOfCertificates>",nullptr},
    {ELEMS_CERT_FORMAT, "<Certificate","</Certificate>", nullptr},
    {ELEMS_ATTEST_CERT, "BEGINCERTIFICATE","ENDCERTIFICATE", nullptr},
    {ELEMS_MAX_ITERM,"Unknown","",nullptr},
};

// Name of the attestation key file is kAttestKeyPrefix.%algorithm, where
// algorithm is either "ec" or "rsa".
const char* kAttestKeyPrefix = "";

// Name of the attestation certificate file is kAttestCertPrefix.%algorithm.%index,
// where index is the index within the certificate chain.
const char* kAttestCertPrefix = "";

// Maximum file name size.
static const int kStorageIdLengthMax = 64;

#if 0 // Just for debug
void dumpString(char *start, char *end) {
  printf("start=%p end=%p length = %d\n",start,end, (int)(end-start));
  while (start < end) {
    printf("%c", *start++);
  }
  printf("\n");
}
#endif

static bool SecureStorageWrite(const char* filename, const uint8_t* data, uint32_t size) {
    FileHandle file(filename);
    if (file.error() < 0) {
        return false;
    }
    int rc = storage_write(file.handle(), 0, data, size, STORAGE_OP_COMPLETE);
    if (rc < 0) {
        LOG_E("Error: [%d] writing storage object '%s'", rc, filename);
        return false;
    }
    if (static_cast<uint32_t>(rc) < size) {
        LOG_E("Error: invalid object size [%d] from '%s'", rc, filename);
        return false;
    }
    return true;
}

static bool SecureStorageRead(const char* filename, uint8_t* data, uint32_t *size) {
    FileHandle file(filename);
    storage_off_t length;
    if(size !=NULL)*size = 0;
    if (file.error() < 0) {
        return false;
    }
    int rc = storage_get_file_size(file.handle(), &length);
    if ( 0 > rc) {
        LOG_E("storage_get_file_size(%s) failed! return %d\n", rc);
        return false;
    }
    uint32_t len = static_cast<uint32_t>(length);
    rc = storage_read(file.handle(), 0, data, len);
    if (rc < 0) {
        LOG_E("Error: [%d] reading storage object '%s'", rc, filename);
        return false;
    }
    if (static_cast<uint32_t>(rc) < len) {
        LOG_E("Error: invalid object size [%d] from '%s'", rc, filename);
        return false;
    }
    if(size !=NULL)*size = len;
    return true;
}


keymaster_error_t WriteItemToStorage(const char* item_name, const uint8_t* data) {
    UniquePtr<char[]> item_file(new char[kStorageIdLengthMax]);

    snprintf(item_file.get(), kStorageIdLengthMax, "%s.%s", kAttestKeyPrefix, item_name);
    if (!SecureStorageWrite(item_file.get(), data, strlen((const char*)data))) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}
keymaster_error_t ReadItemFromStorage(const char* item_name, const uint8_t** data,
                                    uint32_t *data_size) {
    UniquePtr<char[]> item_file(new char[kStorageIdLengthMax]);

    snprintf(item_file.get(), kStorageIdLengthMax, "%s.%s", kAttestKeyPrefix, item_name);
    if (!SecureStorageRead(item_file.get(), (uint8_t*)*data, data_size)) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

KeyboxTools::KeyboxTools(uint8_t *data,storage_off_t length){
    xml_buf_ = (uint8_t*)malloc(length);
    SkipSp(data,xml_buf_);
    xml_size_= strlen((const char*)xml_buf_);
    check_addr_= xml_buf_;
}
KeyboxTools::KeyboxTools(void):AttestBuf(new uint8_t[KEYBOX_ITEM_MAX_SIZE]){
    xml_buf_=NULL;
}

KeyboxTools::~KeyboxTools(){
    if(xml_buf_!=NULL)
        free(xml_buf_);
}

size_t KeyboxTools::ReadAttestKey(keymaster_algorithm_t algorithm,const uint8_t** key){
    size_t keylen=0;
    char path[32]={0};
    keymaster_error_t rt = KM_ERROR_OK;
    if (algorithm==KM_ALGORITHM_RSA)
        sprintf(path,"%s","rsaPrikey");
    else if (algorithm==KM_ALGORITHM_EC)
        sprintf(path,"%s","ecdsaPrikey");
    else
        return 0;

    rt = ReadItemFromStorage(path,key, &keylen);
    if(rt!=KM_ERROR_OK){
        LOG_E("Error: [%d] read storage session\n", rt);
        return 0;
    }
    return keylen;
}
size_t KeyboxTools::ReadAttestCert(keymaster_algorithm_t algorithm,int index,const uint8_t** cert){
    size_t certlen=0;
    char path[32]={0};
    keymaster_error_t rt = KM_ERROR_OK;

    if (algorithm==KM_ALGORITHM_RSA)
        sprintf(path,"rsaCert%d",index);
    else if (algorithm==KM_ALGORITHM_EC)
        sprintf(path,"ecdsaCert%d",index);
    else
        return 0;

    rt = ReadItemFromStorage(path,cert, &certlen);
    if(rt!=KM_ERROR_OK){
        LOG_E("Error: [%d] read storage session\n", rt);
        return 0;
    }
    return certlen;
}

uint8_t KeyboxTools::ReadCertChainLength(keymaster_algorithm_t algorithm){
    keymaster_error_t rt = KM_ERROR_OK;
    uint8_t chain_num[8] = {0} ;
    char path[32]={0};
    if (algorithm==KM_ALGORITHM_RSA)
        sprintf(path,"%s","rsaCertLen");
    else if (algorithm==KM_ALGORITHM_EC)
        sprintf(path,"%s","ecdsaCertLen");
    else
        return 0;
    rt = ReadItemFromStorage(path,(const uint8_t**)&chain_num, NULL);
    if(rt!=KM_ERROR_OK){
        LOG_E("Error: [%d] read storage session\n", rt);
        return 0;
    }
    return (uint8_t)atoi((const char*)chain_num);
}
void KeyboxTools::SkipSp(uint8_t* in,uint8_t*out) {
    while (*in++){
    if(*in != 32)
           *out++=*in;
    }
}

void KeyboxTools::GetNewLine(void){
    elem = elem_end;
    if(elem_end - xml_buf_ >= (int)xml_size_)return;
    while (*elem_end != '>')
        elem_end++;
    elem_end++;
}

uint8_t *KeyboxTools::StrXmlStart(const uint8_t *s1,const uint8_t *start,const uint8_t *end)
{
    int l1, l2;

    l1 = strlen((const char*)s1);
    if (!l1)
        return (uint8_t *)start;
    l2 = end - start;
    while (l2 >= l1) {
        l2--;
        if (!memcmp(start,s1,l1)){
            start += l1;
            return (uint8_t *)start;
        }
        start++;
    }
    start += l1-1;
    return NULL;
}

uint8_t *KeyboxTools::StrXmlEnd(const uint8_t *s1,const uint8_t *start,const uint8_t *end)
{
    int l1, l2;

    l1 = strlen((const char*)s1);
    if (!l1)
        return (uint8_t *)start;
    l2 = end - start;
    while (l2 >= l1) {
        l2--;
        if (!memcmp(start,s1,l1))
            return (uint8_t *)start;
        start++;
    }
    return NULL;
}
void KeyboxTools::GetXmlElems(uint8_t type){
    uint8_t* start = NULL ;
    uint8_t* end = NULL ;
    elem=check_addr_;
    elem_end=check_addr_;
    do {
        GetNewLine();
        if(elem_end>=xml_buf_+xml_size_)break;
        start = StrXmlStart(cert_elems[type].tag_begin, elem, elem_end);
    } while (start == NULL);
    end = elem_end;
    if (strlen((const char*)cert_elems[type].tag_end) != 0 && start != NULL) {
        do {
            GetNewLine();
            if(elem_end>=xml_buf_+xml_size_)break;
            end = StrXmlEnd(cert_elems[type].tag_end, start, elem_end);
        } while (end == NULL);
    }
    if(start!=NULL && end!=NULL)
        HandleCertItems((xml_elems_e)type, start, end);
}
void KeyboxTools::GetElemsValue(const uint8_t* begin,
                                     const uint8_t* end,
                                     uint8_t*value){
    while(begin < end){
        if(*begin=='<'||*begin=='='||*begin=='\"' ||
            *begin=='?'||((*begin&0x80) == 0x80)){
            begin++;
            continue;
        }
        if(*begin=='>')break;
        *value++ = *begin++;
    }
}

void KeyboxTools::GetElemsValue(const uint8_t* begin,
                                     const uint8_t* end,
                                     uint8_t* value,
                                     size_t *len){
    uint32_t i=0;
    while(begin < end){
        if(*begin=='<' ||*begin=='-'||*begin=='\"'||
            ((*begin&0x80) == 0x80)){
            begin++;
            continue;
        }
        if(*begin=='>')break;
        *value++ = *begin++;
        i++;
    }
    *len = i;
}

bool KeyboxTools::HandleCertItems(xml_elems_e type,
                                        const uint8_t* begin,
                                        const uint8_t* end){
    size_t length;
    memset(AttestBuf.get(),0,KEYBOX_ITEM_MAX_SIZE);
    switch(type){
        case ELEMS_XML_VERSION:
        case ELEMS_DEVICE_ID:
        case ELEMS_KEYBOXS_NUM:
        case ELEMS_KEY_ALGO:
        case ELEMS_KEY_FORMAT:
        case ELEMS_CERT_NUM:
        case ELEMS_CERT_FORMAT:
            GetElemsValue(begin,end,AttestBuf.get());
            break;
        case ELEMS_PRIV_KEY:
        case ELEMS_ATTEST_CERT:
            GetElemsValue(begin,end,AttestBuf.get(),&length);
            break;
        default:
            break;
    }
    return true;
}
void KeyboxTools::SaveKeyboxToRpmb(){
    int key_num=0,cert_num=0;
    GetXmlElems(ELEMS_XML_VERSION);
    LOG_E("[ ELEMS_XML_VERSION ] %s\n",AttestBuf.get());
    GetXmlElems(ELEMS_DEVICE_ID);
    LOG_E("[ ELEMS_DEVICE_ID ] %s\n",AttestBuf.get());
    GetXmlElems(ELEMS_KEYBOXS_NUM);
    WriteItemToStorage("CertLen",AttestBuf.get());
    key_num = atoi((const char*)AttestBuf.get());
    LOG_E("[ ELEMS_KEYBOXS_NUM ] %d\n",key_num);
    for(int i=0;i<key_num;i++){
        char algo[8]={0};
        char filename[32]={0};
        GetXmlElems(ELEMS_KEY_ALGO);
        printf("[ ELEMS_KEY_ALGO ] %s\n",AttestBuf.get());
        sprintf(algo,"%s",AttestBuf.get());
        GetXmlElems(ELEMS_CERT_NUM);
        cert_num = atoi((const char*)AttestBuf.get());
        sprintf(filename,"%sCertLen",algo);
        WriteItemToStorage(filename,AttestBuf.get());
        GetXmlElems(ELEMS_PRIV_KEY);
        LOG_E("[ ELEMS_PRIV_KEY ] %s\n",AttestBuf.get());
        sprintf(filename,"%sPrikey",algo);
        WriteItemToStorage(filename,AttestBuf.get());
        for(int j=0;j<cert_num;j++){
            GetXmlElems(ELEMS_ATTEST_CERT);
            LOG_E("[ ELEMS_ATTEST_CERT ] %s\n",AttestBuf.get());
            sprintf(filename,"%sCert%d",algo,j);
            WriteItemToStorage(filename,AttestBuf.get());
        }
        check_addr_ = StrXmlStart(cert_elems[ELEMS_KEY_ALGO].tag_end,check_addr_,xml_buf_+xml_size_);
    }

}

}
