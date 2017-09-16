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

#ifndef KEYMASTER_KEYBOX_TOOLS_H_
#define KEYMASTER_KEYBOX_TOOLS_H_

extern "C" {
#include <errno.h>
#include <hardware/keymaster_defs.h>
#include <lib/storage/storage.h>
}
#include <UniquePtr.h>
#pragma once

namespace keymaster {

#define KEYBOX_ITEM_MAX_SIZE 2048

typedef enum xml_elems_{
    ELEMS_XML_VERSION=0,
    ELEMS_KEYBOXS_NUM,
    ELEMS_DEVICE_ID,

    ELEMS_KEY_ALGO,
    ELEMS_KEY_FORMAT,
    ELEMS_PRIV_KEY,
    ELEMS_CERT_NUM,
    ELEMS_CERT_FORMAT,
    ELEMS_ATTEST_CERT,
    ELEMS_MAX_ITERM,
}xml_elems_e;

typedef struct cert_elems_{
    xml_elems_e type;
    uint8_t tag_begin[32];
    uint8_t tag_end[32];
    void* item_name;
}cert_elems_t;

class KeyboxTools{
public:
    KeyboxTools(uint8_t *data,storage_off_t size);
    KeyboxTools();
    ~KeyboxTools();
    size_t ReadAttestKey(keymaster_algorithm_t algorithm,const uint8_t** key);
//    size_t WriteRsaAttestKey(uint8_t* cert,size_t len);
    size_t ReadAttestCert(keymaster_algorithm_t algorithm,int index,const uint8_t** cert);
//    size_t WriteAttestCert(uint8_t* cert,size_t len);
    uint8_t ReadCertChainLength(keymaster_algorithm_t algorithm);
//    uint8_t WriteCertChainLength(size_t len);
    void SaveKeyboxToRpmb(void);

private:
    void SkipSp(uint8_t* in,uint8_t*out);
    void GetNewLine(void);
    void GetElemsValue(const uint8_t* begin,const uint8_t* end,uint8_t*value);
    void GetElemsValue(const uint8_t* begin,const uint8_t* end,uint8_t* value,size_t *len);
    uint8_t *StrXmlStart(uint8_t const *s1,uint8_t const *start,uint8_t const *end);
    uint8_t *StrXmlEnd(uint8_t const *s1,uint8_t const *start,uint8_t const *end);
    bool HandleCertItems(xml_elems_e type,const uint8_t* begin,const uint8_t* end);
    void GetXmlElems(uint8_t type);

    uint8_t * xml_buf_;
    storage_off_t xml_size_;
    uint8_t *check_addr_;
    uint8_t *elem;
    uint8_t *elem_end;
    UniquePtr<uint8_t[]> AttestBuf;
};

// RAII wrapper for storage_session_t
class StorageSession {
  public:
    StorageSession() {
        error_ = storage_open_session(&handle_, STORAGE_CLIENT_TP_PORT);
        if (error_ < 0) {
            LOG_E("Error: [%d] opening storage session", error_);
        }
    }
    ~StorageSession() {
        if (error_ < 0) {
            return;
        }
        storage_close_session(handle_);
        error_ = -EINVAL;
    }

    int error() const { return error_; }
    storage_session_t handle() { return handle_; }

  private:
    storage_session_t handle_ = 0;
    int error_ = -EINVAL;
};

// RAII wrapper for file_handle_t
class FileHandle {
  public:
    FileHandle(const char* filename) {
        if (session_.error() == 0) {
            error_ = storage_open_file(session_.handle(), &handle_, const_cast<char*>(filename),
                                       STORAGE_FILE_OPEN_CREATE, 0);
        } else {
            error_ = session_.error();
        }
    }
    ~FileHandle() {
        if (error_ != 0) {
            return;
        }
        storage_close_file(handle_);
        error_ = -EINVAL;
    }
    int error() const { return error_; }
    file_handle_t handle() { return handle_; }

  private:
    StorageSession session_;
    int error_ = -EINVAL;
    file_handle_t handle_ = 0;
};
}
#endif //KEYMASTER_PARSE_XML_H_
