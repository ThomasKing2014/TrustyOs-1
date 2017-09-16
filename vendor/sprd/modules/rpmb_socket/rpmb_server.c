/*
 * Copyright (c) 2015, Spreadtrum.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
 
#include <ctype.h>
#include <cutils/log.h>
#include <cutils/sockets.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <utils/Log.h>

#include <linux/major.h>
#include <linux/mmc/ioctl.h>

#define RPMB_DEBUG 1

#define MMC_READ_MULTIPLE_BLOCK  18
#define MMC_WRITE_MULTIPLE_BLOCK 25
#define MMC_RELIABLE_WRITE_FLAG (1 << 31)

#define MMC_RSP_PRESENT         (1 << 0)
#define MMC_RSP_CRC             (1 << 2)
#define MMC_RSP_OPCODE          (1 << 4)
#define MMC_CMD_ADTC            (1 << 5)
#define MMC_RSP_SPI_S1          (1 << 7)
#define MMC_RSP_R1              (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_SPI_R1          (MMC_RSP_SPI_S1)

#define MMC_WRITE_FLAG_R 0
#define MMC_WRITE_FLAG_W 1
#define MMC_WRITE_FLAG_RELW (MMC_WRITE_FLAG_W | MMC_RELIABLE_WRITE_FLAG)

#define MMC_BLOCK_SIZE 512
#define RPMB_DATA_SIZE 256


#define RPMB_DEV_PATH         "/dev/block/mmcblk0rpmb"


struct rpmb_nonce {
    uint8_t     byte[16];
};

struct rpmb_u16 {
    uint8_t     byte[2];
};

struct rpmb_u32 {
    uint8_t     byte[4];
};

struct rpmb_key {
    uint8_t     byte[32];
};


struct rpmb_packet {
    uint8_t              pad[196];
    struct rpmb_key      key_mac;
    uint8_t              data[256];
    struct rpmb_nonce    nonce;
    struct rpmb_u32      write_counter;
    struct rpmb_u16      address;
    struct rpmb_u16      block_count;
    struct rpmb_u16      result;
    struct rpmb_u16      req_resp;
};

enum rpmb_request {
    RPMB_REQ_PROGRAM_KEY                = 0x0001,
    RPMB_REQ_GET_COUNTER                = 0x0002,
    RPMB_REQ_DATA_WRITE                 = 0x0003,
    RPMB_REQ_DATA_READ                  = 0x0004,
    RPMB_REQ_RESULT_READ                = 0x0005,
};

enum rpmb_response {
    RPMB_RESP_PROGRAM_KEY               = 0x0100,
    RPMB_RESP_GET_COUNTER               = 0x0200,
    RPMB_RESP_DATA_WRITE                = 0x0300,
    RPMB_RESP_DATA_READ                 = 0x0400,
};

enum rpmb_result {
    RPMB_RES_OK                         = 0x0000,
    RPMB_RES_GENERAL_FAILURE            = 0x0001,
    RPMB_RES_AUTH_FAILURE               = 0x0002,
    RPMB_RES_COUNT_FAILURE              = 0x0003,
    RPMB_RES_ADDR_FAILURE               = 0x0004,
    RPMB_RES_WRITE_FAILURE              = 0x0005,
    RPMB_RES_READ_FAILURE               = 0x0006,
    RPMB_RES_NO_AUTH_KEY                = 0x0007,

    RPMB_RES_WRITE_COUNTER_EXPIRED      = 0x0080,
};


static struct rpmb_u16 rpmb_u16(uint16_t val)
{
    struct rpmb_u16 ret = {{
        val >> 8,
        val >> 0,
    }};
    return ret;
}



static uint16_t rpmb_get_u16(struct rpmb_u16 u16)
{
    size_t i;
    uint16_t val;

    val = 0;
    for (i = 0; i < sizeof(u16.byte); i++)
        val = val << 8 | u16.byte[i];

    return val;
}

#define LOG_TAG "RPMB_SERVER"

#if RPMB_DEBUG
#define rpmb_dprintf(fmt, ...) ALOGD(fmt, ##__VA_ARGS__)
#else
#define rpmb_dprintf(fmt, ...) do { } while (0)
#endif
#define dprintf(fmt, ...) ALOGD(fmt, ##__VA_ARGS__)


static void rpmb_dprint_buf(const char *prefix, const uint8_t *buf, size_t size)
{
    size_t i, j;

    rpmb_dprintf("%s", prefix);
    for (i = 0; i < size; i++) {
        if (i && i % 32 == 0) {
            rpmb_dprintf("\n");
            j = strlen(prefix);
            while (j--)
                rpmb_dprintf(" ");
        }
        rpmb_dprintf(" %02x", buf[i]);
    }
    rpmb_dprintf("\n");
}

static void rpmb_dprint_u16(const char *prefix, const struct rpmb_u16 u16)
{
    rpmb_dprint_buf(prefix, u16.byte, sizeof(u16.byte));
}


int program_rpmb_key(uint8_t *key_byte, size_t key_len)
{
    struct mmc_ioc_cmd cmds[3];
    struct mmc_ioc_cmd *cmd;

    struct rpmb_packet req;
    struct rpmb_packet res;
    int rpmb_fd = -1;
    int rc;

    rpmb_dprintf("rpmb_program_key() start \n");

    rpmb_fd = open(RPMB_DEV_PATH, O_RDWR);
    if (rpmb_fd < 0 ) {
        rpmb_dprintf("open rpmb device %s failed\n", RPMB_DEV_PATH);
	return -1 ;
    }

    if (NULL == key_byte || key_len <= 0) {
        rpmb_dprintf(" rpmb_program_key()  fail, key_byte is NULL or key_len is %d !\n", key_len);
        rc = -1;
        goto error;

    }

    memset(cmds, 0, sizeof(cmds));
//for write rpmb key req
    cmd = &cmds[0];
    cmd->write_flag = MMC_WRITE_FLAG_RELW;
    cmd->opcode = MMC_WRITE_MULTIPLE_BLOCK;
    cmd->flags = MMC_RSP_R1;
    cmd->blksz = MMC_BLOCK_SIZE;
    cmd->data_timeout_ns = 1000000000;
    cmd->is_acmd = 0;
    cmd->blocks = 1;  //must set 1

    memset(&req, 0, sizeof(req));
    req.req_resp = rpmb_u16(RPMB_REQ_PROGRAM_KEY);
    memcpy(req.key_mac.byte, key_byte, key_len);

    mmc_ioc_cmd_set_data((*cmd), &req);
#ifdef RPMB_DEBUG
    rpmb_dprintf("opcode: 0x%x, write_flag: 0x%x\n", cmd->opcode, cmd->write_flag);
#endif
    rc = ioctl(rpmb_fd, MMC_IOC_CMD, cmd);
    if (0 > rc) {
        rpmb_dprintf("%s: mmc ioctl failed: %d, %s\n", __func__, rc, strerror(errno));
        rc = -1;
        goto error;

    }


//for read result req
    cmd = &cmds[1];
    cmd->write_flag = MMC_WRITE_FLAG_W;
    //the result read sequence is initiated by write Multiple Block command CMD25.
    cmd->opcode = MMC_WRITE_MULTIPLE_BLOCK;
    cmd->flags = MMC_RSP_R1;
    cmd->blksz = MMC_BLOCK_SIZE;
    cmd->data_timeout_ns = 1000000000;
    cmd->is_acmd = 0;
    cmd->blocks = 1;  //must set 1
    memset(&req, 0, sizeof(req));
    req.req_resp = rpmb_u16(RPMB_REQ_RESULT_READ);
    mmc_ioc_cmd_set_data((*cmd), &req);

    rpmb_dprintf("opcode: 0x%x, write_flag: 0x%x\n", cmd->opcode, cmd->write_flag);

    rc = ioctl(rpmb_fd, MMC_IOC_CMD, cmd);
    if (0 > rc) {
        rpmb_dprintf("%s: mmc ioctl failed: %d, %s\n", __func__, rc, strerror(errno));
        rc = -1;
        goto error;

    }


    cmd = &cmds[2];
    cmd->write_flag = MMC_WRITE_FLAG_R;
    //read the result
    cmd->opcode = MMC_READ_MULTIPLE_BLOCK;
    cmd->flags = MMC_RSP_R1;
    cmd->blksz = MMC_BLOCK_SIZE;
    cmd->blocks = 1;
    cmd->data_timeout_ns = 1000000000;
    cmd->is_acmd = 0;

    memset(&res, 0, sizeof(res));
    mmc_ioc_cmd_set_data((*cmd), &res);


    rpmb_dprintf("opcode: 0x%x, write_flag: 0x%x\n", cmd->opcode, cmd->write_flag);


    rc = ioctl(rpmb_fd, MMC_IOC_CMD, cmd);
    if (rc < 0) {
        rpmb_dprintf("%s: mmc ioctl failed: %d, %s\n", __func__, rc, strerror(errno));
        rc = -1;
        goto error;
    }


//result check
    if (RPMB_RESP_PROGRAM_KEY != rpmb_get_u16(res.req_resp)) {
        rpmb_dprintf("rpmb_program_key: Bad response type, 0x%x, expected 0x%x\n",
            rpmb_get_u16(res.req_resp), RPMB_RESP_PROGRAM_KEY);
        rc = -1;
        goto error;
    }

    if (RPMB_RES_OK != rpmb_get_u16(res.result)) {
        rpmb_dprintf("rpmb_program_key: Bad result, 0x%x\n", rpmb_get_u16(res.result));
        rc = -1;
        goto error;
    }

    rpmb_dprintf("rpmb_program_key() successed \n");

    rc = 0;

error:
    close(rpmb_fd);

    return rc;
}

#define LISTEN_BACKLOG 4
int main(int argc, char *argv[]) {
    int srv_fd, lis_fd, cfd, ret;
    uint8_t rpmb_char[32];
    rpmb_dprintf("%s rpmb server start...\n", __func__);

    srv_fd = socket_local_server("rpmb_cli", ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    if (srv_fd < 0) {
        rpmb_dprintf("%s rpmb server socket_local_server error: %s\n", __func__, strerror(errno));
        return -1;
    }

    lis_fd = listen(srv_fd, LISTEN_BACKLOG);
    if(lis_fd != 0){
        rpmb_dprintf("%s rpmb server listen error: %s\n", __func__, strerror(errno));
        return -1;
    }

    while(1){
        cfd = accept(srv_fd, NULL, NULL);
        if (cfd < 0) {
            rpmb_dprintf("%s rpmb server accept error: %s\n", __func__, strerror(errno));
            continue;
        }

        ret = read(cfd, rpmb_char, 7);
        char buf[] = "rpmbkey";
        if (ret > 0 && memcmp(rpmb_char, buf, strlen(buf)) == 0) {
            rpmb_dprintf("%s rpmb server first read %d bytes to client socket [%d] \n", __func__, ret, cfd);
        } else {
            rpmb_dprintf("%s rpmb server first read error: %s\n", __func__, strerror(errno));
            continue;
        }

        ret = read(cfd, rpmb_char, 32);
        if (ret > 0) {
            rpmb_dprintf("%s rpmb server second read %d bytes to client socket [%d] \n", __func__, ret, cfd);
        } else {
            rpmb_dprintf("%s rpmb server second read error: %s\n", __func__, strerror(errno));
            continue;
        }
        //ret = program_rpmb_key(rpmb_char, 32);
        ret = 0;
        write(cfd, &ret, sizeof(ret));
        //break;
    }
    rpmb_dprintf("%s rpmb server end...\n", __func__);
    return 0;
}
