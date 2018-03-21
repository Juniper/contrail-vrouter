/*
 * windows_util.c
 *
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include <assert.h>
#include <strsafe.h>
#include <stdbool.h>
#include <netinet/ether.h>

#include <vr_defs.h>
#include <vr_mem.h>
#include <nl_util.h>
#include <windows_shmem_ioctl.h>

#define ETHER_ADDR_STR_LEN (ETHER_ADDR_LEN * 3)

const LPCTSTR KSYNC_PATH = TEXT("\\\\.\\vrouterKsync");
const LPCTSTR FLOW_PATH  = TEXT("\\\\.\\vrouterFlow");
const LPCTSTR BRIDGE_PATH  = TEXT("\\\\.\\vrouterBridge");

static DWORD
print_and_get_error_code()
{
    DWORD error = GetLastError();
    LPTSTR message = NULL;

    DWORD flags = (FORMAT_MESSAGE_ALLOCATE_BUFFER |
                   FORMAT_MESSAGE_FROM_SYSTEM |
                   FORMAT_MESSAGE_IGNORE_INSERTS);
    DWORD lang_id = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    DWORD ret = FormatMessage(flags, NULL, error, lang_id, message, 0, NULL);

    if (ret != 0) {
        printf("Error: %s [%d]\r\n", message, error);
        LocalFree(message);
    } else {
        printf("Error: [%d]\r\n", error);
    }

    return error;
}

const char *
vr_table_map(int major, unsigned int table, const char *table_path, size_t size, void **mem)
{
    enum { ERROR_LEN = 1024 };
    static char error_msg[ERROR_LEN];

    LPCTSTR path;
    switch(table) {
    case VR_MEM_BRIDGE_TABLE_OBJECT:
        path = BRIDGE_PATH;
        break;
    case VR_MEM_FLOW_TABLE_OBJECT:
        path = FLOW_PATH;
        break;
    default:
        snprintf(error_msg, ERROR_LEN, "Error: Invalid 'table' value: %u", table);
        return error_msg;
    }

    HANDLE shmemPipe = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0,
        NULL);
    if (shmemPipe == INVALID_HANDLE_VALUE) {
        snprintf(error_msg, ERROR_LEN, "Error: CreateFile on shmem pipe: %d", GetLastError());
        return error_msg;
    }

    DWORD outBytes;
    BOOL transactionResult = DeviceIoControl(shmemPipe, IOCTL_SHMEM_GET_ADDRESS, NULL, 0, mem,
        sizeof(*mem), &outBytes, NULL);

    if (!transactionResult) {
        snprintf(error_msg, ERROR_LEN, "Error: DeviceIoControl on shmem pipe: %d", GetLastError());
        return error_msg;
    } else if (outBytes != sizeof(*mem)) {
        snprintf(error_msg, ERROR_LEN,
            "Error: DeviceIoControl on shmem pipe: pointer wasn't fully filled");
        return error_msg;
    }

    return NULL;
}

const char *
vr_table_unlink(const char *path)
{
    return NULL;
}

int
nl_socket(struct nl_client *cl, int domain, int type, int protocol)
{
    DWORD access_flags = GENERIC_READ | GENERIC_WRITE;
    DWORD attrs = OPEN_EXISTING;

    HANDLE pipe = CreateFile(KSYNC_PATH, access_flags, 0, NULL, attrs, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
        return -1;

    cl->cl_win_pipe = pipe;
    cl->cl_recvmsg = win_nl_client_recvmsg;

    return 1;
}

int
nl_connect(struct nl_client *cl, uint32_t ip, uint16_t port)
{
    vrouter_obtain_family_id(cl);
    return 0;
}

int
nl_sendmsg(struct nl_client *cl)
{
    DWORD written = 0;
    BOOL ret = WriteFile(cl->cl_win_pipe, cl->cl_buf, cl->cl_buf_offset, &written, NULL);
    if (!ret) {
        print_and_get_error_code();
        return -1;
    }

    return written;
}

int
win_nl_client_recvmsg(struct nl_client *cl, bool msg_wait)
{
    DWORD read_bytes = 0;

    cl->cl_buf_offset = 0;
    cl->cl_recv_len = 0;

    BOOL ret = ReadFile(cl->cl_win_pipe, cl->cl_buf, NL_MSG_DEFAULT_SIZE, &read_bytes, NULL);
    if (!ret) {
        print_and_get_error_code();
        return -1;
    }

    cl->cl_recv_len = read_bytes;
    if (cl->cl_recv_len > cl->cl_buf_len)
        return -EOPNOTSUPP;

    return read_bytes;
}

void
nl_free_os_specific(struct nl_client *cl)
{
    if (cl->cl_win_pipe) {
        CloseHandle(cl->cl_win_pipe);
        cl->cl_win_pipe = NULL;
    }
}

void
nl_reset_cl_sock(struct nl_client *cl)
{
}

struct nl_response *
nl_parse_reply_os_specific(struct nl_client *cl)
{
    return NULL;
}

int
vrouter_obtain_family_id(struct nl_client *cl)
{
    /* On platforms other than Linux value of family id is not checked,
       so it is set to FAKE_NETLINK_FAMILY */
    nl_set_genl_family_id(cl, FAKE_NETLINK_FAMILY);
    return cl->cl_genl_family_id;
}

static inline int
xdigit(char c) {
    unsigned d;
    d = (unsigned)(c - '0');
    if (d < 10) return (int)d;
    d = (unsigned)(c - 'a');
    if (d < 6) return (int)(10 + d);
    d = (unsigned)(c - 'A');
    if (d < 6) return (int)(10 + d);
    return -1;
}

int
inet_aton(const char *cp, struct in_addr *addr)
{
    return inet_pton(AF_INET, cp, addr);
}

struct ether_addr *
ether_aton_r(const char *asc, struct ether_addr * addr)
{
    int i, val0, val1;
    for (i = 0; i < ETHER_ADDR_LEN; ++i) {
        val0 = xdigit(*asc);
        asc++;
        if (val0 < 0)
            return NULL;

        val1 = xdigit(*asc);
        asc++;
        if (val1 < 0)
            return NULL;

        addr->ether_addr_octet[i] = (u_int8_t)((val0 << 4) + val1);

        if (i < ETHER_ADDR_LEN - 1) {
            if (*asc != ':')
                return NULL;
            asc++;
        }
    }
    if (*asc != '\0')
        return NULL;
    return addr;
}

/*
* Convert Ethernet address in the standard hex-digits-and-colons to binary
* representation.
* Re-entrant version (GNU extensions)
*/
struct ether_addr *
ether_aton(const char *asc)
{
    static struct ether_addr addr;
    return ether_aton_r(asc, &addr);
}

char *
ether_ntoa(const struct ether_addr *addr)
{
    static char buffer[ETHER_ADDR_STR_LEN];

    memset(buffer, 0, sizeof(buffer));
    int ret = snprintf(buffer, sizeof(buffer), MAC_FORMAT, MAC_VALUE(addr->ether_addr_octet));
    assert(ret == ETHER_ADDR_STR_LEN - 1);  // ETHER_ADDR_STR_LEN includes '\0' byte

    return buffer;
}
