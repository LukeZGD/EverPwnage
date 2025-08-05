#include "oob_entry.h"
#include "util.h"

void *(*IOSurfaceCreate)(CFDictionaryRef) = NULL;
void *(*IOSurfaceGetBaseAddress)(void *) = NULL;
int (*IOServiceOpen)(mach_port_t, mach_port_t, uint32_t, mach_port_t *) = NULL;
CFMutableDictionaryRef (*IOServiceMatching)(const char *) = NULL;
mach_port_t (*IOServiceGetMatchingService)(mach_port_t, CFDictionaryRef) = NULL;
int (*IOMobileFramebufferOpen)(mach_port_t, mach_port_t, uint32_t, void *) = NULL;
int (*IOMobileFramebufferGetLayerDefaultSurface)(mach_port_t, int, void *) = NULL;

int init_io(void) {
    void *io_handle = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW);
    if (io_handle == NULL) {
        io_handle = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_NOW);
        if (io_handle == NULL) return -1;
    }

    if ((IOSurfaceCreate = dlsym(io_handle, "IOSurfaceCreate")) == NULL) return -1;
    if ((IOSurfaceGetBaseAddress = dlsym(io_handle, "IOSurfaceGetBaseAddress")) == NULL) return -1;
    if ((IOServiceGetMatchingService = dlsym(io_handle, "IOServiceGetMatchingService")) == NULL) return -1;
    if ((IOServiceMatching = dlsym(io_handle, "IOServiceMatching")) == NULL) return -1;
    if ((IOServiceOpen = dlsym(io_handle, "IOServiceOpen")) == NULL) return -1;

    void *fb_handle = dlopen("/System/Library/Frameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer", RTLD_NOW);
    if (fb_handle == NULL) {
        fb_handle = dlopen("/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer", RTLD_NOW);
        if (fb_handle == NULL) return -1;
    }

    if ((IOMobileFramebufferOpen = dlsym(fb_handle, "IOMobileFramebufferOpen")) == NULL) return -1;
    if ((IOMobileFramebufferGetLayerDefaultSurface = dlsym(fb_handle, "IOMobileFramebufferGetLayerDefaultSurface")) == NULL) return -1;
    return 0;
}

void get_ios_version(uint32_t *output) {
    char str[32] = {0};
    CFDictionaryRef dict = _CFCopySystemVersionDictionary();
    CFStringRef version = CFDictionaryGetValue(dict, CFSTR("ProductVersion"));
    CFStringGetCString(version, str, 32, kCFStringEncodingUTF8);
    
    sscanf(str, "%d.%d.%d", &output[0], &output[1], &output[2]);
    CFRelease(dict);
}

CFNumberRef CFNUM(uint32_t value) {
    return CFNumberCreate(NULL, kCFNumberIntType, (void *)&value);
}

mach_port_t create_mach_port(void) {
    mach_port_t port = MACH_PORT_NULL;
    mach_port_t task = mach_task_self();
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND);
    return port;
}

bool valid_ipc_port(uint32_t addr) {
    if ((addr & 0x80000000) != 0x80000000 || (addr % 4) != 0) return false;
    return !(addr == 0xff000000 || addr == 0xffff0000 || addr == 0xdeadbeef);
}

uint64_t timer_start(void) {
    return mach_absolute_time();
}

uint64_t timer_end(uint64_t start) {
    uint64_t end = mach_absolute_time();
    mach_timebase_info_data_t info = {0};
    mach_timebase_info(&info);
    return (uint64_t)(((double)(end - start) * info.numer / info.denom) / 1000000);
}

int init_offsets(void) {
    get_ios_version(kinfo->version);
    if (kinfo->version[0] < 3 || kinfo->version[0] > 10) return -1;
    
    size_t size = sizeof(kinfo->mem_size);
    sysctlbyname("hw.physmem", &kinfo->mem_size, &size, NULL, 0);
    kinfo->mem_size &= 0xfff00000;

    switch (kinfo->version[0]) {
        case 10:
            kinfo->offsets.task.ref_count = 0x8;
            kinfo->offsets.task.bsd_info = 0x22c;
            kinfo->offsets.ipc_port.ip_references = 0x4;
            kinfo->offsets.ipc_port.ip_kobject = 0x48;
            kinfo->offsets.ipc_port.size = 0x74;
            kinfo->kernel_static_base = 0x80001000;
            kinfo->kernel_phys_base = 0x80001000;
            kinfo->mem_base = 0x80000000;
            break;
        case 9:
            kinfo->offsets.task.ref_count = 0xc;
            kinfo->offsets.task.bsd_info = 0x200;
            kinfo->offsets.ipc_port.ip_references = 0x4;
            kinfo->offsets.ipc_port.ip_kobject = 0x50;
            kinfo->offsets.ipc_port.size = 0x78;
            kinfo->kernel_static_base = 0x80001000;
            kinfo->kernel_phys_base = 0x80001000;
            kinfo->mem_base = 0x80000000;
            break;
        case 8:
            kinfo->offsets.task.ref_count = 0xc;
            kinfo->offsets.task.bsd_info = 0x1f0;
            kinfo->offsets.ipc_port.ip_references = 0x4;
            kinfo->offsets.ipc_port.ip_kobject = 0x44;
            kinfo->offsets.ipc_port.size = 0x70;
            kinfo->kernel_static_base = 0x80001000;
            kinfo->kernel_phys_base = 0x80001000;
            kinfo->mem_base = 0x80000000;
            break;
        case 7:
            kinfo->offsets.task.ref_count = 0xc;
            kinfo->offsets.task.bsd_info = 0x1e8;
            kinfo->offsets.ipc_port.ip_references = 0x4;
            kinfo->offsets.ipc_port.ip_kobject = 0x44;
            kinfo->offsets.ipc_port.size = 0x70;
            kinfo->kernel_static_base = 0x80001000;
            kinfo->kernel_phys_base = 0x80001000;
            kinfo->mem_base = 0x80000000;
            break;
        case 6:
            kinfo->offsets.task.ref_count = 0xc;
            kinfo->offsets.task.bsd_info = 0x1e0;
            kinfo->offsets.ipc_port.ip_references = 0x4;
            kinfo->offsets.ipc_port.ip_kobject = 0x44;
            kinfo->offsets.ipc_port.size = 0x70;
            kinfo->kernel_static_base = 0x80001000;
            kinfo->kernel_phys_base = 0x80001000;
            kinfo->mem_base = 0x80000000;
            break;
        case 5:
            kinfo->offsets.task.ref_count = 0xc;
            kinfo->offsets.task.bsd_info = 0x1ec;
            kinfo->offsets.ipc_port.ip_references = 0x4;
            kinfo->offsets.ipc_port.ip_kobject = 0x40;
            kinfo->offsets.ipc_port.size = 0x74;
            kinfo->kernel_static_base = 0x80001000;
            kinfo->kernel_phys_base = 0x80001000;
            kinfo->mem_base = 0x80000000;
            break;
        case 4:
            kinfo->offsets.task.ref_count = 0xc;
            kinfo->offsets.task.bsd_info = 0x1cc;
            kinfo->offsets.ipc_port.ip_references = 0x4;
            kinfo->offsets.ipc_port.ip_kobject = 0x40;
            kinfo->offsets.ipc_port.size = 0x6c;
            kinfo->kernel_static_base = 0x80001000;
            kinfo->kernel_phys_base = 0x80001000;
            kinfo->mem_base = 0x80000000;
            break;
        case 3:
            kinfo->offsets.task.ref_count = 0xc;
            kinfo->offsets.task.bsd_info = 0x1c4;
            kinfo->offsets.ipc_port.ip_references = 0x0;
            kinfo->offsets.ipc_port.ip_kobject = 0x40;
            kinfo->offsets.ipc_port.size = 0x90;
            if (kinfo->version[1] == 1) {
                kinfo->kernel_static_base = 0xc0008000;
                kinfo->kernel_phys_base = 0x40008000;
                kinfo->mem_base = 0x40000000;
            } else {
                kinfo->kernel_static_base = 0x80001000;
                kinfo->kernel_phys_base = 0x80001000;
                kinfo->mem_base = 0x80000000;
            }
            break;
        default:
            break;
    }
    return 0;
}
