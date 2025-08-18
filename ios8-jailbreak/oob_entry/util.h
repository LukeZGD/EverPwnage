#ifndef util_h
#define util_h

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>

#define IKOT_TASK           0x00000002
#define	IKOT_HOST           0x00000003
#define	IKOT_HOST_PRIV      0x00000004
#define IO_BITS_ACTIVE      0x80000000
#ifdef UNTETHER
#define OOL_COUNT           1024
#else
#define OOL_COUNT           5
#endif

#define koffsetof(struct, entry) kinfo->offsets.struct.entry

typedef struct {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports;
} ool_msg_t;

extern CFDictionaryRef _CFCopySystemVersionDictionary(void);
extern void *(*IOSurfaceCreate)(CFDictionaryRef);
extern void *(*IOSurfaceGetBaseAddress)(void *);
extern int (*IOServiceOpen)(mach_port_t, mach_port_t, uint32_t, mach_port_t *);
extern CFMutableDictionaryRef (*IOServiceMatching)(const char *);
extern mach_port_t (*IOServiceGetMatchingService)(mach_port_t, CFDictionaryRef);
extern int (*IOMobileFramebufferOpen)(mach_port_t, mach_port_t, uint32_t, void *);
extern int (*IOMobileFramebufferGetLayerDefaultSurface)(mach_port_t, int, void *);

int init_io(void);
void get_ios_version(uint32_t *output);
CFNumberRef CFNUM(uint32_t value);
mach_port_t create_mach_port(void);
bool valid_ipc_port(uint32_t addr);
uint64_t timer_start(void);
uint64_t timer_end(uint64_t start);
int init_offsets(void);

#endif /* util_h */
