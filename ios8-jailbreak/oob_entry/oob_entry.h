#ifndef oob_entry_h
#define oob_entry_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#include <sys/resource.h>

typedef struct {
    uint32_t self_port_addr;
    uint32_t self_proc_addr;
    uint32_t self_task_addr;
    uint32_t kern_port_addr;
    uint32_t kern_proc_addr;
    uint32_t kern_task_addr;
    uint32_t kern_tte_phys;
    uint32_t host_port_addr;
    uint32_t kernel_slide;
    uint32_t kernel_base;
    uint32_t kernel_static_base;
    uint32_t kernel_phys_base;
    mach_port_t main_entry;
    mach_port_t oob_entry;
    uint32_t mapping_base;
    uint32_t mem_base;
    uint32_t mem_size;
    uint32_t addr_mask;
    mach_port_t tfp0;
    uint32_t version[3];
    struct {
        struct {
            int ref_count;
            int bsd_info;
        } task;        
        struct {
            int ip_references;
            int ip_kobject;
            int size;
        } ipc_port;
    } offsets;
} kinfo_t;

extern kinfo_t *kinfo;

void print_log(const char *fmt, ...);
int run_exploit(int ool_count);

#endif /* oob_entry_h */
