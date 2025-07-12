// offsets.m from wtfis

#import <Foundation/Foundation.h>

#import <stdio.h>
#import <stdlib.h>

#import "common.h"
#import "offsets.h"
#import "jailbreak.h"

int* offsets = NULL;
bool is_ios9 = false;

int kstruct_offsets_9_3[] = {
    0x18,  // TASK_VM_MAP
    0x1c,  // TASK_NEXT
    0x20,  // TASK_PREV
    0xa4,  // TASK_ITK_SELF
    0x1b8, // TASK_ITK_SPACE
    0x200, // TASK_BSDINFO

    0x4c,  // IPC_PORT_IP_RECEIVER
    0x50,  // IPC_PORT_IP_KOBJECT
    0x70,  // IPC_PORT_IP_SRIGHTS

    0x8,   // BSDINFO_PID
    0xa8,  // PROC_P_FD
    0xa4,  // BSDINFO_KAUTH_CRED

    0x0,   // FILEDESC_FD_OFILES

    0x8,   // FILEPROC_F_FGLOB

    0x28,  // FILEGLOB_FG_DATA

    0x10,  // PIPE_BUFFER

    0x18,  // IPC_SPACE_IS_TABLE
    0x10,  // IPC_ENTRY_SIZE
};

int kstruct_offsets_9_2[] = {
    0x18,  // TASK_VM_MAP
    0x1c,  // TASK_NEXT
    0x20,  // TASK_PREV
    0xa4,  // TASK_ITK_SELF
    0x1b8, // TASK_ITK_SPACE
    0x200, // TASK_BSDINFO

    0x4c,  // IPC_PORT_IP_RECEIVER
    0x50,  // IPC_PORT_IP_KOBJECT
    0x70,  // IPC_PORT_IP_SRIGHTS

    0x8,   // BSDINFO_PID
    0x9c,  // PROC_P_FD
    0x98,  // BSDINFO_KAUTH_CRED

    0x0,   // FILEDESC_FD_OFILES

    0x8,   // FILEPROC_F_FGLOB

    0x28,  // FILEGLOB_FG_DATA

    0x10,  // PIPE_BUFFER

    0x18,  // IPC_SPACE_IS_TABLE
    0x10,  // IPC_ENTRY_SIZE
};

int kstruct_offsets_9_0[] = {
    0x18,  // TASK_VM_MAP
    0x1c,  // TASK_NEXT
    0x20,  // TASK_PREV
    0xa4,  // TASK_ITK_SELF
    0x1b8, // TASK_ITK_SPACE
    0x200, // TASK_BSDINFO

    0x4c,  // IPC_PORT_IP_RECEIVER
    0x50,  // IPC_PORT_IP_KOBJECT
    0x70,  // IPC_PORT_IP_SRIGHTS

    0x8,   // BSDINFO_PID
    0x90,  // PROC_P_FD
    0x8c,  // BSDINFO_KAUTH_CRED

    0x0,   // FILEDESC_FD_OFILES

    0x8,   // FILEPROC_F_FGLOB

    0x28,  // FILEGLOB_FG_DATA

    0x10,  // PIPE_BUFFER

    0x18,  // IPC_SPACE_IS_TABLE
    0x10,  // IPC_ENTRY_SIZE
};

int kstruct_offsets_8[] = {
    0x18,  // TASK_VM_MAP
    0x1c,  // TASK_NEXT
    0x20,  // TASK_PREV
    0xa4,  // TASK_ITK_SELF
    0x1a8, // TASK_ITK_SPACE
    0x1f0, // TASK_BSDINFO
    
    0x40,  // IPC_PORT_IP_RECEIVER
    0x44,  // IPC_PORT_IP_KOBJECT
    0x5c,  // IPC_PORT_IP_SRIGHTS
    
    0x8,   // BSDINFO_PID
    0x90,  // PROC_P_FD
    0x8c,  // BSDINFO_KAUTH_CRED
    
    0x0,   // FILEDESC_FD_OFILES
    
    0x8,   // FILEPROC_F_FGLOB
    
    0x28,  // FILEGLOB_FG_DATA
    
    0x10,  // PIPE_BUFFER
    
    0x18,  // IPC_SPACE_IS_TABLE
    0x10,  // IPC_ENTRY_SIZE
};

int kstruct_offsets_7[] = {
    0x18,  // TASK_VM_MAP
    0x1c,  // TASK_NEXT
    0x20,  // TASK_PREV
    0xa0,  // TASK_ITK_SELF
    0x1a8, // TASK_ITK_SPACE
    0x1e8, // TASK_BSDINFO

    0x40,  // IPC_PORT_IP_RECEIVER
    0x44,  // IPC_PORT_IP_KOBJECT
    0x5c,  // IPC_PORT_IP_SRIGHTS

    0x8,   // BSDINFO_PID
    0x90,  // PROC_P_FD
    0x8c,  // BSDINFO_KAUTH_CRED

    0x0,   // FILEDESC_FD_OFILES

    0x8,   // FILEPROC_F_FGLOB

    0x28,  // FILEGLOB_FG_DATA

    0x10,  // PIPE_BUFFER

    0x14,  // IPC_SPACE_IS_TABLE
    0x10,  // IPC_ENTRY_SIZE
};

int koffset(enum kstruct_offset offset) {
    if (offsets == NULL) {
        printf("need to call offsets_init() prior to querying offsets\n");
        return 0;
    }
    return offsets[offset];
}

void offsets_init(void) {
    if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
        printf("[i] offsets selected for iOS 9.3.x\n");
        offsets = kstruct_offsets_9_3;
        is_ios9 = true;
    } else if (strstr(ckernv, "3248.3") || strstr(ckernv, "3248.2") || strstr(ckernv, "3248.10")) {
        printf("[i] offsets selected for iOS 9.1-9.2.1\n");
        offsets = kstruct_offsets_9_2;
        is_ios9 = true;
    } else if (strstr(ckernv, "3248.1.") || strstr(ckernv, "3247")) {
        printf("[i] offsets selected for iOS 9.0.x\n");
        offsets = kstruct_offsets_9_0;
        is_ios9 = true;
    } else if (strstr(ckernv, "2784") || strstr(ckernv, "2783")) {
        printf("[i] offsets selected for iOS 8.x\n");
        offsets = kstruct_offsets_8;
    } else if (strstr(ckernv, "2423")) {
        printf("[i] offsets selected for iOS 7.x\n");
        offsets = kstruct_offsets_7;
    } else {
        printf("[-] iOS version not supported\n");
        exit(1);
    }
}
