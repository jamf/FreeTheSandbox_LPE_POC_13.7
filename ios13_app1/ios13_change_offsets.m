//
//  ios13_change_offsets.c
//  ios13_app1
//
//  Created by bb on 1/25/20.
//  Copyright © 2020 bb. All rights reserved.
//


#include <stdio.h>
#include <setjmp.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/semaphore.h>
#include <mach/mach_traps.h>
#include <mach/thread_status.h>
#include <pthread/pthread.h>
#include <IOSurface/IOSurfaceRef.h>
#include "IOKitLib.h"
#include <dirent.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#pragma mark --- External API
//set share_analytics = false to disable analytics sharing
share_analytics = true;

#define SYSTEM_VERSION_EQUAL_TO(v)                  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v)              ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v)                 ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v)     ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)

bool check_if_iOS_version_equal_to(const char *cmpto_version){
    CFStringRef cfstrwrap = CFStringCreateWithCString(kCFAllocatorDefault, cmpto_version, kCFStringEncodingUTF8);
    
    if (SYSTEM_VERSION_EQUAL_TO((__bridge NSString * _Nonnull)(cfstrwrap))) {
        return true;
    }
    
    CFRelease(cfstrwrap);
    return false;
}

bool check_if_iOS_version_greater_than_or_equal_to(const char *cmpto_version){
    CFStringRef cfstrwrap = CFStringCreateWithCString(kCFAllocatorDefault, cmpto_version, kCFStringEncodingUTF8);
    
    if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO((__bridge NSString * _Nonnull)(cfstrwrap))) {
        return true;
    }
    
    CFRelease(cfstrwrap);
    return false;
}

bool check_if_iOS_version_less_then(const char *cmpto_version){
    CFStringRef cfstrwrap = CFStringCreateWithCString(kCFAllocatorDefault, cmpto_version, kCFStringEncodingUTF8);
    
    if (SYSTEM_VERSION_LESS_THAN((__bridge NSString * _Nonnull)(cfstrwrap))) {
        return true;
    }
    
    CFRelease(cfstrwrap);
    return false;
}

bool check_if_its_PAC_device(){
#if __arm64e__
    return true;
#endif
    return false;
}

bool check_if_amfid_has_entitParser(){
    if(check_if_iOS_version_greater_than_or_equal_to("13.5"))
        return true;
    return false;
}

char *_cur_deviceModel = NULL;
char *get_current_deviceModel(){
    if(_cur_deviceModel)
        return _cur_deviceModel;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString* code = [NSString stringWithCString:systemInfo.machine
                                        encoding:NSUTF8StringEncoding];
    static NSDictionary* deviceNamesByCode = nil;
    if (!deviceNamesByCode) {
        deviceNamesByCode = @{@"i386"      : @"Simulator",
                              @"x86_64"    : @"Simulator",
                              @"iPod1,1"   : @"iPod Touch",        // (Original)
                              @"iPod2,1"   : @"iPod Touch",        // (Second Generation)
                              @"iPod3,1"   : @"iPod Touch",        // (Third Generation)
                              @"iPod4,1"   : @"iPod Touch",        // (Fourth Generation)
                              @"iPod7,1"   : @"iPod Touch",        // (6th Generation)
                              @"iPhone1,1" : @"iPhone",            // (Original)
                              @"iPhone1,2" : @"iPhone",            // (3G)
                              @"iPhone2,1" : @"iPhone",            // (3GS)
                              @"iPad1,1"   : @"iPad",              // (Original)
                              @"iPad2,1"   : @"iPad 2",            //
                              @"iPad3,1"   : @"iPad",              // (3rd Generation)
                              @"iPhone3,1" : @"iPhone 4",          // (GSM)
                              @"iPhone3,3" : @"iPhone 4",          // (CDMA/Verizon/Sprint)
                              @"iPhone4,1" : @"iPhone 4S",         //
                              @"iPhone5,1" : @"iPhone 5",          // (model A1428, AT&T/Canada)
                              @"iPhone5,2" : @"iPhone 5",          // (model A1429, everything else)
                              @"iPad3,4"   : @"iPad",              // (4th Generation)
                              @"iPad2,5"   : @"iPad Mini",         // (Original)
                              @"iPhone5,3" : @"iPhone 5c",         // (model A1456, A1532 | GSM)
                              @"iPhone5,4" : @"iPhone 5c",         // (model A1507, A1516, A1526 (China), A1529 | Global)
                              @"iPhone6,1" : @"iPhone 5s",         // (model A1433, A1533 | GSM)
                              @"iPhone6,2" : @"iPhone 5s",         // (model A1457, A1518, A1528 (China), A1530 | Global)
                              @"iPhone7,1" : @"iPhone 6 Plus",     //
                              @"iPhone7,2" : @"iPhone 6",          //
                              @"iPhone8,1" : @"iPhone 6S",         //
                              @"iPhone8,2" : @"iPhone 6S Plus",    //
                              @"iPhone8,4" : @"iPhone SE",         //
                              @"iPhone9,1" : @"iPhone 7",          //
                              @"iPhone9,3" : @"iPhone 7",          //
                              @"iPhone9,2" : @"iPhone 7 Plus",     //
                              @"iPhone9,4" : @"iPhone 7 Plus",     //
                              @"iPhone10,1": @"iPhone 8",          // CDMA
                              @"iPhone10,4": @"iPhone 8",          // GSM
                              @"iPhone10,2": @"iPhone 8 Plus",     // CDMA
                              @"iPhone10,5": @"iPhone 8 Plus",     // GSM
                              @"iPhone10,3": @"iPhone X",          // CDMA
                              @"iPhone10,6": @"iPhone X",          // GSM
                              @"iPhone11,2": @"iPhone XS",         //
                              @"iPhone11,4": @"iPhone XS Max",     //
                              @"iPhone11,6": @"iPhone XS Max",     // China
                              @"iPhone11,8": @"iPhone XR",         //
                              @"iPhone12,1": @"iPhone 11",         //
                              @"iPhone12,3": @"iPhone 11 Pro",     //
                              @"iPhone12,5": @"iPhone 11 Pro Max", //
                              
                              @"iPad4,1"   : @"iPad Air",          // 5th Generation iPad (iPad Air) - Wifi
                              @"iPad4,2"   : @"iPad Air",          // 5th Generation iPad (iPad Air) - Cellular
                              @"iPad4,4"   : @"iPad Mini",         // (2nd Generation iPad Mini - Wifi)
                              @"iPad4,5"   : @"iPad Mini",         // (2nd Generation iPad Mini - Cellular)
                              @"iPad4,7"   : @"iPad Mini",         // (3rd Generation iPad Mini - Wifi (model A1599))
                              @"iPad6,7"   : @"iPad Pro (12.9\")", // iPad Pro 12.9 inches - (model A1584)
                              @"iPad6,8"   : @"iPad Pro (12.9\")", // iPad Pro 12.9 inches - (model A1652)
                              @"iPad6,3"   : @"iPad Pro (9.7\")",  // iPad Pro 9.7 inches - (model A1673)
                              @"iPad6,4"   : @"iPad Pro (9.7\")"   // iPad Pro 9.7 inches - (models A1674 and A1675)
        };
    }
    NSString* deviceName = [deviceNamesByCode objectForKey:code];
    if (!deviceName) {
        // Not found on database. At least guess main device type from string contents:
        
        if ([code rangeOfString:@"iPod"].location != NSNotFound) {
            deviceName = @"iPod Touch";
        }
        else if([code rangeOfString:@"iPad"].location != NSNotFound) {
            deviceName = @"iPad";
        }
        else if([code rangeOfString:@"iPhone"].location != NSNotFound){
            deviceName = @"iPhone";
        }
        else {
            deviceName = @"Unknown";
        }
    }
    _cur_deviceModel = strdup([deviceName UTF8String]);
    return _cur_deviceModel;
}


#pragma mark --- Hardcoded values

// HARDCODED addresses used in kernel
uint64_t HARDCODED_infoleak_addr = 0; // vtable of IOSurface
uint64_t HARDCODED_allproc = 0; // via IDA search pgrp_add : pgrp is dead adding process
uint64_t HARDCODED_kernel_map = 0; // via jtool2

// HARDCODED offsets used in kernel
uint32_t OFFSET_bsd_info_pid = 0x68; // +0x68:  bsd_info->pid
uint32_t OFFSET_bsd_info_task = 0x10; // +0x10:  bsd_info->task
uint32_t OFFSET_task_itk_task_access = 0x2F8; // +0x2F8:  task->itk_task_access (ios13.x)
uint32_t OFFSET_task_itk_registered = 0x308; // +0x308:  task->itk_registered (ios13.x)
uint32_t OFFSET_task_t_flags; // for TF_PLATFORM Patch

// HARDCODED zone index used in kernel
uint32_t zone_index_ipc_ports = 42;
uint32_t zone_index_tasks = 58;

// --- following addr/offsets are post-exp

// HARDCODED addresses used in kernel for remount rootFS
uint64_t HARDCODED_jnodehash_mask = 0;
uint64_t HARDCODED_jjnodehashtbl = 0;
uint32_t OFFSET_bsd_info_p_fd = 0x108; // pac: 0x108
uint32_t OFFSET_fileproc_f_fglob = 0x10; // pac: 0x10 // for use of find_vnode_with_path
uint32_t OFFSET_fileglob_fg_data = 0x38; // pac: 0x38 // for use of find_vnode_with_path
uint32_t OFFSET_vnode_v_data = 0xE0; // pac: 0xE0 find the snapshot stru off a vnode, used in patch_snapshot_vnode
uint32_t OFFSET_vnode_v_mount = 0xD8; // pac: 0xD8 // for find the mount structure off a vnode
uint32_t OFFSET_mount_mnt_flag = 0x70; // pac: 0x70 // for remove read-only flag on mount stru

#pragma mark --- Check device

bool check_device_compatibility(){
    extern int Apply_hardcoded_addresses_and_offsets(void);
    
    if(Apply_hardcoded_addresses_and_offsets() == 0)
        return true;
    return false;
}

int Apply_hardcoded_addresses_and_offsets(){
    
    if(!strcmp(get_current_deviceModel(), "iPhone X")){
        int apply_to_iPhone_X(void);
        return apply_to_iPhone_X();
    }
    else if(!strcmp(get_current_deviceModel(), "iPhone 11 Pro Max")){
        int apply_to_iPhone_11_pro_max(void);
        return apply_to_iPhone_11_pro_max();
    }else if(!strcmp(get_current_deviceModel(), "iPhone 7 Plus")){
        int apply_to_iPhone_7_plus(void);
        return apply_to_iPhone_7_plus();
    }
    else if(!strcmp(get_current_deviceModel(), "iPhone XS")){
        int apply_to_iPhone_XS(void);
        return apply_to_iPhone_XS();
    }
    
    
    (printf)("Execution pause: Not found offsets set for current device(model: %s)\n", get_current_deviceModel());
    return -1;
}

#pragma mark --- iPhone X

int apply_to_iPhone_X(){
    
    OFFSET_task_t_flags = 0x3B8; // take from iphoneX 13.2.x, think it remains the same in all non-pac device
    
    if(check_if_iOS_version_greater_than_or_equal_to("13.2") && check_if_iOS_version_less_then("13.3")){
        // iOS 13.2.x on iPhone X
        HARDCODED_infoleak_addr = 0xfffffff007a10fb0;
        HARDCODED_allproc = 0xFFFFFFF0091EAC50;
        HARDCODED_kernel_map = 0xfffffff007905658;
    }
    else if(check_if_iOS_version_equal_to("13.3")){
        // iOS 13.3 on iPhone X
        HARDCODED_infoleak_addr = 0xFFFFFFF007A150D0;
        HARDCODED_allproc = 0xFFFFFFF0091EEC30;
        HARDCODED_kernel_map = 0xfffffff007909658;
        
        HARDCODED_jnodehash_mask = 0xFFFFFFF009225CD4;
        HARDCODED_jjnodehashtbl = 0xFFFFFFF009225CD8;
        
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.3.1") && check_if_iOS_version_less_then("13.3.2")){
        // iOS 13.3.1 on iPhone X
        HARDCODED_infoleak_addr = 0xFFFFFFF007A21150;
        HARDCODED_allproc = 0xFFFFFFF009232C30;
        HARDCODED_kernel_map = 0xfffffff007915658;
        
        HARDCODED_jnodehash_mask = 0xFFFFFFF009269CD4;
        HARDCODED_jjnodehashtbl = 0xFFFFFFF009269CD8;
        
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.4") && check_if_iOS_version_less_then("13.4.2")){
        
        zone_index_tasks = 60;
        
        // iOS 13.4
        HARDCODED_infoleak_addr = 0xFFFFFFF007A5E7D8;
        HARDCODED_allproc = 0xFFFFFFF00926FC60;
        HARDCODED_kernel_map = 0xFFFFFFF00794D6A8;
    }
    else if(check_if_iOS_version_equal_to("13.4.5")){
        
        zone_index_tasks = 60;
        
        // iOS 13.4.5 beta, 后来改名为 13.5 beta
        HARDCODED_infoleak_addr = 0xFFFFFFF007A5E7D8;
        HARDCODED_allproc = 0xFFFFFFF00926FC60;
        HARDCODED_kernel_map = 0xFFFFFFF00794D6A8;
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.5") && check_if_iOS_version_less_then("13.5.2")){
        
        zone_index_tasks = 60;
        
        // iOS 13.5/13.5.1
        HARDCODED_infoleak_addr = 0xFFFFFFF007A427E8;
        HARDCODED_allproc = 0xFFFFFFF0092544B0;
        HARDCODED_kernel_map = 0xfffffff0079316a8;
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.6") && check_if_iOS_version_less_then("13.6.2")){
        
        zone_index_tasks = 60;
        
        // iOS 13.6/13.6.1
        HARDCODED_infoleak_addr = 0xFFFFFFF007A427F8;
        HARDCODED_allproc = 0xFFFFFFF009257AB0;
        HARDCODED_kernel_map = 0xfffffff0079316c0;
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.7") && check_if_iOS_version_less_then("13.7.1")){
        
        zone_index_tasks = 60;
        
        // iOS 13.7
        HARDCODED_infoleak_addr = 0xFFFFFFF007A427F8;
        HARDCODED_allproc = 0xFFFFFFF009257AB0;
        HARDCODED_kernel_map = 0xfffffff0079316c0;
    }
    else{
        printf("Execution pause: require update hardcoded addresses and offsets\n");
        return -1;
    }
    
    return 0;
}

#pragma mark --- iPhone 11 Pro Max

int apply_to_iPhone_11_pro_max(){
    
    OFFSET_task_t_flags = 0x3C0; // confirmed remains the same in iphonexs max(13.1.x ~ 13.3.x)
    
    // zone index changes likely can apply to all PAC device
    zone_index_tasks = 57;
    
    if(check_if_iOS_version_greater_than_or_equal_to("13.3.1") && check_if_iOS_version_less_then("13.3.2")){
        
        // iOS 13.3.1
        HARDCODED_infoleak_addr = 0xFFFFFFF0079F4760;
        HARDCODED_allproc = 0xFFFFFFF00945C940;
        HARDCODED_kernel_map = 0xfffffff0078d1768;
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.4") && check_if_iOS_version_less_then("13.4.2")){
        
        zone_index_tasks = 59;
        
        // iOS 13.4
        HARDCODED_infoleak_addr = 0xFFFFFFF007A30C78;
        HARDCODED_allproc = 0xFFFFFFF0094A5970;
        HARDCODED_kernel_map = 0xFFFFFFF007909678;
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.5") && check_if_iOS_version_less_then("13.5.2")){
        
        zone_index_tasks = 59;
        
        // iOS 13.5/13.5.1
        HARDCODED_infoleak_addr = 0xFFFFFFF007A10C88;
        HARDCODED_allproc = 0xFFFFFFF0094821C0;
        HARDCODED_kernel_map = 0xfffffff0078e9678;
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.6") && check_if_iOS_version_less_then("13.6.2")){
        
        zone_index_tasks = 59;
        
        // iOS 13.6/13.6.1
        HARDCODED_infoleak_addr = 0xFFFFFFF007A18C98;
        HARDCODED_allproc = 0xFFFFFFF009481800;
        HARDCODED_kernel_map = 0xfffffff0078f1690;
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.7") && check_if_iOS_version_less_then("13.7.1")){
        zone_index_tasks = 59;
        
        // iOS 13.7
        HARDCODED_infoleak_addr = 0xFFFFFFF007A18C98;
        HARDCODED_allproc = 0xFFFFFFF009481800;
        HARDCODED_kernel_map = 0xfffffff0078f1690;
    }
    else{
        printf("Execution pause: require update hardcoded addresses and offsets\n");
        return -1;
    }
    
    return 0;
}

int apply_to_iPhone_7_plus(){
    
    OFFSET_task_t_flags = 0x3B8; // confirmed remains the same in iphonexs max(13.1.x ~ 13.3.x)
    
    // zone index changes likely can apply to all PAC device
    zone_index_tasks = 58;
    
    if(check_if_iOS_version_greater_than_or_equal_to("13.3.1") && check_if_iOS_version_less_then("13.3.2")){
        
        // iOS 13.3.1
        HARDCODED_infoleak_addr = 0xfffffff006dc4f38;
        HARDCODED_allproc = 0xFFFFFFF007767860;
        HARDCODED_kernel_map = 0xfffffff0070d0aa8;
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.6") && check_if_iOS_version_less_then("13.6.2")){
         
        // iOS 13.6/13.6.1
        HARDCODED_infoleak_addr = 0xFFFFFFF006DBCEF8;
        HARDCODED_allproc = 0xFFFFFFF007770FA0;
        HARDCODED_kernel_map = 0xFFFFFFF0070D0A90;
    }
    else{
        printf("Execution pause: require update hardcoded addresses and offsets\n");
        return -1;
    }
    
    return 0;
}

int apply_to_iPhone_XS(){
    
    OFFSET_task_t_flags = 0x3C0;
    
    // zone index changes likely can apply to all PAC device
    zone_index_tasks = 57;
    
    if(check_if_iOS_version_greater_than_or_equal_to("13.5") && check_if_iOS_version_less_then("13.5.2")){
        
        zone_index_tasks = 59;
        
        // iOS 13.5/13.5.1
        HARDCODED_infoleak_addr = 0xFFFFFFF007917A18;
        HARDCODED_allproc = 0xFFFFFFF0093AB1B0;
        HARDCODED_kernel_map = 0xfffffff00789d678;
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.6") && check_if_iOS_version_less_then("13.6.2")){
        
        zone_index_tasks = 59;
        
        // iOS 13.6/13.6.1
        HARDCODED_infoleak_addr = 0xFFFFFFF00791FA18;
        HARDCODED_allproc = 0xFFFFFFF0093AA7F0;
        HARDCODED_kernel_map = 0xfffffff0078a5690;
    }
    else if(check_if_iOS_version_greater_than_or_equal_to("13.7") && check_if_iOS_version_less_then("13.7.1")){
        zone_index_tasks = 59;
        
        // iOS 13.7
        HARDCODED_infoleak_addr = 0xFFFFFFF00791FA18;
        HARDCODED_allproc = 0xFFFFFFF0093AA7F0;
        HARDCODED_kernel_map = 0xfffffff0078a5690;
    }
    else{
        printf("Execution pause: require update hardcoded addresses and offsets\n");
        return -1;
    }
    
    return 0;
}
