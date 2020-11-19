//
//  ios_7st_utils.c
//  ios_7st_test
//
//  Created by bb on 12/26/19.
//  Copyright © 2019 bb. All rights reserved.
//

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
#include <dirent.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <spawn.h>
#import <Foundation/Foundation.h>

#define RAWLOG(str, args...) do { printf("%s\n", [[NSString stringWithFormat:CFSTR(str), ##args] UTF8String]); } while(false)
//#define RAWLOG(str, args...) do { writetofile([NSString stringWithFormat:CFSTR(str), ##args]); } while(false)

/*extern char *itunes_export_path;
void writetofile(NSString *str){
    NSString *oldstr = [NSString stringWithContentsOfFile:[NSString stringWithUTF8String:itunes_export_path] encoding:NSUTF8StringEncoding error:nil];
    if(oldstr){
        oldstr = [oldstr stringByAppendingString:@"\n"];
        oldstr = [oldstr stringByAppendingString:str];
    }
    else{
        oldstr = str;
    }
    [oldstr writeToFile:[NSString stringWithUTF8String:itunes_export_path] atomically:YES encoding:NSUTF8StringEncoding error:nil];
}*/

#define LOG(str, args...) RAWLOG("[*] " str, ##args)

extern char **environ;
NSData *lastSystemOutput=nil;

int runCommandv(const char *cmd, int argc, const char * const* argv, void (^unrestrict)(pid_t)) {
    pid_t pid;
    posix_spawn_file_actions_t *actions = NULL;
    posix_spawn_file_actions_t actionsStruct;
    int out_pipe[2];
    bool valid_pipe = false;
    posix_spawnattr_t *attr = NULL;
    posix_spawnattr_t attrStruct;
    
    NSMutableString *cmdstr = [NSMutableString stringWithCString:cmd encoding:NSUTF8StringEncoding];
    for (int i=1; i<argc; i++) {
        [cmdstr appendFormat:@" \"%s\"", argv[i]];
    }
    
    valid_pipe = pipe(out_pipe) == ERR_SUCCESS;
    if (valid_pipe && posix_spawn_file_actions_init(&actionsStruct) == ERR_SUCCESS) {
        actions = &actionsStruct;
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 1);
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 2);
        posix_spawn_file_actions_addclose(actions, out_pipe[0]);
        posix_spawn_file_actions_addclose(actions, out_pipe[1]);
    }
    
    if (unrestrict && posix_spawnattr_init(&attrStruct) == ERR_SUCCESS) {
        attr = &attrStruct;
        posix_spawnattr_setflags(attr, POSIX_SPAWN_START_SUSPENDED);
    }
    
    int rv = posix_spawn(&pid, cmd, actions, attr, (char *const *)argv, environ);
    LOG("%s(%d) command: %@", __FUNCTION__, pid, cmdstr);
    
    if (unrestrict) {
        unrestrict(pid);
        kill(pid, SIGCONT);
    }
    
    if (valid_pipe) {
        close(out_pipe[1]);
    }
    
    if (rv == ERR_SUCCESS) {
        if (valid_pipe) {
            NSMutableData *outData = [NSMutableData new];
            char c;
            char s[2] = {0, 0};
            NSMutableString *line = [NSMutableString new];
            while (read(out_pipe[0], &c, 1) == 1) {
                [outData appendBytes:&c length:1];
                if (c == '\n') {
                    LOG("%s(%d): %@", __FUNCTION__, pid, line);
                    [line setString:@""];
                } else {
                    s[0] = c;
                    [line appendString:@(s)];
                }
            }
            if ([line length] > 0) {
                LOG("%s(%d): %@", __FUNCTION__, pid, line);
            }
            lastSystemOutput = [outData copy];
        }
        if (waitpid(pid, &rv, 0) == -1) {
            LOG("ERROR: Waitpid failed");
        } else {
            LOG("%s(%d) completed with exit status %d", __FUNCTION__, pid, WEXITSTATUS(rv));
        }
        
    } else {
        LOG("%s(%d): ERROR posix_spawn failed (%d): %s", __FUNCTION__, pid, rv, strerror(rv));
        rv <<= 8; // Put error into WEXITSTATUS
    }
    if (valid_pipe) {
        close(out_pipe[0]);
    }
    return rv;
}

int runCommand(const char *cmd, ...) {
    va_list ap, ap2;
    int argc = 1;
    
    va_start(ap, cmd);
    va_copy(ap2, ap);
    
    while (va_arg(ap, const char *) != NULL) {
        argc++;
    }
    va_end(ap);
    
    const char *argv[argc+1];
    argv[0] = cmd;
    for (int i=1; i<argc; i++) {
        argv[i] = va_arg(ap2, const char *);
    }
    va_end(ap2);
    argv[argc] = NULL;
    
    int rv = runCommandv(cmd, argc, argv, NULL);
    return WEXITSTATUS(rv);
}

