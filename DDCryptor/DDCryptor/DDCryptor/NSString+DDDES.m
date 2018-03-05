//
//  NSString+DDDES.m
//  DDCryptor
//
//  Created by longxdragon on 2018/3/5.
//  Copyright © 2018年 longxdragon. All rights reserved.
//

#import "NSString+DDDES.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <GTMBase64/GTMBase64.h>

@implementation NSString (DDDES)

static NSString *kDDDESGIV = @"dd.com.des";

- (NSData *)_dd_3desCryptWithKey:(NSString *)key data:(NSData *)data isEncrypt:(BOOL)isEncrypt {
    const char *cstr = [key cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [NSData dataWithBytes:cstr length:key.length];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(keyData.bytes, (int)keyData.length, digest);
    
    size_t plainTextBufferSize = [data length];
    const void *vplainText = (const void *)[data bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *vkey = (const void *) [key UTF8String];
    const void *vinitVec = (const void *) [kDDDESGIV UTF8String];

    ccStatus = CCCrypt(isEncrypt ? kCCEncrypt : kCCDecrypt,
                       kCCAlgorithm3DES,
                       kCCOptionPKCS7Padding,
                       vkey,
                       kCCKeySize3DES,
                       vinitVec,
                       vplainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    
    NSData *resultData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
    free((void *)bufferPtr);
    
    return resultData;
}

#pragma mark - Public

- (NSString *)dd_3desEncryptWithKey:(NSString *)key {
    if (!key || key.length == 0) {
        return nil;
    }
    
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    NSData *resultData = [self _dd_3desCryptWithKey:key data:data isEncrypt:YES];
    NSString *result = [GTMBase64 stringByEncodingData:resultData];
    
    return result;
}

- (NSString *)dd_3desDecryptWithKey:(NSString *)key {
    if (!key || key.length == 0) {
        return nil;
    }
    
    NSData *data = [GTMBase64 decodeData:[self dataUsingEncoding:NSUTF8StringEncoding]];
    NSData *resultData = [self _dd_3desCryptWithKey:key data:data isEncrypt:NO];
    NSString *result = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    
    return result;
}

@end
