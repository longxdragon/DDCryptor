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

typedef NS_ENUM(NSInteger, DDDESType) {
    DDDESType3DES,
    DDDESTypeDES
};

@implementation NSString (DDDES)

static NSString *kDDDESGIV = @"dd.com.des";

- (NSData *)_dd_3desCryptWithKey:(NSString *)key
                            data:(NSData *)data
                       isEncrypt:(BOOL)isEncrypt
                            type:(DDDESType)type
                              iv:(NSString *)iv {
    
    const char *cstr = [key cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [NSData dataWithBytes:cstr length:key.length];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(keyData.bytes, (int)keyData.length, digest);
    
    size_t plainTextBufferSize = [data length];
    const void *vplainText = (const void *)[data bytes];
    
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *vkey = (const void *) [key UTF8String];
    const void *vinitVec = (const void *) [iv UTF8String];
    
    uint32_t operation = kCCEncrypt;
    if (!isEncrypt) {
        operation = kCCDecrypt;
    }
    
    long keySize = kCCKeySize3DES;
    uint32_t algorithm = kCCAlgorithm3DES;
    switch (type) {
        case DDDESType3DES: algorithm = kCCAlgorithm3DES; keySize = kCCKeySize3DES; break;
        case DDDESTypeDES: algorithm = kCCAlgorithmDES; keySize = kCCKeySizeDES; break;
    }
    
    CCCryptorStatus ccStatus = CCCrypt(operation,
                                       algorithm,
                                       kCCOptionPKCS7Padding,
                                       vkey,
                                       keySize,
                                       vinitVec,
                                       vplainText,
                                       plainTextBufferSize,
                                       (void *)bufferPtr,
                                       bufferPtrSize,
                                       &movedBytes);
    if (ccStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
        free((void *)bufferPtr);
        return resultData;
    } else {
        free((void *)bufferPtr);
        return nil;
    }
}

#pragma mark - Public

- (NSString *)dd_3desEncryptWithKey:(NSString *)key {
    return [self dd_3desEncryptWithKey:key iv:kDDDESGIV];
}

- (NSString *)dd_3desEncryptWithKey:(NSString *)key iv:(NSString *)iv {
    if (!key || key.length == 0 || !iv || iv.length == 0) {
        return nil;
    }
    
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    NSData *resultData = [self _dd_3desCryptWithKey:key
                                               data:data
                                          isEncrypt:YES
                                               type:DDDESType3DES
                                                 iv:iv];
    NSString *result = [GTMBase64 stringByEncodingData:resultData];
    
    return result;
}

- (NSString *)dd_3desDecryptWithKey:(NSString *)key {
    return [self dd_3desDecryptWithKey:key iv:kDDDESGIV]
}

- (NSString *)dd_3desDecryptWithKey:(NSString *)key iv:(NSString *)iv {
    if (!key || key.length == 0 || !iv || iv.length == 0) {
        return nil;
    }
    
    NSData *data = [GTMBase64 decodeData:[self dataUsingEncoding:NSUTF8StringEncoding]];
    NSData *resultData = [self _dd_3desCryptWithKey:key
                                               data:data
                                          isEncrypt:NO
                                               type:DDDESType3DES
                                                 iv:iv];
    NSString *result = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    
    return result;
}

- (NSString *)dd_desEncryptWithKey:(NSString *)key {
    return [self dd_desEncryptWithKey:key iv:kDDDESGIV];
}

- (NSString *)dd_desEncryptWithKey:(NSString *)key iv:(NSString *)iv {
    if (!key || key.length == 0 || !iv || iv.length == 0) {
        return nil;
    }
    
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    NSData *resultData = [self _dd_3desCryptWithKey:key
                                               data:data
                                          isEncrypt:YES
                                               type:DDDESTypeDES
                                                 iv:iv];
    NSString *result = [GTMBase64 stringByEncodingData:resultData];
    
    return result;
}

- (NSString *)dd_desDecryptWithKey:(NSString *)key {
    return [self dd_desDecryptWithKey:key iv:kDDDESGIV];
}

- (NSString *)dd_desDecryptWithKey:(NSString *)key iv:(NSString *)iv {
    if (!key || key.length == 0 || !iv || iv.length == 0) {
        return nil;
    }
    
    NSData *data = [GTMBase64 decodeData:[self dataUsingEncoding:NSUTF8StringEncoding]];
    NSData *resultData = [self _dd_3desCryptWithKey:key
                                               data:data
                                          isEncrypt:NO
                                               type:DDDESTypeDES
                                                 iv:iv];
    NSString *result = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    
    return result;
}

@end
