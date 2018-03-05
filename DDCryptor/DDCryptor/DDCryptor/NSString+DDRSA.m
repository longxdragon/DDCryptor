//
//  NSString+DDRSA.m
//  DDCryptor
//
//  Created by longxdragon on 2017/8/14.
//  Copyright © 2017年 longxdragon. All rights reserved.
//

#import "NSString+DDRSA.h"
#import "DDCryptorFile.h"

@implementation NSString (DDRSA)

// 格式化公钥
// 因为公钥是以字符串的形式传入的，所以需要先把字符串存入到本地pem文件
- (BOOL)_localFormatWithPublicKey:(NSString *)publicKey path:(NSString *)path {
    if (!publicKey || publicKey.length == 0 || path.length == 0) {
        return NO;
    }
    
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
    int count = 0;
    for (int i = 0; i < [publicKey length]; ++i) {
        unichar c = [publicKey characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == 64) {
            [result appendString:@"\n"];
            count = 0;
        }
    }
    [result appendString:@"\n-----END PUBLIC KEY-----"];
    
    NSError *error = nil;
    BOOL success = [result writeToFile:path
                            atomically:YES
                              encoding:NSASCIIStringEncoding
                                 error:&error];
    if (!success) {
        NSLog(@"rsa: write public key error. %@", error);
    }
    return success;
}

// 格式化私钥
- (BOOL)_localFormatWithPrivateKey:(NSString *)privateKey path:(NSString *)path {
    if (!privateKey || privateKey.length == 0 || path.length == 0) {
        return NO;
    }
    
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN RSA PRIVATE KEY-----\n"];
    int count = 0;
    for (int i = 0; i < [privateKey length]; ++i) {
        unichar c = [privateKey characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == 64) {
            [result appendString:@"\n"];
            count = 0;
        }
    }
    [result appendString:@"\n-----END RSA PRIVATE KEY-----"];
    
    NSError *error = nil;
    BOOL success = [result writeToFile:path
                            atomically:YES
                              encoding:NSASCIIStringEncoding
                                 error:&error];
    if (!success) {
        NSLog(@"rsa: write private key error. %@", error);
    }
    return success;
}

// 利用OpenSSl库读取本地pem文件形式的公钥
- (RSA *)_rsaFromLocalKeyPath:(NSString *)path {
    FILE *pubkey = fopen([path cStringUsingEncoding:1], "rb");
    if (pubkey == NULL) {
        NSLog(@"duh: %@", [path stringByAppendingString:@" not found"]);
        return nil;
    }
    
    RSA *rsa = PEM_read_RSA_PUBKEY(pubkey, NULL, NULL, NULL);
    fclose(pubkey);
    if (rsa == NULL) {
        NSLog(@"Error reading RSA public key.");
        return nil;
    }
    
    return rsa;
}

// RSA 操作
// 私钥加密、私钥解密、公钥加密、公钥解密
- (NSData *)_rsaCryptWithRSA:(RSA *)rsa plainData:(NSData *)plainData padding:(DD_RSA_PADDING_TYPE)padding isEncrypt:(BOOL)isEncrypt {
    if (!rsa) {
        return nil;
    }
    if ([plainData length] == 0) {
        NSLog(@"Error input data.");
        return nil;
    }
    
    int len = (int)[plainData length];
    int clen = RSA_size(rsa);
    int blocklen = clen - 11;
    int blockCount = (int)ceil((double)len/blocklen);
    
    // RSA加密是有长度限制，支持分段加密
    NSMutableData *mutableData = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        int loc = i * blocklen;
        int reallen = MIN(blocklen, len - loc);
        NSData *segmentData = [plainData subdataWithRange:NSMakeRange(loc, reallen)];
        
        unsigned char *cipherBuffer = calloc(clen, sizeof(unsigned char));
        unsigned char *segmentBuffer = (unsigned char *)[segmentData bytes];
        int result = -1;
        if (isEncrypt) {
            result = RSA_public_encrypt(reallen, segmentBuffer, cipherBuffer, rsa, padding);
        } else {
            result = RSA_public_decrypt(reallen, segmentBuffer, cipherBuffer, rsa,  padding);
        }
        if (result == -1) {
            return nil;
        }
        
        NSData *cipherData = [[NSData alloc] initWithBytes:cipherBuffer length:clen];
        if (cipherData) {
            [mutableData appendData:cipherData];
        }
        
        free(cipherBuffer);
    }
    return [mutableData copy];
}

#pragma mark - Public

// RSA + Base64
- (NSString *)dd_rsaEncryptWithPublicKey:(NSString *)publicKey padding:(DD_RSA_PADDING_TYPE)padding {
    NSString *path = [DDCryptorFile rsaPublicKeyFile];
    if (![self _localFormatWithPublicKey:publicKey path:path]) {
        return nil;
    }
    NSString *result = [self dd_rsaEncryptWithPublicKeyPath:path padding:padding];
    return result;
}

- (NSString *)dd_rsaEncryptWithPublicKeyPath:(NSString *)path padding:(DD_RSA_PADDING_TYPE)padding {
    if (!path || path.length == 0) {
        return nil;
    }
    
    NSData *plainData = [self dataUsingEncoding:NSUTF8StringEncoding];
    RSA *rsa = [self _rsaFromLocalKeyPath:path];
    NSData *resultData = [self _rsaCryptWithRSA:rsa plainData:plainData padding:padding isEncrypt:YES];
    RSA_free(rsa);
    
    NSString *result = [GTMBase64 stringByEncodingData:resultData];
    return result;
}

// Base64 + RSA
- (NSString *)dd_rsaDecryptWithPublicKey:(NSString *)publicKey padding:(DD_RSA_PADDING_TYPE)padding {
    NSString *path = [DDCryptorFile rsaPublicKeyFile];
    if (![self _localFormatWithPublicKey:publicKey path:path]) {
        return nil;
    }
    NSString *result = [self dd_rsaDecryptWithPublicKeyPath:path padding:padding];
    return result;
}

- (NSString *)dd_rsaDecryptWithPublicKeyPath:(NSString *)path padding:(DD_RSA_PADDING_TYPE)padding {
    if (!path || path.length == 0) {
        return nil;
    }
    
    NSData *plainData = [GTMBase64 decodeData:[self dataUsingEncoding:NSUTF8StringEncoding]];
    RSA *rsa = [self _rsaFromLocalKeyPath:path];
    NSData *resultData = [self _rsaCryptWithRSA:rsa plainData:plainData padding:padding isEncrypt:NO];
    RSA_free(rsa);
    
    NSString *result = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    return result;
}

// Private Encrypt
- (NSString *)dd_rsaEncryptWithPrivateKey:(NSString *)privateKey padding:(DD_RSA_PADDING_TYPE)padding {
    NSString *path = [DDCryptorFile rsaPrivateKeyFile];
    if (![self _localFormatWithPrivateKey:privateKey path:path]) {
        return nil;
    }
    NSString *result = [self dd_rsaEncryptWithPrivateKeyPath:path padding:padding];
    return result;
}

- (NSString *)dd_rsaEncryptWithPrivateKeyPath:(NSString *)path padding:(DD_RSA_PADDING_TYPE)padding {
    if (!path || path.length == 0) {
        return nil;
    }
    
    NSData *plainData = [self dataUsingEncoding:NSUTF8StringEncoding];
    RSA *rsa = [self _rsaFromLocalKeyPath:path];
    NSData *resultData = [self _rsaCryptWithRSA:rsa plainData:plainData padding:padding isEncrypt:YES];
    RSA_free(rsa);
    
    NSString *result = [GTMBase64 stringByEncodingData:resultData];
    return result;
}

// Private Decrypt
- (NSString *)dd_rsaDecryptWithPrivateKey:(NSString *)privateKey padding:(DD_RSA_PADDING_TYPE)padding {
    NSString *path = [DDCryptorFile rsaPrivateKeyFile];
    if (![self _localFormatWithPrivateKey:privateKey path:path]) {
        return nil;
    }
    NSString *result = [self dd_rsaDecryptWithPrivateKeyPath:path padding:padding];
    return result;
}

- (NSString *)dd_rsaDecryptWithPrivateKeyPath:(NSString *)path padding:(DD_RSA_PADDING_TYPE)padding {
    if (!path || path.length == 0) {
        return nil;
    }
    
    NSData *plainData = [GTMBase64 decodeData:[self dataUsingEncoding:NSUTF8StringEncoding]];
    RSA *rsa = [self _rsaFromLocalKeyPath:path];
    NSData *resultData = [self _rsaCryptWithRSA:rsa plainData:plainData padding:padding isEncrypt:NO];
    RSA_free(rsa);
    
    NSString *result = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    return result;
}

@end
