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

- (NSString *)dd_rsaEncryptWithPublicKey:(NSString *)publicKey
                                 padding:(DD_RSA_PADDING_TYPE)padding {
    // 格式化公钥
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
    BOOL success = [result writeToFile:[DDCryptorFile rsaPublicKeyFile]
                            atomically:YES
                              encoding:NSASCIIStringEncoding
                                 error:&error];
    if (!success) {
        NSLog(@"rsa: write public key error. %@", error);
    }
    
    // 取公钥
    NSString *path = [DDCryptorFile rsaPublicKeyFile];
    FILE *pubkey = fopen([path cStringUsingEncoding:1], "rb");
    if (pubkey == NULL) {
        NSLog(@"duh: %@", [path stringByAppendingString:@" not found"]);
        return NULL;
    }
    RSA *rsa = PEM_read_RSA_PUBKEY(pubkey, NULL, NULL, NULL);
    fclose(pubkey);
    if (rsa == NULL) {
        NSLog(@"Error reading RSA public key.");
        return NULL;
    }
    
    NSData *plainData = [self dataUsingEncoding:NSUTF8StringEncoding];
    if ([plainData length] == 0) {
        NSLog(@"Error input data.");
        RSA_free(rsa);
        return NULL;
    }
    
    int len = (int)[plainData length];
    int clen = RSA_size(rsa);
    int blocklen = clen - 11;
    int blockCount = (int)ceil((double)len/blocklen);
    
    NSMutableData *mutableData = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        int loc = i * blocklen;
        int reallen = MIN(blocklen, len - loc);
        NSData *segmentData = [plainData subdataWithRange:NSMakeRange(loc, reallen)];
        
        unsigned char *cipherBuffer = calloc(clen, sizeof(unsigned char));
        unsigned char *segmentBuffer = (unsigned char *)[segmentData bytes];
        int result = RSA_public_encrypt(reallen, segmentBuffer, cipherBuffer, rsa,  padding);
        if (result == -1) {
            return NULL;
        }
        NSData *cipherData = [[NSData alloc] initWithBytes:cipherBuffer length:clen];
        if (cipherData) {
            [mutableData appendData:cipherData];
        }
        
        free(cipherBuffer);
    }
    RSA_free(rsa);
    
    // Base64
    NSString *encryptedString = [GTMBase64 stringByEncodingData:[mutableData copy]];
    
    return [encryptedString copy];
}

@end
