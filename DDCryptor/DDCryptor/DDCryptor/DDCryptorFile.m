//
//  DDCryptorFile.m
//  DDCryptor
//
//  Created by longxdragon on 2017/8/14.
//  Copyright © 2017年 longxdragon. All rights reserved.
//

#import "DDCryptorFile.h"

@implementation DDCryptorFile

+ (NSString *)cryptorDir {
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject];
    NSString *dir = [path stringByAppendingPathComponent:@".dd_openssl_rsa"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dir]) {
        [fm createDirectoryAtPath:dir
      withIntermediateDirectories:YES
                       attributes:NULL
                            error:nil];
    }
    return dir;
}

+ (NSString *)rsaPublicKeyFile {
    NSString *file = [[self cryptorDir] stringByAppendingPathComponent:@"dd.publicKey.pem"];
    
    return file;
}

+ (NSString *)rsaPrivateKeyFile {
    NSString *file = [[self cryptorDir] stringByAppendingPathComponent:@"dd.privateKey.pem"];
    
    return file;
}

@end
