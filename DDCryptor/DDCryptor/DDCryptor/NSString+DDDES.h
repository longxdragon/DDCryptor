//
//  NSString+DDDES.h
//  DDCryptor
//
//  Created by longxdragon on 2018/3/5.
//  Copyright © 2018年 longxdragon. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (DDDES)

// 3DES encrypt
- (NSString *)dd_3desEncryptWithKey:(NSString *)key;
- (NSString *)dd_3desEncryptWithKey:(NSString *)key iv:(NSString *)iv;

// 3DES decrypt
- (NSString *)dd_3desDecryptWithKey:(NSString *)key;
- (NSString *)dd_3desDecryptWithKey:(NSString *)key iv:(NSString *)iv;

// DES encrypt
- (NSString *)dd_desEncryptWithKey:(NSString *)key;
- (NSString *)dd_desEncryptWithKey:(NSString *)key iv:(NSString *)iv;

// DES decrypt
- (NSString *)dd_desDecryptWithKey:(NSString *)key;
- (NSString *)dd_desDecryptWithKey:(NSString *)key iv:(NSString *)iv;

@end
