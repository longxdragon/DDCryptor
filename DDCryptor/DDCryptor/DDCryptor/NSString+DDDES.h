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

// 3DES decrypt
- (NSString *)dd_3desDecryptWithKey:(NSString *)key;

// DES encrypt
- (NSString *)dd_desEncryptWithKey:(NSString *)key;

// DES decrypt
- (NSString *)dd_desDecryptWithKey:(NSString *)key;

@end
