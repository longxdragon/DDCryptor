//
//  NSString+DDDES.h
//  DDCryptor
//
//  Created by longxdragon on 2018/3/5.
//  Copyright © 2018年 longxdragon. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (DDDES)

- (NSString *)dd_3desEncryptWithKey:(NSString *)key;
- (NSString *)dd_3desDecryptWithKey:(NSString *)key;

@end
