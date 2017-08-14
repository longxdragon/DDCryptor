//
//  NSString+DDRSA.h
//  DDCryptor
//
//  Created by longxdragon on 2017/8/14.
//  Copyright © 2017年 longxdragon. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/rsa.h>
#import <openssl/pem.h>
#import <GTMBase64/GTMBase64.h>

typedef NS_ENUM(NSInteger, DD_RSA_PADDING_TYPE) {
    DD_RSA_PADDING_TYPE_NONE       = RSA_NO_PADDING,
    DD_RSA_PADDING_TYPE_PKCS1      = RSA_PKCS1_PADDING,
    DD_RSA_PADDING_TYPE_SSLV23     = RSA_SSLV23_PADDING
};

typedef NS_ENUM(int, DD_RSA_SIGN_DIGEST_TYPE) {
    DD_RSA_SIGN_DIGEST_TYPE_SHA1 = NID_sha1,
    DD_RSA_SIGN_DIGEST_TYPE_SHA256 = NID_sha256,
    DD_RSA_SIGN_DIGEST_TYPE_SHA384 = NID_sha384,
    DD_RSA_SIGN_DIGEST_TYPE_SHA512 = NID_sha512,
    DD_RSA_SIGN_DIGEST_TYPE_SHA224 = NID_sha224,
    DD_RSA_SIGN_DIGEST_TYPE_MD5 = NID_md5
};


@interface NSString (DDRSA)

- (NSString *)dd_rsaEncryptWithPublicKey:(NSString *)publicKey
                                 padding:(DD_RSA_PADDING_TYPE)padding;

@end
