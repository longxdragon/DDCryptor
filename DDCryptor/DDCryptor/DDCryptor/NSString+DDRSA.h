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

// Public Encrypt with public key, padding is DD_RSA_PADDING_TYPE_PKCS1
- (NSString *)dd_rsaEncryptWithPublicKey:(NSString *)publicKey;

// Public Encrypt with public key and padding
- (NSString *)dd_rsaEncryptWithPublicKey:(NSString *)publicKey padding:(DD_RSA_PADDING_TYPE)padding;

// Public Encrypt with path of public pem file, padding is DD_RSA_PADDING_TYPE_PKCS1
- (NSString *)dd_rsaEncryptWithPublicKeyPath:(NSString *)path;

// Public Encrypt with path of public pem file and padding
- (NSString *)dd_rsaEncryptWithPublicKeyPath:(NSString *)path padding:(DD_RSA_PADDING_TYPE)padding;

// Private Decrypt with private key, padding is DD_RSA_PADDING_TYPE_PKCS1
- (NSString *)dd_rsaDecryptWithPrivateKey:(NSString *)privateKey;

// Private Decrypt with private key
- (NSString *)dd_rsaDecryptWithPrivateKey:(NSString *)privateKey padding:(DD_RSA_PADDING_TYPE)padding;

// Private Decrypt with path of private pem file, padding is DD_RSA_PADDING_TYPE_PKCS1
- (NSString *)dd_rsaDecryptWithPrivateKeyPath:(NSString *)path;

// Private Decrypt with path of private pem file and padding
- (NSString *)dd_rsaDecryptWithPrivateKeyPath:(NSString *)path padding:(DD_RSA_PADDING_TYPE)padding;

@end
