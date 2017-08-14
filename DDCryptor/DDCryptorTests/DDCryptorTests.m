//
//  DDCryptorTests.m
//  DDCryptorTests
//
//  Created by longxdragon on 2017/8/10.
//  Copyright © 2017年 longxdragon. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "DDCryptor.h"

@interface DDCryptorTests : XCTestCase

@end

@implementation DDCryptorTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)testRSAEncrypt {
    NSString *str = @"Test RSA encrypt! 的家都没拿绿卡是没电了凯撒的拉伸快没电了萨马德里马萨、、 &&&bd o=.de'dan c [dl;as,;dmaskmdkasmdkc jadjknsjkdnandkasmdlkadksamdlkasmdkamkk////damskdmaksdakmsddansk cmkamndksamdapdmasldkjpoasmd;lamsdpoasnclas mcpxkasodmksamd;alsm";
    NSString *publicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsfEjWk0jIPOqrfD943VzyGN0Z8SD3B1Fb8gL67bNo+epQaE6TqlP3j7exFdNdfgGwmFe/uX2m3HfDjjxShC8O5E3iuBwk8HECHO6+FeNZfhlJQqJ53YK39K2u1Bjuv325ZJllYea4NeqkrX4WkbSX7igys05Ziof9tmR2dQTcCwIDAQAB";
    
    NSString *result = [str dd_rsaEncryptWithPublicKey:publicKey
                                               padding:DD_RSA_PADDING_TYPE_PKCS1];
    
    XCTAssertNotNil(result, @"encrypt fail");
}

@end
