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

static NSString *testStr = @"Test RSA encrypt! \
的家都没拿绿卡是没电了凯撒的拉伸快没电了萨马德里马萨、、 &&&bd o=.de'dan c [dl;as,;\
dmaskmdkasmdkc jadjknsjkdnandkasmdlkadksamdlkasmdkamkk////damskdmaksdakmsd\
dansk cmkamndksamdapdmasldkjpoasmd;lamsdpoasnclas mcpxkasodmksamd;alsm";

static NSString *RSAPublicKey = @"\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjUkIp7TayQdAQqe7w9LF2zTfE\
u0aGeDpxxy0JCfTIE5nyqFleRaSnNzaGxc44BrYNKzU6chlAPzNuf/Zm6OwcK3Q0\
5bWxPpams5NmBEGZv0HHNAPSuxId97V9fQ3ThhQNEBqOLzQbj/UvgSs4O6fxfM+0\
zSf9pRjOTxoF+tCHywIDAQAB";
static NSString *RSAPrivateKey = @"\
MIICXgIBAAKBgQCjUkIp7TayQdAQqe7w9LF2zTfEu0aGeDpxxy0JCfTIE5nyqFle\
RaSnNzaGxc44BrYNKzU6chlAPzNuf/Zm6OwcK3Q05bWxPpams5NmBEGZv0HHNAPS\
uxId97V9fQ3ThhQNEBqOLzQbj/UvgSs4O6fxfM+0zSf9pRjOTxoF+tCHywIDAQAB\
AoGALzbejcRX5ZyFC+w0eVAj5ZZaIvOI5eLn8nCEInLQYu7XuIDWpRw5B2Y8yyVw\
Al5eTtxI3QaTKjGbKryvfPylFODWgxmAT2+L8k7OYTdi0GhlHhABV0Z7/5CbRf5/\
7QLUd3j2mawNaKfNjKioQc2Zi3RaJaSAMpaHjBdiB7H/EhECQQDi0vMED6ykuw+M\
KOYPy2Gu6yn6g9irZzAQV12JdSCv1x5z9YUyD20ZWj90ayxuOzE2puui7x7bQUH2\
ai/9rI9NAkEAuFQ9QpeZ9y47elEfsq8+J6qnNVijqtLDJLODWXqL1K170abL7rKh\
QlZzw0k92me8wybJPLxh2IqTMrBxYKIXdwJBAMrlBaqpVrZX+dVXNEwGko+EHh3P\
2H2iJPVJIQt3MVD5bW0uvwGDmQSnnMFHqQvFeQU5FOi/WuunmRiR7fHNbLUCQQCj\
zvD1+gXwvZxL0kYqJERHOggIh3JDf7O+LO3AmgAkC9wqb2FyCjr22h9cX/1g16nP\
f+t8VylZJ6Uyecz4BHR3AkEApO/6wYCcK/2T/n4EH+auyCOjKPnN+6ZOOZH5wjd9\
01clooxoqNaOFTK50TSHQL3QeTNH3TVmuKe2rVDim94FcA==";

static NSString *ThreeDESKey = @"lPrzT8BMoJt2dUSslfwn3Vkl";
static NSString *DESKey = @"lPrzT8BMoJt2dUSslfwn3Vkl";

- (void)testRSAEncrypt {
    NSString *encrypt = [testStr dd_rsaEncryptWithPublicKey:RSAPublicKey padding:DD_RSA_PADDING_TYPE_PKCS1];
    XCTAssertNotNil(encrypt, @"rsa fail");
    NSString *decrypt = [encrypt dd_rsaDecryptWithPrivateKey:RSAPrivateKey padding:DD_RSA_PADDING_TYPE_PKCS1];
    XCTAssertNotNil(decrypt, @"rsa fail");
    XCTAssertTrue([decrypt isEqualToString:testStr], @"rsa fail");
}

- (void)test3DESCrypt {
    NSString *encrypt = [testStr dd_3desEncryptWithKey:ThreeDESKey];
    XCTAssertNotNil(encrypt, @"decry fail");
    NSString *decrypt = [encrypt dd_3desDecryptWithKey:ThreeDESKey];
    XCTAssertNotNil(decrypt, @"decry fail");
    XCTAssertTrue([decrypt isEqualToString:testStr], @"decry fail");
}

- (void)testDESCrypt {
    NSString *encrypt = [testStr dd_desEncryptWithKey:DESKey];
    XCTAssertNotNil(encrypt, @"decry fail");
    NSString *decrypt = [encrypt dd_desDecryptWithKey:DESKey];
    XCTAssertNotNil(decrypt, @"decry fail");
    XCTAssertTrue([decrypt isEqualToString:testStr], @"decry fail");
}

- (void)testMD5 {
    NSString *str = @"40D9CD8AF69C030929C5AA30F1DC8BDE";
    NSString *result = [testStr dd_md5];
    XCTAssertNotNil(result, @"fail");
    XCTAssertTrue([result isEqualToString:str], @"fail");
}

@end
