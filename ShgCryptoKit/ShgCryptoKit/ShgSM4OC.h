//
//  ShgSM4OC.h
//  ShgCryptoKit
//
//  Created by shg on 2020/11/30.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ShgSM4OC : NSObject

/// 国密SM4加密，ECB模式
/// @param aString 需要加密的字符串
/// @param key 加密密钥16位长度
+ (NSData *)sm4EncrytoECB:(NSString *)aString key:(NSString *)key;

/// 国密SM4加密，CBC模式
/// @param aString 需要加密的字符串
/// @param key 加密密钥16位长度
+ (NSData *)sm4EncrytoCBC:(NSString *)aString key:(NSString *)key;

/// 国密SM4解密，ECB模式
/// @param data 需要解密的数据
/// @param key 加密密钥16位长度
+ (NSData *)sm4DecrytoECB:(NSData *)data key:(NSString *)key;

/// 国密SM4解密，CBC模式
/// @param data 需要解密的数据
/// @param key 加密密钥16位长度
+ (NSData *)sm4DecrytoCBC:(NSData *)data key:(NSString *)key;

@end

NS_ASSUME_NONNULL_END
