//
//  ShgSM3OC.h
//  ShgCryptoKit
//
//  Created by shg on 2020/12/1.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ShgSM3OC : NSObject

///  SM3 加密算法，不可逆
/// @param data 需要加密的数据
/// @param callBack 回调数据 data:加密的数据 ，base64:加密数据以base64串形似返回，hex：加密数据以16进制串返回
+ (void)sm3Encryto:(NSData *)data finish:(void (^)(NSData *data,NSString *base64,NSString *hex))callBack;

@end

NS_ASSUME_NONNULL_END
