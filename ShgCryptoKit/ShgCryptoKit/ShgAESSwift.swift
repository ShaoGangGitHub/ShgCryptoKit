//
//  ShgAESSwift.swift
//  MobileFourAOC
//
//  Created by shg on 2020/11/19.
//  Copyright © 2020 asiainfo. All rights reserved.
//

import UIKit
import CommonCrypto

public class ShgAESSwift: NSObject {
    
    /// AES128加密
    /// - Parameters:
    ///   - data: 需要加密的数据
    ///   - key: 加密 密钥 16 为长度
    /// - Returns: 加密后的数据
    @objc public class func encrypt(data:Data,key:String) -> Data? {
        
        let keyLength = kCCKeySizeAES128 + 1
        
        var keyPtr:Array<CChar> = []
        
        for _:Int in 0 ..< keyLength {
            keyPtr.append(CChar(0))
        }
        
        if key.getCString(&keyPtr, maxLength: keyLength, encoding: .utf8) {
            
            let dataLength:Int = data.count
            
            let bufferSize:Int = dataLength + kCCBlockSizeAES128
            
            let buffer = malloc(bufferSize)
            
            var numBytesEncrypted:Int = 0
            
            let bytes = [UInt8](data)
            
            let cryptStatus:CCCryptorStatus = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(ccPKCS7Padding | kCCModeECB) , keyPtr, kCCKeySizeAES128, nil, bytes, dataLength, buffer, bufferSize, &numBytesEncrypted)
            
            var outData:Data?
            
            if cryptStatus == kCCSuccess {
                
                outData = Data.init(bytes: buffer!, count: numBytesEncrypted)
            }
            
            free(buffer)
            
            return outData
        }
        
        return nil;
    }
    
    /// AES 128 解密
    /// - Parameters:
    ///   - data: 需要解密的数据
    ///   - key: 解密的密钥 16位
    /// - Returns: 解密后的数据
    @objc public class func decrypt(data:Data,key:String) -> Data? {

        let keyLength = kCCKeySizeAES128 + 1
        
        var keyPtr:Array<CChar> = []
        
        for _:Int in 0 ..< keyLength {
            keyPtr.append(CChar(0))
        }

        if key.getCString(&keyPtr, maxLength: keyLength, encoding: .utf8) {
            
            let dataLength:Int = data.count
            
            let bufferSize:Int = dataLength + kCCBlockSizeAES128
            
            let buffer = malloc(bufferSize)
            
            var numBytesDecrypted:Int = 0
            
            let bytes = [UInt8](data)
            
            let cryptStatus:CCCryptorStatus = CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(ccPKCS7Padding | kCCModeECB) , keyPtr, kCCKeySizeAES128, nil, bytes, dataLength, buffer, bufferSize, &numBytesDecrypted)
            
            var outData:Data?
            
            if cryptStatus == kCCSuccess {
                
                outData = Data.init(bytes: buffer!, count: numBytesDecrypted)
            }
            
            free(buffer)

            return outData
        }
        
        return nil
    }
}
