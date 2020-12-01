//
//  ShgDESSwift.swift
//  MobileFourAOC
//
//  Created by shg on 2020/11/24.
//  Copyright © 2020 asiainfo. All rights reserved.
//

import UIKit
import CommonCrypto

public class ShgDESSwift: NSObject {
    
    /// DES 加密
    /// - Parameters:
    ///   - data: 需要加密的数据
    ///   - key: 加密 密钥 8 位长度
    /// - Returns: 加密后的数据
    @objc public class func encrypt(data:Data,key:String) -> Data? {
        
        let keyLength = kCCKeySizeDES + 1
        
        var keyPtr:Array<CChar> = []
    
        for _:Int in 0 ..< keyLength {
            keyPtr.append(CChar(0))
        }
        
        if key.getCString(&keyPtr, maxLength: keyLength, encoding: .utf8) {
            
            let dataLength:Int = data.count
            
            let bufferSize:Int = dataLength + kCCBlockSizeDES
            
            let buffer = malloc(bufferSize)
            
            var numBytesEncrypted:Int = 0
            
            let bytes = [UInt8](data)
            
            let cryptStatus:CCCryptorStatus = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES), CCOptions(ccPKCS7Padding | kCCModeECB) , keyPtr, kCCKeySizeDES, nil, bytes, dataLength, buffer, bufferSize, &numBytesEncrypted)
            
            var outData:Data?
            
            if cryptStatus == kCCSuccess {
                
                outData = Data.init(bytes: buffer!, count: numBytesEncrypted)
            }
            
            free(buffer)
            
            return outData
        }
        
        return nil;
    }
    
    /// DES 解密
    /// - Parameters:
    ///   - data: 需要解密的数据
    ///   - key: 解密的密钥 8位
    /// - Returns: 解密后的数据
    @objc public class func decrypt(data:Data,key:String) -> Data? {

        let keyLength = kCCKeySizeDES + 1
        
        var keyPtr:Array<CChar> = []
        
        for _:Int in 0 ..< keyLength {
            keyPtr.append(CChar(0))
        }

        if key.getCString(&keyPtr, maxLength: keyLength, encoding: .utf8) {
            
            let dataLength:Int = data.count
            
            let bufferSize:Int = dataLength + kCCBlockSizeDES
            
            let buffer = malloc(bufferSize)
            
            var numBytesDecrypted:Int = 0
            
            let bytes = [UInt8](data)
            
            let cryptStatus:CCCryptorStatus = CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmDES), CCOptions(ccPKCS7Padding | kCCModeECB) , keyPtr, kCCKeySizeDES, nil, bytes, dataLength, buffer, bufferSize, &numBytesDecrypted)
            
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
