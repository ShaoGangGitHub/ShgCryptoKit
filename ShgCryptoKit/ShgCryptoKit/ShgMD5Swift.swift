//
//  ShgMD5Swift.swift
//  MobileFourAOC
//
//  Created by shg on 2020/11/24.
//  Copyright © 2020 asiainfo. All rights reserved.
//

import UIKit
import CommonCrypto

public class ShgMD5Swift: NSObject {

    /// MD5 算法
    /// - Parameter aString: 需要处理的字符串
    /// - Returns: 目标字符串 32位
    @objc public class func md5(_ aString:String) -> String? {
        
        if let data:Data = aString.data(using: .utf8) {
            
            let inputByte = [UInt8](data)
            
            let output = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_MD5_DIGEST_LENGTH))
            
            CC_MD5(inputByte, CC_LONG(inputByte.count), output)
            
            var md5Str:String = ""
            
            for i:Int in 0 ..< Int(CC_MD5_DIGEST_LENGTH) {
                md5Str = md5Str.appendingFormat("%02x", _:output[i])
            }
            
            output.deallocate()
            
            return md5Str
        }
        return nil
    }
}
