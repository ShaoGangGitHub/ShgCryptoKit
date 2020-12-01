//
//  ShgBase64Swift.swift
//  MobileFourAOC
//
//  Created by shg on 2020/11/24.
//  Copyright © 2020 asiainfo. All rights reserved.
//

import UIKit

public class ShgBase64Swift: NSObject {
    
    /// base64 加密算法
    /// - Parameter aString: 需要处理的字符串
    /// - Returns: 加密后的目标字符串
    @objc public class func stringToBase64(_ aString:String) -> String? {
        
        if let data:Data = aString.data(using: .utf8) {
            
            let base64Str = data.base64EncodedString()
            
            return base64Str
        }
        return nil
    }
    
    /// base64 解密算法
    /// - Parameter base64String: 需要解密的base64串
    /// - Returns: 解密后的目标字符串
    @objc public class func base64ToString(_ base64String:String) -> String? {
        
        if let data:Data = NSData.init(base64Encoded: base64String, options: NSData.Base64DecodingOptions.ignoreUnknownCharacters) as Data? {
            
            if let string:String = String.init(data: data, encoding: .utf8) {
                
                return string
            }
        }
        
        return nil
    }
}
