//
//  ShgSHASwift.swift
//  MobileFourAOC
//
//  Created by shg on 2020/11/25.
//  Copyright © 2020 asiainfo. All rights reserved.
//

import UIKit
import CommonCrypto

public class ShgSHASwift: NSObject {

    @objc public enum SHA:Int {
        case MD5    = 0
        case SHA1   = 1
        case SHA224 = 2
        case SHA256 = 3
        case SHA384 = 4
        case SHA512 = 5
    }
    
    class func encryptLength(_ sha:SHA) -> Int {
        
        switch sha {
        case .MD5:
            return Int(CC_MD5_DIGEST_LENGTH)
        case .SHA1:
            return Int(CC_SHA1_DIGEST_LENGTH)
        case .SHA224:
            return Int(CC_SHA224_DIGEST_LENGTH)
        case .SHA256:
            return Int(CC_SHA256_DIGEST_LENGTH)
        case .SHA384:
            return Int(CC_SHA384_DIGEST_LENGTH)
        case .SHA512:
            return Int(CC_SHA512_DIGEST_LENGTH)
        default:
            return 0
        }
    }
    
    /// SHA 加密算法
    /// - Parameters:
    ///   - sha: 加密类型
    ///   - aString: 需要加密的字符串
    /// - Returns: 目标字符串 MD5:32位，SHA1:40位，SHA224:56位，SHA256:64位，SHA384:96位，SHA512:128位
    @objc public class func encrypt(_ sha:SHA,_ aString:String) -> String? {
        
        guard let data:Data = aString.data(using: .utf8) else {
            return nil
        }
        
        let inputByte = [UInt8](data)
        
        let lenght:Int = self.encryptLength(sha)
        
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: lenght)
        
        switch sha {
        case .MD5:
            CC_MD5(inputByte, CC_LONG(inputByte.count), output)
            break
        case .SHA1:
            CC_SHA1(inputByte, CC_LONG(inputByte.count), output)
            break
        case .SHA224:
            CC_SHA224(inputByte, CC_LONG(inputByte.count), output)
            break
        case .SHA256:
            CC_SHA256(inputByte, CC_LONG(inputByte.count), output)
            break
        case .SHA384:
            CC_SHA384(inputByte, CC_LONG(inputByte.count), output)
            break
        case .SHA512:
            CC_SHA512(inputByte, CC_LONG(inputByte.count), output)
            break
        }
        
        var shaStr:String = ""
        
        for i:Int in 0 ..< lenght {
            shaStr = shaStr.appendingFormat("%02x", _:output[i])
        }
        
        output.deallocate()
        
        return shaStr
    }
    
    /// CCHMAC 加密算法，加入key值的序列化加密算法
    /// - Parameters:
    ///   - sha: 加密方式
    ///   - aString: 需要加密的字符串
    ///   - key: 加密key，任意长度
    /// - Returns: 目标字符串
    @objc public class func ccHMC(_ sha:SHA,_ aString:String,_ key:String) -> String? {
        
        guard let data:Data = aString.data(using: .utf8) else {
            return nil
        }
        
        var type:CCHmacAlgorithm!
        
        switch sha {
        case .MD5:
            type = CCHmacAlgorithm(kCCHmacAlgMD5)
            break
        case .SHA1:
            type = CCHmacAlgorithm(kCCHmacAlgSHA1)
            break
        case .SHA224:
            type = CCHmacAlgorithm(kCCHmacAlgSHA224)
            break
        case .SHA256:
            type = CCHmacAlgorithm(kCCHmacAlgSHA256)
            break
        case .SHA384:
            type = CCHmacAlgorithm(kCCHmacAlgSHA384)
            break
        case .SHA512:
            type = CCHmacAlgorithm(kCCHmacAlgSHA512)
            break
        }
        
        guard let ketData:Data = key.data(using: .utf8) else {
            return nil
        }
        
        let keyLenght:Int = ketData.count
        
        let keyByte = [UInt8](ketData)
        
        let inputByte = [UInt8](data)
        
        let lenght:Int = self.encryptLength(sha)
        
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: lenght)
        
        CCHmac(type, keyByte, keyLenght, inputByte, data.count, output)
        
        var shaStr:String = ""
        
        for i:Int in 0 ..< lenght {
            shaStr = shaStr.appendingFormat("%02x", _:output[i])
        }
        
        output.deallocate()
        
        return shaStr
    }
    
    /// SHA1 加密算法
    /// - Parameter aStrign: 需要加密的字符串
    /// - Returns: 目标字符串 40位
    @objc public class func SHA1(_ aString:String) -> String? {
        
        guard let data:Data = aString.data(using: .utf8) else {
            return nil
        }
        
        let inputByte = [UInt8](data)
        
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA1_DIGEST_LENGTH))
        
        CC_SHA1(inputByte, CC_LONG(inputByte.count), output)
        
        var shaStr:String = ""
        
        for i:Int in 0 ..< Int(CC_SHA1_DIGEST_LENGTH) {
            shaStr = shaStr.appendingFormat("%02x", _:output[i])
        }
        
        output.deallocate()
        
        return shaStr
    }
    
    /// SHA224 加密算法
    /// - Parameter aStrign: 需要加密的字符串
    /// - Returns: 目标字符串 56位
    @objc public class func SHA224(_ aString:String) -> String? {
        
        guard let data:Data = aString.data(using: .utf8) else {
            return nil
        }
        
        let inputByte = [UInt8](data)
        
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA224_DIGEST_LENGTH))
        
        CC_SHA224(inputByte, CC_LONG(inputByte.count), output)

        var shaStr:String = ""
        
        for i:Int in 0 ..< Int(CC_SHA224_DIGEST_LENGTH) {
            shaStr = shaStr.appendingFormat("%02x", _:output[i])
        }
        
        output.deallocate()
        
        return shaStr
    }
    
    /// SHA256 加密算法
    /// - Parameter aStrign: 需要加密的字符串
    /// - Returns: 目标字符串 64位
    @objc public class func SHA256(_ aString:String) -> String? {
        
        guard let data:Data = aString.data(using: .utf8) else {
            return nil
        }
        
        let inputByte = [UInt8](data)
        
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA256_DIGEST_LENGTH))
        
        CC_SHA256(inputByte, CC_LONG(inputByte.count), output)

        var shaStr:String = ""
        
        for i:Int in 0 ..< Int(CC_SHA256_DIGEST_LENGTH) {
            shaStr = shaStr.appendingFormat("%02x", _:output[i])
        }
        
        output.deallocate()
        
        return shaStr
    }
    
    /// SHA384 加密算法
    /// - Parameter aStrign: 需要加密的字符串
    /// - Returns: 目标字符串 96位
    @objc public class func SHA384(_ aString:String) -> String? {
        
        guard let data:Data = aString.data(using: .utf8) else {
            return nil
        }
        
        let inputByte = [UInt8](data)
        
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA384_DIGEST_LENGTH))
        
        CC_SHA384(inputByte, CC_LONG(inputByte.count), output)

        var shaStr:String = ""
        
        for i:Int in 0 ..< Int(CC_SHA384_DIGEST_LENGTH) {
            shaStr = shaStr.appendingFormat("%02x", _:output[i])
        }
        
        output.deallocate()
        
        return shaStr
    }
    
    /// SHA512 加密算法
    /// - Parameter aStrign: 需要加密的字符串
    /// - Returns: 目标字符串 128位
    @objc public class func SHA512(_ aString:String) -> String? {
        
        guard let data:Data = aString.data(using: .utf8) else {
            return nil
        }
        
        let inputByte = [UInt8](data)
        
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA512_DIGEST_LENGTH))
        
        CC_SHA512(inputByte, CC_LONG(inputByte.count), output)

        var shaStr:String = ""
        
        for i:Int in 0 ..< Int(CC_SHA512_DIGEST_LENGTH) {
            shaStr = shaStr.appendingFormat("%02x", _:output[i])
        }
        
        output.deallocate()
        
        return shaStr
    }
}

