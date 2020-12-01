//
//  ShgRSASwift.swift
//  MobileFourAOC
//
//  Created by shg on 2020/11/25.
//  Copyright © 2020 asiainfo. All rights reserved.
//

import UIKit
import Security

public class ShgRSASwift: NSObject {
    
    /**
    #!/usr/bin/env bash
    echo "Generating RSA key pair ..."
    echo "1024 RSA key: private_key.pem"
    openssl genrsa -out private_key.pem 1024

    echo "create certification require file: rsaCertReq.csr"
    openssl req -new -key private_key.pem -out rsaCertReq.csr

    echo "create certification using x509: rsaCert.crt"
    openssl x509 -req -days 3650 -in rsaCertReq.csr -signkey private_key.pem -out rsaCert.crt

    echo "create public_key.der For IOS"
    openssl x509 -outform der -in rsaCert.crt -out public_key.der

    echo "create private_key.p12 For IOS. Please remember your password. The password will be used in iOS."
    openssl pkcs12 -export -out private_key.p12 -inkey private_key.pem -in rsaCert.crt

    echo "create rsa_public_key.pem For Java"
    openssl rsa -in private_key.pem -out rsa_public_key.pem -pubout
    echo "create pkcs8_private_key.pem For Java"
    openssl pkcs8 -topk8 -in private_key.pem -out pkcs8_private_key.pem -nocrypt

    echo "finished."
    ********************************************************************************/
    
    /// 支持的RSA keySize 大小有：512，768，1024，2048位
    /// 支持的RSA 填充方式有三种：NOPadding,PKCS1,OAEP 三种方式 ，填充方式影响最大分组加密数据块的大小
    /// 签名使用的填充方式PKCS1, 支持的签名算法有 sha1,sha256,sha224,sha384,sha512
    /// Nopadding填充最大数据块为 下面接口 SecKeyGetBlockSize 大小;
    /// PKCS1 填充方式最大数据为 SecKeyGetBlockSize大小 减去11
    /// OAEP 填充方式最大数据为 SecKeyGetBlockSize 大小减去 42
    /// RSA加密解密签名，适合小块的数据处理，大量数量需要处理分组逻辑；密码学中推荐使用对称加密进行数据加密，使用RSA来加密对称密钥
   
    /// RSA 加密，公钥加密
    /// - Parameters:
    ///   - aString: 需要加密的字符串
    ///   - publicKeyPath: 公钥文件路径
    /// - Returns: 加密后的字符串 16进制串
    @objc public class func encrypt(_ aString:String,_ publicKeyPath:String) -> String? {
        
        if aString.count == 0 || publicKeyPath.count == 0 {
            return nil
        }
        
        guard let secKey:SecKey = self.publicSecKey(publicKeyPath) else {
            return nil
        }
        
        guard let data:Data = aString.data(using: .utf8) else {
            return nil
        }
        
        //输入数据bytes
        let dataByte = [UInt8](data)
        
        //输入数据长度
        let dataLenght = data.count

        //公钥块长度
        let secKeyBlockSize = SecKeyGetBlockSize(secKey)
        
        //输出buffer
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: secKeyBlockSize)
        
        //说明：如果填充模式为 PKCS1 ，可加密数据块最大长度为 SecKeyGetBlockSize() - 11
        let maxInputLenght = secKeyBlockSize - 11

        var status:OSStatus = noErr
        
        var outLength:Int = secKeyBlockSize
        
        //RSA加密块数据长度不能大于密钥块长度,当数据大于密钥块长度时，进行分组加密
        if dataLenght > maxInputLenght {
            
            let index:Int = Int(ceilf(Float(dataLenght)/Float(maxInputLenght)))
            
            var rsaStr:String = ""
            
            for i:Int in 0 ..< index {
                
                let sufLength = dataLenght - i * maxInputLenght
                
                guard let range:Range = Range.init(NSMakeRange(i * maxInputLenght, i == index - 1 ? sufLength : maxInputLenght)) else {
                    return nil
                }
                
                let subData:Data = data.subdata(in: range)
                
                let subByte = [UInt8](subData)
                
                status = SecKeyEncrypt(secKey, SecPadding.PKCS1, subByte, subData.count, output, &outLength)
                
                if status != noErr {
                    return nil
                }
                
                for i:Int in 0 ..< outLength {
                    rsaStr = rsaStr.appendingFormat("%02x", _:output[i])
                }
            }
            
            output.deallocate()
            
            return rsaStr
            
        } else {
            
            status = SecKeyEncrypt(secKey, SecPadding.PKCS1, dataByte, dataLenght, output, &outLength)
            
            if status != noErr {
                return nil
            }
            
            var rsaStr:String = ""
            
            for i:Int in 0 ..< outLength {
                rsaStr = rsaStr.appendingFormat("%02x", _:output[i])
            }
            
            output.deallocate()
            
            return rsaStr
        }
    }
    
    /// 获取公钥 .der证书
    /// - Parameter publicKeyPath: 公钥文件路径
    /// - Returns: 公钥
    class func publicSecKey(_ publicKeyPath:String) -> SecKey? {
        
        let url:URL = URL.init(fileURLWithPath: publicKeyPath)
        
        var data:Data
        
        do {
            try data = Data.init(contentsOf: url)
        } catch  {
            return nil
        }
        
        let dataByte = [UInt8](data)
        
        let cfData:CFData = CFDataCreate(kCFAllocatorDefault, dataByte, CFIndex(dataByte.count))
        
        guard let cert:SecCertificate = SecCertificateCreateWithData(nil, cfData) else {
            return nil
        }
        
        var trust:SecTrust?
        
        let policy:SecPolicy = SecPolicyCreateBasicX509()
      
        let status:OSStatus = SecTrustCreateWithCertificates(cert, policy, &trust)
        
        if status != noErr {
            return nil
        }
        
        var result:SecTrustResultType = .invalid
        
        if SecTrustEvaluate(trust!, &result) != noErr {
            return nil
        }
        
        guard let secKey:SecKey = SecTrustCopyPublicKey(trust!) else {
            return nil
        }
        
        return secKey
    }
    
    /// RSA 解密，私钥解密
    /// - Parameters:
    ///   - data: 需要解密的data
    ///   - privateKeyPath: 私钥文件路径
    /// - Returns: 解密后的字符串
    @objc public class func decrypt(_ data:Data,_ privateKeyPath:String) -> String? {
        
        if data.count == 0 || privateKeyPath.count == 0 {
            return nil
        }
        
        guard let secKey:SecKey = self.privateSecKey(privateKeyPath) else {
            return nil
        }
        
        //输入数据bytes
        let dataByte = [UInt8](data)
        
        //输入数据长度
        let dataLenght = data.count

        //私钥块长度
        let secKeyBlockSize = SecKeyGetBlockSize(secKey)
        
        //输出buffer
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: secKeyBlockSize)
        
        let maxInputLenght = secKeyBlockSize

        var status:OSStatus = noErr
        
        var outLength:Int = secKeyBlockSize
        
        //RSA解密块数据长度不能大于密钥块长度,当数据大于密钥块长度时，进行分组解密
        if dataLenght > maxInputLenght {
            
            let index:Int = Int(ceilf(Float(dataLenght)/Float(maxInputLenght)))
            
            var outData:Data = Data()
         
            for i:Int in 0 ..< index {
                
                let sufLength = dataLenght - i * maxInputLenght
                
                guard let range:Range = Range.init(NSMakeRange(i * maxInputLenght, i == index - 1 ? sufLength : maxInputLenght)) else {
                    return nil
                }
                
                let subData:Data = data.subdata(in: range)
                
                let subByte = [UInt8](subData)
                
                status = SecKeyDecrypt(secKey, SecPadding.init(rawValue: 0), subByte, subData.count, output, &outLength)
                
                if status != noErr {
                    return nil
                }
                
                var idxFirstZero:Int = -1
                
                var idxNextZero:Int = outLength
                
                for i:Int in 0 ..< outLength {
                    if output[i] == 0 {
                        if idxFirstZero < 0 {
                            idxFirstZero = i
                        } else {
                            idxNextZero = i
                            break
                        }
                    }
                }
                
                outData.append(&output[idxFirstZero + 1], count: idxNextZero - idxFirstZero - 1)
                
            }
            
            output.deallocate()
            
            let rsaStr:String? = String.init(data: outData, encoding: .utf8)
            
            return rsaStr
            
        } else {
            
            status = SecKeyDecrypt(secKey, SecPadding.PKCS1, dataByte, dataLenght, output, &outLength)
            
            if status != noErr {
                return nil
            }
            
            var idxFirstZero:Int = -1
            
            var idxNextZero:Int = outLength
            
            for i:Int in 0 ..< outLength {
                if output[i] == 0 {
                    if idxFirstZero < 0 {
                        idxFirstZero = i
                    } else {
                        idxNextZero = i
                        break
                    }
                }
            }
            
            var outData:Data = Data()
            
            outData.append(&output[idxFirstZero + 1], count: idxNextZero - idxFirstZero - 1)
            
            output.deallocate()
            
            let rsaStr:String? = String.init(data: outData, encoding: .utf8)
            
            return rsaStr
        }
    }
    
    /// 获取私钥 .p12证书
    /// - Parameter privateKeyPath: 私钥文件路径
    /// - Returns: 私钥
    class func privateSecKey(_ privateKeyPath:String) -> SecKey? {
        
        let url:URL = URL.init(fileURLWithPath: privateKeyPath)
        
        var data:CFData
        
        do {
            try data = Data.init(contentsOf: url) as CFData
        } catch  {
            return nil
        }
        
        let options:CFMutableDictionary = CFDictionaryCreateMutable(kCFAllocatorDefault, CFIndex(0), nil, nil)
        
        // 对象转 UnsafeRawPointer
        let key = Unmanaged.passRetained(kSecImportExportPassphrase as NSString).autorelease().toOpaque()
        
        let value = Unmanaged.passRetained("1" as NSString).autorelease().toOpaque()
        
        CFDictionaryAddValue(options, key, value)
        
        var items:CFArray? = CFArrayCreate(nil, UnsafeMutablePointer<UnsafeRawPointer?>(bitPattern: 0), 0, nil)
        
        let securityError:OSStatus = SecPKCS12Import(data, options, &items)
        
        if securityError == noErr && CFArrayGetCount(items) > 0 {
            
            let identityDict = CFArrayGetValueAtIndex(items, 0)
            
            // UnsafeRawPointer 转 任意类型
            let cfDic:CFDictionary = Unmanaged.fromOpaque(identityDict!).takeUnretainedValue()
            
            if CFDictionaryGetCount(cfDic) == 0 {
                return nil
            }
            
            let identityKey = Unmanaged.passRetained(kSecImportItemIdentity as NSString).autorelease().toOpaque()
            
            let identityPriv = CFDictionaryGetValue(cfDic, identityKey)
            
            let identity:SecIdentity = Unmanaged.fromOpaque(identityPriv!).takeUnretainedValue()
            
            var secKey:SecKey?
            
            let status = SecIdentityCopyPrivateKey(identity, &secKey)
            
            if status == noErr {
                return secKey
            }
        }
        
        return nil
    }
    
    @objc public class func hexStrToData(_ hexStr:String) -> Data? {
        
        if hexStr.count == 0 {
            return nil
        }
        
        var hexData:Data = Data.init(capacity: 8)
        
        var range:NSRange
        
        if hexStr.count % 2 == 0 {
            range = NSMakeRange(0, 2)
        } else {
            range = NSMakeRange(0, 1)
        }
        
        for _:Int in stride(from: range.location, to: hexStr.count, by: 2) {
            
            let hexCharStr:String = String(hexStr[hexStr.index(hexStr.startIndex, offsetBy: range.location) ..< hexStr.index(hexStr.startIndex, offsetBy: range.location + range.length)])
            
            let data:Data = hexCharStr.data(using: .utf8)!
            
            let anInt:UnsafeMutablePointer<UInt64> = UnsafeMutablePointer<UInt64>.allocate(capacity: data.count)
            
            let scanner:Scanner = Scanner.init(string: hexCharStr)
            
            scanner.scanHexInt64(anInt)
            
            let entity:Data = Data.init(bytes: anInt, count: 1)
            
            hexData.append(entity)
            
            range.location += range.length
            
            range.length = 2
            
            anInt.deallocate()
        }
        
        return hexData
    }
}
