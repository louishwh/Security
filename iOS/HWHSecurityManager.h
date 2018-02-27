//
//  HWHSecurityManager.h
//  Security
//
//  Created by louis on 2018/2/27.
//  Copyright © 2018年 louis. All rights reserved.
//

#import <Foundation/Foundation.h>

/** 数据加密中心
 *
 * 包含对称加密、非对称加密、摘要、消息认证以及Base64编码
 */
@interface HWHSecurityManager : NSObject

#pragma mark - 对称加密

/**
 * DES加密
 *
 * NSString(utf-8) ->  NSData(utf-8)-> 加密密文 -> NSData(Base64) -> NSString(utf-8)
 *
 * @param plaintext = 明文
 *
 * @param key = 密钥
 *
 * @param vector = 初始向量
 *
 * @return 密文
 */
+ (NSString *)DESencryptPlaintext:(NSString *)plaintext key:(NSString *)key vector:(NSString *)vector;

/**
 * DES解密
 *
 * NSString(utf-8) ->  NSData(base64)-> 明文 -> NSData(utf-8) -> NSString(utf-8)
 *
 * @param ciphertext = 密文
 *
 * @param key = 密钥
 *
 * @param vector = 初始向量
 *
 * @return 明文
 */
+ (NSString *)DESdecryptCiphertext:(NSString *)ciphertext key:(NSString *)key vector:(NSString *)vector;


/**
 * 三重DES加密
 *
 * @param plaintext = 明文
 *
 * @param key = 密钥
 *
 * @param vector = 初始向量
 *
 * @return 密文
 */
+ (NSString *)trebleDESencryptPlaintext:(NSString *)plaintext key:(NSString *)key vector:(NSString *)vector;

/**
 * 三重DES解密
 *
 * @param ciphertext = 密文
 *
 * @param key = 密钥
 *
 * @param vector = 初始向量
 *
 * @return 明文
 */
+ (NSString *)trebleDESdecryptCiphertext:(NSString *)ciphertext key:(NSString *)key vector:(NSString *)vector;


/**
 * AES128加密
 *
 * @param plaintext = 明文
 *
 * @param key = 密钥
 *
 * @param vector = 初始向量
 *
 * @return 密文
 */
+ (NSString *)AES128encryptPlaintext:(NSString *)plaintext key:(NSString *)key vector:(NSString *)vector;

/**
 * AES128解密
 *
 * @param ciphertext = 密文
 *
 * @param key = 密钥
 *
 * @param vector = 初始向量
 *
 * @return 明文
 */
+ (NSString *)AES128decryptCiphertext:(NSString *)ciphertext key:(NSString *)key vector:(NSString *)vector;


#pragma mark - 公钥加密
/**
 * RSA 公钥加密
 *
 * @param plaintext = 明文
 *
 * @param publickey = 公钥
 *
 * @return 密文
 */
+ (NSString *)RSAencryptWithPlaintext:(NSString *)plaintext PublicKey:(NSString *)publickey;

/**
 * RSA 公钥加密
 *
 * @param ciphertext = 密文
 *
 * @param privatekey = 私钥
 *
 * @return 明文
 */
+ (NSString *)RSAdecryptCiphertext:(NSString *)ciphertext privateKey:(NSString *)privatekey;


#pragma mark - 单向散列函数

#pragma mark - 消息认证码

#pragma mark - Base64编码


@end
