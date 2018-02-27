//
//  NSString+Security.h
//  Security
//
//  Created by louis on 2018/2/27.
//  Copyright © 2018年 louis. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (Hash)

#pragma mark - 单向散列函数
/* MD5、SHA-1、SHA-256、SHA-384、SHA-512 */

/**
 *  计算MD5散列(MD5已不用于信息摘要)
 *  @return 32个字符的MD5散列字符串
 */
- (NSString *)md5Digest;

/**
 *  计算SHA1散列
 *  @return 40个字符的SHA1散列字符串
 */
- (NSString *)sha1Digest;

/**
 *  计算SHA256散列
 *  @return 64个字符的SHA256散列字符串
 */
- (NSString *)sha256Digest;

/**
 *  计算SHA512散列
 *  @return 128个字符的SHA512散列字符串
 */
- (NSString *)sha512Digest;


/**
 *  计算文件的MD5散列
 *  @return 32个字符的MD5散列字符串
 */
- (NSString *)fileMD5Digest;

/**
 *  计算文件SHA1散列
 *  @return 40个字符的SHA1散列字符串
 */
- (NSString *)fileSHA1Digest;

/**
 *  计算文件的SHA256散列结果
 *
 *  终端测试命令：
 *  @code
 *  openssl sha -sha256 file.dat
 *  @endcode
 *
 *  @return 64个字符的SHA256散列字符串
 */
- (NSString *)fileSHA256Digest;

/**
 *  计算文件的SHA512散列结果
 *
 *  终端测试命令：
 *  @code
 *  openssl sha -sha512 file.dat
 *  @endcode
 *
 *  @return 128个字符的SHA512散列字符串
 */
- (NSString *)fileSHA512Digest;


#pragma mark - 消息认证码
/* HMAC-MD5、HMAC-SHA-1、HMAC-SHA-256、HMAC-SHA-512 */

/**
 *  计算HMAC MD5散列
 *  @return 32个字符的HMAC MD5散列字符串
 */
- (NSString *)hmacMD5WithKey:(NSString *)key;

/**
 *  计算HMAC SHA1散列
 *  @return 40个字符的HMAC SHA1散列字符串
 */
- (NSString *)hmacSHA1WithKey:(NSString *)key;

/**
 *  计算HMAC SHA256散列
 *  @return 64个字符的HMAC SHA256散列字符串
 */
- (NSString *)hmacSHA256WithKey:(NSString *)key;

/**
 *  计算HMAC SHA512散列
 *  @return 128个字符的HMAC SHA512散列字符串
 */
- (NSString *)hmacSHA512WithKey:(NSString *)key;

#pragma mark - Base64编码

/**
 *  字符串 -> Base64编码的字符串
 *  @return Base64编码后的字符串
 */
- (NSString*)encodeBase64;

/**
 *  Base64编码的字符串 -> 字符串
 *  @return Base64解码后的字符串
 */
- (NSString*)decodeBase64;

/**
 *  二进制数据 -> Base64编码的字符串
 *  @return 128个字符的HMAC SHA512散列字符串
 */
+ (NSString*)encodeBase64Data:(NSData *)data;

/**
 *  Base64编码的二进制数据 -> 字符串
 *  @return 二进制数据
 */
+ (NSString*)decodeBase64Data:(NSData *)data;


@end
