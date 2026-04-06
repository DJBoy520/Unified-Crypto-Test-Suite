#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4 分组密码算法多模式实现（国密标准）
支持多种加密模式的完整实现
"""

import os
import struct
from typing import Tuple, Optional, Union


class SM4:
    """SM4 算法实现"""
    
    # S盒
    Sbox = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xe6, 0x0c, 0xd9, 0xed, 0xaf, 0x73, 0x15,
        0xc0, 0x9b, 0xc6, 0xc5, 0x9a, 0xca, 0x6a, 0xb7, 0x22, 0x37, 0x00, 0x07, 0x59, 0xb1, 0xf6, 0x29,
        0xc1, 0xda, 0xf3, 0xed, 0xfa, 0xca, 0x82, 0xc9, 0xfb, 0x15, 0x02, 0xd6, 0xcd, 0xb7, 0xd7, 0xa8,
        0xe9, 0x0d, 0xad, 0xd7, 0xd0, 0xc4, 0xe4, 0x07, 0xb6, 0x71, 0x95, 0x0d, 0x32, 0x22, 0x43, 0x45,
        0xbb, 0x14, 0x72, 0xc3, 0xc6, 0x98, 0x18, 0xa4, 0x60, 0x6e, 0x07, 0xa6, 0xf3, 0x55, 0x66, 0xf8,
        0xb0, 0xfe, 0x8b, 0x6e, 0x46, 0xf0, 0xf8, 0x60, 0xf1, 0x4d, 0xd0, 0x9a, 0x0e, 0x6e, 0xe7, 0xe6,
        0x1f, 0x07, 0xfa, 0xa6, 0x73, 0xd6, 0x31, 0xce, 0x4c, 0xf7, 0x26, 0x9f, 0x4b, 0xc3, 0x7d, 0x44,
        0xaf, 0xd9, 0xce, 0x4f, 0x3f, 0xd4, 0x6f, 0xa5, 0x3c, 0x65, 0xf0, 0x2d, 0x28, 0x2d, 0x6d, 0x7c,
        0x63, 0x68, 0x39, 0x20, 0x9a, 0x7f, 0x1f, 0x0e, 0x5f, 0x4e, 0x45, 0xc3, 0x08, 0xea, 0x4a, 0xd7,
        0x27, 0x7a, 0x28, 0x8e, 0xac, 0xf3, 0x4d, 0xfe, 0xa8, 0x5f, 0x36, 0xe4, 0xf6, 0xd6, 0x52, 0x7e,
        0xa5, 0x29, 0x68, 0xee, 0x4e, 0xc7, 0x8c, 0x3f, 0x64, 0x8d, 0x21, 0x3e, 0xb7, 0x78, 0x76, 0xb2,
        0xce, 0xc2, 0x71, 0xe0, 0xa2, 0xe2, 0x8c, 0xa6, 0x27, 0x06, 0x5a, 0x4c, 0xb4, 0xb6, 0xc5, 0x28,
        0x66, 0xdc, 0x78, 0xbf, 0x0b, 0x52, 0x6c, 0xb6, 0xc6, 0x47, 0x22, 0xfb, 0x12, 0xf1, 0x29, 0x16,
        0x02, 0x84, 0x26, 0x65, 0x49, 0x97, 0x06, 0x96, 0xb5, 0x73, 0x60, 0x89, 0x86, 0xc1, 0xc9, 0x6b,
        0xe1, 0x8e, 0x61, 0x02, 0xe6, 0x8a, 0x69, 0xf0, 0x55, 0x9e, 0xd4, 0xad, 0x91, 0xf7, 0xf5, 0x51,
        0x81, 0x51, 0x6c, 0xf4, 0xfd, 0x3c, 0xde, 0x42, 0x5b, 0x1d, 0x2e, 0xed, 0xdd, 0x46, 0x37, 0xe1,
    ]
    
    # 常数
    FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
    CK = [0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6267,
          0x6e757c83, 0x8a919899, 0xa0a7aeb5, 0xbcc3cad1,
          0xd8dfe6ed, 0xf4fb0208, 0x0f161d24, 0x2b323940,
          0x474e555c, 0x636a7178, 0x7f868d94, 0x9ba1a8af,
          0xb6bdc4cb, 0xd2d9e0e7, 0xeef5fc03, 0x0a11181f,
          0x262d343b, 0x424956005d, 0x646b7279, 0x80878e95,
          0x9ca3aab1, 0xb8bfc6cd, 0xd4dbe2e9, 0xf0f7fe05,
          0x0c131a21, 0x282f363d, 0x444b5259, 0x606768af]
    
    @staticmethod
    def _left_rotate(x, n):
        """左循环移位"""
        n = n & 31
        return ((x << n) | (x >> (32 - n))) & 0xffffffff
    
    @staticmethod
    def _sbox_replace(input_data):
        """S盒替换"""
        output = 0
        for i in range(4):
            index = (input_data >> (8 * i)) & 0xff
            output |= SM4.Sbox[index] << (8 * i)
        return output & 0xffffffff
    
    @staticmethod
    def _linear_transform(input_data):
        """线性变换"""
        return input_data ^ SM4._left_rotate(input_data, 2) ^ \
               SM4._left_rotate(input_data, 10) ^ SM4._left_rotate(input_data, 18) ^ \
               SM4._left_rotate(input_data, 24)
    
    @staticmethod
    def _linear_transform_key(input_data):
        """密钥线性变换"""
        return input_data ^ SM4._left_rotate(input_data, 13) ^ SM4._left_rotate(input_data, 23)
    
    @staticmethod
    def _t(input_data):
        """T 变换"""
        return SM4._linear_transform(SM4._sbox_replace(input_data))
    
    @staticmethod
    def _t_key(input_data):
        """T' 变换（用于密钥展开）"""
        return SM4._linear_transform_key(SM4._sbox_replace(input_data))
    
    def __init__(self, key: Union[bytes, str]):
        """初始化SM4"""
        if isinstance(key, str):
            key = key.encode('utf-8')
        if len(key) != 16:
            raise ValueError("Key length must be 16 bytes")
        
        # 密钥展开
        self.rk = self._expand_key(key)
    
    def _expand_key(self, key: bytes) -> list:
        """密钥展开"""
        # 转换密钥为32位大端整数
        mk = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
        
        # 初始化 K
        k = [mk[0] ^ self.FK[0], mk[1] ^ self.FK[1], 
             mk[2] ^ self.FK[2], mk[3] ^ self.FK[3]]
        
        # 生成轮密钥
        rk = []
        for i in range(32):
            k_next = k[3] ^ self._t_key(k[0] ^ k[1] ^ k[2] ^ self.CK[i])
            rk.append(k_next)
            k = [k[1], k[2], k[3], k_next]
        
        return rk
    
    def _process_block(self, block: bytes, is_encrypt: bool = True) -> bytes:
        """处理一个数据块"""
        if len(block) != 16:
            raise ValueError("Block size must be 16 bytes")
        
        # 转换块为32位大端整数
        x = [int.from_bytes(block[i:i+4], 'big') for i in range(0, 16, 4)]
        
        # 轮函数
        rk = self.rk if is_encrypt else self.rk[::-1]
        
        for i in range(32):
            x_next = self._t(x[1] ^ x[2] ^ x[3] ^ rk[i]) ^ x[0]
            x = [x[1], x[2], x[3], x_next]
        
        # 反序
        result = []
        for val in [x[3], x[2], x[1], x[0]]:
            result.append(val.to_bytes(4, 'big'))
        
        return b''.join(result)
    
    def _pkcs7_pad(self, data: bytes, block_size: int = 16) -> bytes:
        """PKCS#7填充"""
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)
    
    def _pkcs7_unpad(self, data: bytes) -> bytes:
        """移除PKCS#7填充"""
        if not data:
            return data
        pad_len = data[-1]
        if pad_len > 0 and pad_len <= 16:
            # 验证填充
            if all(b == pad_len for b in data[-pad_len:]):
                return data[:-pad_len]
        return data
    
    def encrypt_ecb(self, plaintext: bytes, padding: bool = True) -> bytes:
        """ECB模式加密"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        if padding:
            plaintext = self._pkcs7_pad(plaintext)
        elif len(plaintext) % 16 != 0:
            raise ValueError("ECB plaintext length must be multiple of 16 without padding")
        
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            ciphertext += self._process_block(plaintext[i:i+16], is_encrypt=True)
        
        return ciphertext
    
    def decrypt_ecb(self, ciphertext: bytes, padding: bool = True) -> bytes:
        """ECB模式解密"""
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        
        if len(ciphertext) % 16 != 0:
            raise ValueError("ECB ciphertext length must be multiple of 16")
        
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            plaintext += self._process_block(ciphertext[i:i+16], is_encrypt=False)
        
        if padding:
            plaintext = self._pkcs7_unpad(plaintext)
        
        return plaintext
    
    def encrypt_cbc(self, plaintext: bytes, iv: bytes, padding: bool = True) -> bytes:
        """CBC模式加密"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        
        if len(iv) != 16:
            raise ValueError("IV length must be 16 bytes")
        
        if padding:
            plaintext = self._pkcs7_pad(plaintext)
        elif len(plaintext) % 16 != 0:
            raise ValueError("CBC plaintext length must be multiple of 16 without padding")
        
        ciphertext = b''
        prev_block = iv
        
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            # XOR with previous ciphertext block
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted = self._process_block(xored, is_encrypt=True)
            ciphertext += encrypted
            prev_block = encrypted
        
        return ciphertext
    
    def decrypt_cbc(self, ciphertext: bytes, iv: bytes, padding: bool = True) -> bytes:
        """CBC模式解密"""
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        
        if len(iv) != 16:
            raise ValueError("IV length must be 16 bytes")
        if len(ciphertext) % 16 != 0:
            raise ValueError("CBC ciphertext length must be multiple of 16")
        
        plaintext = b''
        prev_block = iv
        
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted = self._process_block(block, is_encrypt=False)
            # XOR with previous ciphertext block
            plaintext += bytes(a ^ b for a, b in zip(decrypted, prev_block))
            prev_block = block
        
        if padding:
            plaintext = self._pkcs7_unpad(plaintext)
        
        return plaintext
    
    def encrypt_cfb(self, plaintext: bytes, iv: bytes, segment_size: int = 128) -> bytes:
        """CFB模式加密（支持FB8和FB128）"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        
        if len(iv) != 16:
            raise ValueError("IV length must be 16 bytes")
        
        # segment_size: 反馈位数（8表示CFB8，128表示CFB128）
        segment_bytes = segment_size // 8
        
        ciphertext = b''
        shift_register = iv
        
        for i in range(0, len(plaintext), segment_bytes):
            # 加密shift_register
            encrypted_sr = self._process_block(shift_register, is_encrypt=True)
            
            # 取前segment_bytes字节
            feedback = encrypted_sr[:segment_bytes]
            
            # 明文与反馈异或
            block = plaintext[i:i+segment_bytes]
            if len(block) < segment_bytes:
                # 最后一块可以少于segment_bytes
                feedback = feedback[:len(block)]
            
            encrypted_block = bytes(a ^ b for a, b in zip(block, feedback))
            ciphertext += encrypted_block
            
            # 更新shift_register
            shift_register = shift_register[segment_bytes:] + encrypted_block
            # 如果shift_register不足16字节，用0填充
            if len(shift_register) < 16:
                shift_register = shift_register + b'\x00' * (16 - len(shift_register))
        
        return ciphertext
    
    def decrypt_cfb(self, ciphertext: bytes, iv: bytes, segment_size: int = 128) -> bytes:
        """CFB模式解密"""
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        
        if len(iv) != 16:
            raise ValueError("IV length must be 16 bytes")
        
        segment_bytes = segment_size // 8
        
        plaintext = b''
        shift_register = iv
        
        for i in range(0, len(ciphertext), segment_bytes):
            # 加密shift_register
            encrypted_sr = self._process_block(shift_register, is_encrypt=True)
            
            # 取前segment_bytes字节
            feedback = encrypted_sr[:segment_bytes]
            
            # 密文与反馈异或
            block = ciphertext[i:i+segment_bytes]
            if len(block) < segment_bytes:
                feedback = feedback[:len(block)]
            
            decrypted_block = bytes(a ^ b for a, b in zip(block, feedback))
            plaintext += decrypted_block
            
            # 更新shift_register
            shift_register = shift_register[segment_bytes:] + block
            if len(shift_register) < 16:
                shift_register = shift_register + b'\x00' * (16 - len(shift_register))
        
        return plaintext
    
    def encrypt_ofb(self, plaintext: bytes, iv: bytes) -> bytes:
        """OFB模式加密"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        
        if len(iv) != 16:
            raise ValueError("IV length must be 16 bytes")
        
        ciphertext = b''
        feedback = iv
        
        for i in range(0, len(plaintext), 16):
            # 加密反馈值
            encrypted_fb = self._process_block(feedback, is_encrypt=True)
            
            # 明文与加密反馈异或
            block = plaintext[i:i+16]
            if len(block) == 16:
                ciphertext += bytes(a ^ b for a, b in zip(block, encrypted_fb))
                feedback = encrypted_fb
            else:
                # 最后一块可能少于16字节
                ciphertext += bytes(a ^ b for a, b in zip(block, encrypted_fb[:len(block)]))
        
        return ciphertext
    
    def decrypt_ofb(self, ciphertext: bytes, iv: bytes) -> bytes:
        """OFB模式解密（与加密相同）"""
        # OFB模式加密和解密是相同的操作
        return self.encrypt_ofb(ciphertext, iv)
    
    def encrypt_ctr(self, plaintext: bytes, iv: bytes) -> bytes:
        """CTR模式加密"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        
        if len(iv) != 16:
            raise ValueError("IV length must be 16 bytes")
        
        ciphertext = b''
        counter = int.from_bytes(iv, 'big')
        
        for i in range(0, len(plaintext), 16):
            # 加密计数器
            counter_bytes = counter.to_bytes(16, 'big')
            encrypted_counter = self._process_block(counter_bytes, is_encrypt=True)
            
            # 明文与加密计数器异或
            block = plaintext[i:i+16]
            if len(block) == 16:
                ciphertext += bytes(a ^ b for a, b in zip(block, encrypted_counter))
            else:
                # 最后一块可能少于16字节
                ciphertext += bytes(a ^ b for a, b in zip(block, encrypted_counter[:len(block)]))
            
            # 增加计数器
            counter = (counter + 1) & 0xffffffffffffffffffffffffffffffff
        
        return ciphertext
    
    def decrypt_ctr(self, ciphertext: bytes, iv: bytes) -> bytes:
        """CTR模式解密（与加密相同）"""
        # CTR模式加密和解密是相同的操作
        return self.encrypt_ctr(ciphertext, iv)
    
    def encrypt_xts(self, plaintext: bytes, key2: bytes, tweak: bytes) -> bytes:
        """XTS模式加密（需要两个密钥）"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if isinstance(tweak, str):
            tweak = tweak.encode('utf-8')
        
        if len(key2) != 16:
            raise ValueError("Second key length must be 16 bytes")
        if len(tweak) != 16:
            raise ValueError("Tweak length must be 16 bytes")
        
        # 使用第二个密钥加密tweak获得初始化值
        cipher2 = SM4(key2)
        tweak_value = int.from_bytes(cipher2._process_block(tweak, is_encrypt=True), 'big')
        
        ciphertext = b''
        total_len = len(plaintext)
        if total_len == 0:
            return b''
        
        if total_len < 16:
            # 单块短明文：直接用tweak加密，无需密文窃取
            tweak_bytes = tweak_value.to_bytes(16, 'big')
            tweaked_block = bytes(a ^ b for a, b in zip(plaintext, tweak_bytes))
            encrypted = self._process_block(tweaked_block, is_encrypt=True)
            return bytes(a ^ b for a, b in zip(encrypted, tweak_bytes))
        
        full_blocks = total_len // 16
        partial_len = total_len % 16
        
        # 处理除最后一个完整块外的所有完整块
        for i in range(full_blocks - 1):
            block = plaintext[i * 16:(i + 1) * 16]
            tweak_bytes = tweak_value.to_bytes(16, 'big')
            tweaked_block = bytes(a ^ b for a, b in zip(block, tweak_bytes))
            encrypted = self._process_block(tweaked_block, is_encrypt=True)
            ciphertext += bytes(a ^ b for a, b in zip(encrypted, tweak_bytes))
            tweak_value = self._gf2_mult(tweak_value)
        
        # 最后一个完整块
        last_full_block = plaintext[(full_blocks - 1) * 16:full_blocks * 16]
        tweak_bytes = tweak_value.to_bytes(16, 'big')
        if partial_len == 0:
            tweaked_block = bytes(a ^ b for a, b in zip(last_full_block, tweak_bytes))
            encrypted = self._process_block(tweaked_block, is_encrypt=True)
            ciphertext += bytes(a ^ b for a, b in zip(encrypted, tweak_bytes))
        else:
            partial_block = plaintext[full_blocks * 16:]
            # 加密最后一个完整块获得临时密文，用于密文窃取
            temp = self._process_block(bytes(a ^ b for a, b in zip(last_full_block, tweak_bytes)), is_encrypt=True)
            c_n = bytes(a ^ b for a, b in zip(temp, tweak_bytes))
            c_star = c_n[:partial_len]
            # 构造伪明文块 P' = P_last[:16-partial_len] || P_partial
            p_prime = last_full_block[:16 - partial_len] + partial_block
            c_last = self._process_block(bytes(a ^ b for a, b in zip(p_prime, tweak_bytes)), is_encrypt=True)
            ciphertext += bytes(a ^ b for a, b in zip(c_last, tweak_bytes))
            ciphertext += c_star
        
        return ciphertext
    
    def decrypt_xts(self, ciphertext: bytes, key2: bytes, tweak: bytes) -> bytes:
        """XTS模式解密"""
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        if isinstance(tweak, str):
            tweak = tweak.encode('utf-8')
        
        if len(key2) != 16:
            raise ValueError("Second key length must be 16 bytes")
        if len(tweak) != 16:
            raise ValueError("Tweak length must be 16 bytes")
        
        # 使用第二个密钥加密tweak获得初始化值
        cipher2 = SM4(key2)
        tweak_value = int.from_bytes(cipher2._process_block(tweak, is_encrypt=True), 'big')
        
        total_len = len(ciphertext)
        if total_len == 0:
            return b''
        full_blocks = total_len // 16
        partial_len = total_len % 16
        
        if full_blocks == 0:
            raise ValueError("XTS密文长度至少需要一个完整块")
        
        plaintext = b''
        total_len = len(ciphertext)
        if total_len == 0:
            return b''
        
        if total_len < 16:
            # 单块短密文：直接用tweak解密
            tweak_bytes = tweak_value.to_bytes(16, 'big')
            decrypted = self._process_block(bytes(a ^ b for a, b in zip(ciphertext, tweak_bytes)), is_encrypt=False)
            return bytes(a ^ b for a, b in zip(decrypted, tweak_bytes))
        
        full_blocks = total_len // 16
        partial_len = total_len % 16
            for i in range(full_blocks):
                block = ciphertext[i * 16:(i + 1) * 16]
                tweak_bytes = tweak_value.to_bytes(16, 'big')
                decrypted = self._process_block(bytes(a ^ b for a, b in zip(block, tweak_bytes)), is_encrypt=False)
                plaintext += bytes(a ^ b for a, b in zip(decrypted, tweak_bytes))
                tweak_value = self._gf2_mult(tweak_value)
        else:
            if full_blocks < 1:
                raise ValueError("XTS密文损坏：缺少完整块")
            for i in range(full_blocks - 1):
                block = ciphertext[i * 16:(i + 1) * 16]
                tweak_bytes = tweak_value.to_bytes(16, 'big')
                decrypted = self._process_block(bytes(a ^ b for a, b in zip(block, tweak_bytes)), is_encrypt=False)
                plaintext += bytes(a ^ b for a, b in zip(decrypted, tweak_bytes))
                tweak_value = self._gf2_mult(tweak_value)
            
            last_full_block = ciphertext[(full_blocks - 1) * 16:full_blocks * 16]
            c_star = ciphertext[full_blocks * 16:]
            tweak_bytes = tweak_value.to_bytes(16, 'big')
            # 计算 C_n = C_last[:16-partial_len] + C_star
            c_n = last_full_block[:16 - partial_len] + c_star
            # P_n = SM4_decrypt(C_n ^ tweak) ^ tweak
            p_n = self._process_block(bytes(a ^ b for a, b in zip(c_n, tweak_bytes)), is_encrypt=False)
            p_n = bytes(a ^ b for a, b in zip(p_n, tweak_bytes))
            # P' = SM4_decrypt(C_last ^ tweak) ^ tweak
            p_prime = self._process_block(bytes(a ^ b for a, b in zip(last_full_block, tweak_bytes)), is_encrypt=False)
            p_prime = bytes(a ^ b for a, b in zip(p_prime, tweak_bytes))
            # P_s = P'[16-partial_len:]
            p_s = p_prime[16 - partial_len:]
            plaintext += p_n + p_s
        
        return plaintext
    
    @staticmethod
    def _gf2_mult(x: int) -> int:
        """GF(2)中乘以2（用于XTS模式的tweak值更新）"""
        # x是128位值（16字节）
        msb = (x >> 127) & 1
        result = ((x << 1) & ((1 << 128) - 1)) ^ (0x87 if msb else 0)
        return result
    
    def compute_mac(self, plaintext: bytes, mac_length: int = 16) -> bytes:
        """计算MAC（简化版本）"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # 使用CBC-MAC方式计算
        # 这是一个简化实现，真实的GM/T标准可能有不同的细节
        plaintext = self._pkcs7_pad(plaintext)
        
        mac_block = b'\x00' * 16
        
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            xored = bytes(a ^ b for a, b in zip(block, mac_block))
            mac_block = self._process_block(xored, is_encrypt=True)
        
        return mac_block[:mac_length]
    
    def verify_mac(self, plaintext: bytes, mac: bytes) -> bool:
        """验证MAC"""
        computed_mac = self.compute_mac(plaintext, len(mac))
        return computed_mac == mac
    
    # 兼容旧接口
    def encrypt(self, plaintext: bytes, padding: bool = True) -> bytes:
        """加密（默认ECB模式，向后兼容）"""
        return self.encrypt_ecb(plaintext, padding)
    
    def decrypt(self, ciphertext: bytes, padding: bool = True) -> bytes:
        """解密（默认ECB模式，向后兼容）"""
        return self.decrypt_ecb(ciphertext, padding)


# 便利函数
def sm4_encrypt(key: Union[bytes, str], plaintext: Union[bytes, str], 
                mode: str = 'ECB', iv: Optional[bytes] = None, 
                padding: bool = True) -> Union[bytes, Tuple[bytes, bytes]]:
    """SM4加密便利函数"""
    cipher = SM4(key)
    
    mode = mode.upper()
    
    if mode == 'ECB':
        return cipher.encrypt_ecb(plaintext, padding)
    elif mode == 'CBC':
        if iv is None:
            raise ValueError("IV required for CBC mode")
        return cipher.encrypt_cbc(plaintext, iv, padding)
    elif mode == 'CFB':
        if iv is None:
            raise ValueError("IV required for CFB mode")
        return cipher.encrypt_cfb(plaintext, iv)
    elif mode == 'OFB':
        if iv is None:
            raise ValueError("IV required for OFB mode")
        return cipher.encrypt_ofb(plaintext, iv)
    elif mode == 'CTR':
        if iv is None:
            raise ValueError("IV required for CTR mode")
        return cipher.encrypt_ctr(plaintext, iv)
    elif mode == 'XTS':
        raise NotImplementedError("XTS mode requires key2 and tweak parameters")
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def sm4_decrypt(key: Union[bytes, str], ciphertext: Union[bytes, str],
                mode: str = 'ECB', iv: Optional[bytes] = None,
                padding: bool = True) -> bytes:
    """SM4解密便利函数"""
    cipher = SM4(key)
    
    mode = mode.upper()
    
    if mode == 'ECB':
        return cipher.decrypt_ecb(ciphertext, padding)
    elif mode == 'CBC':
        if iv is None:
            raise ValueError("IV required for CBC mode")
        return cipher.decrypt_cbc(ciphertext, iv, padding)
    elif mode == 'CFB':
        if iv is None:
            raise ValueError("IV required for CFB mode")
        return cipher.decrypt_cfb(ciphertext, iv)
    elif mode == 'OFB':
        if iv is None:
            raise ValueError("IV required for OFB mode")
        return cipher.decrypt_ofb(ciphertext, iv)
    elif mode == 'CTR':
        if iv is None:
            raise ValueError("IV required for CTR mode")
        return cipher.decrypt_ctr(ciphertext, iv)
    elif mode == 'XTS':
        raise NotImplementedError("XTS mode requires key2 and tweak parameters")
    else:
        raise ValueError(f"Unsupported mode: {mode}")
