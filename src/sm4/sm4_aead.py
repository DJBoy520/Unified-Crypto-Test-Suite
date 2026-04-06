#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4 AEAD模式实现（GCM, HCTR等）
"""

from typing import Tuple, Optional, Union
from .sm4_multimode import SM4


class SM4_AEAD:
    """SM4 AEAD模式实现"""
    
    @staticmethod
    def _gf128_mult(x: bytes, y: bytes) -> bytes:
        """GF(128)中的乘法（用于GCM）"""
        # 将x和y转换为128位整数（大端）
        x_int = int.from_bytes(x, 'big')
        y_int = int.from_bytes(y, 'big')
        
        result = 0
        for i in range(128):
            if (x_int >> i) & 1:
                result ^= y_int
            
            # 检查y的最高位
            msb = (y_int >> 127) & 1
            y_int = ((y_int << 1) & ((1 << 128) - 1)) ^ (0x87 if msb else 0)
        
        return result.to_bytes(16, 'big')
    
    @staticmethod
    def _gcm_mult(x: bytes, y: bytes) -> bytes:
        """GF(2^128) 乘法，用于GCM GHASH。"""
        x_int = int.from_bytes(x, 'big')
        y_int = int.from_bytes(y, 'big')
        z = 0
        v = y_int
        for i in range(128):
            if (x_int >> (127 - i)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ 0xE1000000000000000000000000000000
            else:
                v >>= 1
        return z.to_bytes(16, 'big')

    @staticmethod
    def _ghash(h: bytes, data: bytes) -> bytes:
        """计算GHASH(H, data)。"""
        y = b'\x00' * 16
        padded = data
        if len(padded) % 16 != 0:
            padded += b'\x00' * (16 - len(padded) % 16)
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            y = bytes(a ^ b for a, b in zip(y, block))
            y = SM4_AEAD._gcm_mult(y, h)
        return y

    @staticmethod
    def encrypt_gcm(cipher_obj: SM4, plaintext: bytes, iv: bytes, 
                   aad: Optional[bytes] = None, tag_length: int = 16) -> Tuple[bytes, bytes]:
        """
        SM4 GCM模式加密
        
        Args:
            cipher_obj: SM4对象
            plaintext: 明文
            iv: 初始化向量
            aad: 附加认证数据
            tag_length: 认证标签长度
        
        Returns:
            (ciphertext, tag)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        if aad is None:
            aad = b''
        elif isinstance(aad, str):
            aad = aad.encode('utf-8')
        
        h = cipher_obj._process_block(b'\x00' * 16, is_encrypt=True)

        # 生成初始计数器 J0
        if len(iv) == 12:
            j0 = iv + b'\x00\x00\x00\x01'
        else:
            iv_len_bits = len(iv) * 8
            iv_padding = (16 - (len(iv) % 16)) % 16
            iv_data = iv + b'\x00' * iv_padding + iv_len_bits.to_bytes(8, 'big') + (0).to_bytes(8, 'big')
            j0 = SM4_AEAD._ghash(h, iv_data)

        ciphertext = b''
        counter_int = int.from_bytes(j0, 'big')
        for i in range(0, len(plaintext), 16):
            counter_int = (counter_int + 1) & ((1 << 128) - 1)
            counter_block = counter_int.to_bytes(16, 'big')
            encrypted_counter = cipher_obj._process_block(counter_block, is_encrypt=True)
            block = plaintext[i:i+16]
            ciphertext += bytes(a ^ b for a, b in zip(block, encrypted_counter[:len(block)]))

        # 计算GHASH
        aad_len_bits = len(aad) * 8
        ciphertext_len_bits = len(ciphertext) * 8
        ghash_data = aad
        if len(ghash_data) % 16 != 0:
            ghash_data += b'\x00' * (16 - len(ghash_data) % 16)
        ghash_data += ciphertext
        if len(ghash_data) % 16 != 0:
            ghash_data += b'\x00' * (16 - len(ghash_data) % 16)
        ghash_data += aad_len_bits.to_bytes(8, 'big') + ciphertext_len_bits.to_bytes(8, 'big')
        ghash_tag = SM4_AEAD._ghash(h, ghash_data)

        tag_block = cipher_obj._process_block(j0, is_encrypt=True)
        tag = bytes(a ^ b for a, b in zip(ghash_tag, tag_block))

        return ciphertext, tag[:tag_length]
    
    @staticmethod
    def decrypt_gcm(cipher_obj: SM4, ciphertext: bytes, iv: bytes,
                   tag: bytes, aad: Optional[bytes] = None) -> Optional[bytes]:
        """
        SM4 GCM模式解密和认证
        
        Returns:
            明文，如果认证失败则返回None
        """
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        if isinstance(tag, str):
            tag = tag.encode('utf-8')
        if aad is None:
            aad = b''
        elif isinstance(aad, str):
            aad = aad.encode('utf-8')
        
        # 生成初始计数器 J0
        if len(iv) == 12:
            j0 = iv + b'\x00\x00\x00\x01'
        else:
            h = cipher_obj._process_block(b'\x00' * 16, is_encrypt=True)
            iv_len_bits = len(iv) * 8
            iv_padding = (16 - (len(iv) % 16)) % 16
            iv_data = iv + b'\x00' * iv_padding + iv_len_bits.to_bytes(8, 'big') + (0).to_bytes(8, 'big')
            j0 = SM4_AEAD._ghash(h, iv_data)

        # 解密
        plaintext = b''
        counter_int = int.from_bytes(j0, 'big')
        
        for i in range(0, len(ciphertext), 16):
            counter_int = (counter_int + 1) & ((1 << 128) - 1)
            counter_bytes = counter_int.to_bytes(16, 'big')
            
            encrypted_counter = cipher_obj._process_block(counter_bytes, is_encrypt=True)
            
            block = ciphertext[i:i+16]
            if len(block) == 16:
                plaintext += bytes(a ^ b for a, b in zip(block, encrypted_counter))
            else:
                plaintext += bytes(a ^ b for a, b in zip(block, encrypted_counter[:len(block)]))
        
        # 验证认证标签
        # 3. 直接计算GHASH验证Tag（替代复用encrypt_gcm）
        h = cipher_obj._process_block(b'\x00'*16, is_encrypt=True)
        aad_len_bits = len(aad)*8
        ct_len_bits = len(ciphertext)*8
        ghash_data = aad.ljust((len(aad)+15)//16 * 16, b'\x00') + \
                     ciphertext.ljust((len(ciphertext)+15)//16 * 16, b'\x00') + \
                     aad_len_bits.to_bytes(8, 'big') + ct_len_bits.to_bytes(8, 'big')
        ghash_tag = SM4_AEAD._ghash(h, ghash_data)
        tag_block = cipher_obj._process_block(j0, is_encrypt=True)
        computed_tag = bytes(a^b for a,b in zip(ghash_tag, tag_block))[:len(tag)]

        if computed_tag != tag:
            return None
        return plaintext


def sm4_encrypt_gcm(key: Union[bytes, str], plaintext: Union[bytes, str],
                   iv: Union[bytes, str], aad: Optional[Union[bytes, str]] = None,
                   tag_length: int = 16) -> Tuple[bytes, bytes]:
    """SM4 GCM加密便利函数"""
    cipher = SM4(key)
    return SM4_AEAD.encrypt_gcm(cipher, plaintext, iv, aad, tag_length)


def sm4_decrypt_gcm(key: Union[bytes, str], ciphertext: Union[bytes, str],
                   iv: Union[bytes, str], tag: Union[bytes, str],
                   aad: Optional[Union[bytes, str]] = None) -> Optional[bytes]:
    """SM4 GCM解密便利函数"""
    cipher = SM4(key)
    return SM4_AEAD.decrypt_gcm(cipher, ciphertext, iv, tag, aad)


# 添加GF(2¹²⁸)乘法边界测试（用SM4_GCM_ENC.txt的第一条用例验证_gcm_mult）
test_x = bytes.fromhex("ffffffffffffffffffffffffffffffff")
test_y = bytes.fromhex("e1000000000000000000000000000000")
assert SM4_AEAD._gcm_mult(test_x, test_y) == b'\x87' + b'\x00'*15  # 验证乘法结果
