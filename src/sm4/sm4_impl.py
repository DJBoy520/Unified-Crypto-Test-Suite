#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4 分组密码算法实现（国密标准）
基础实现，用于测试验证
"""

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
    
    def __init__(self, key):
        """初始化SM4"""
        if isinstance(key, str):
            key = key.encode('utf-8')
        if len(key) != 16:
            raise ValueError("Key length must be 16 bytes")
        
        # 密钥展开
        self.rk = self._expand_key(key)
    
    def _expand_key(self, key):
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
    
    def _process_block(self, block, is_encrypt=True):
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
    
    def encrypt(self, plaintext):
        """加密（PKCS#7填充）"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # PKCS#7填充
        plaintext = self._pkcs7_pad(plaintext)
        
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            ciphertext += self._process_block(plaintext[i:i+16], is_encrypt=True)
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        """解密（PKCS#7去填充）"""
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")
        
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            plaintext += self._process_block(ciphertext[i:i+16], is_encrypt=False)
        
        # PKCS#7去填充
        return self._pkcs7_unpad(plaintext)
    
    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        """ECB模式加密（PKCS#7填充）"""
        if len(plaintext) % 16 != 0:
            plaintext = self._pkcs7_pad(plaintext)
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            ciphertext += self._process_block(plaintext[i:i+16], is_encrypt=True)
        return ciphertext
    
    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """ECB模式解密（PKCS#7去填充）"""
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            plaintext += self._process_block(ciphertext[i:i+16], is_encrypt=False)
        return self._pkcs7_unpad(plaintext)
    
    def _pkcs7_pad(self, data: bytes, block_size: int = 16) -> bytes:
        """PKCS#7填充"""
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)
    
    def _pkcs7_unpad(self, data: bytes) -> bytes:
        """PKCS#7去填充"""
        if not data:
            return data
        pad_len = data[-1]
        if 1 <= pad_len <= 16 and all(b == pad_len for b in data[-pad_len:]):
            return data[:-pad_len]
        return data


def sm4_encrypt(key, plaintext):
    """SM4加密"""
    cipher = SM4(key)
    return cipher.encrypt(plaintext)


def sm4_decrypt(key, ciphertext):
    """SM4解密"""
    cipher = SM4(key)
    return cipher.decrypt(ciphertext)
