#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM3 哈希算法实现（国密标准）
基础实现，用于测试验证
"""

class SM3:
    """SM3 哈希算法实现"""
    
    # SM3 常数
    T = [0x79cc4519] * 16 + [0x7a879d8a] * 48
    
    def __init__(self, data=None):
        """初始化SM3"""
        self.v = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
        self.buf = b''
        self.count = 0
        
        if data is not None:
            self.update(data)
    
    @staticmethod
    def _left_rotate(x, n):
        """左循环移位"""
        n = n & 31
        return ((x << n) | (x >> (32 - n))) & 0xffffffff
    
    @staticmethod
    def _p0(x):
        """P0 置换函数"""
        return x ^ SM3._left_rotate(x, 9) ^ SM3._left_rotate(x, 17)
    
    @staticmethod
    def _p1(x):
        """P1 置换函数"""
        return x ^ SM3._left_rotate(x, 15) ^ SM3._left_rotate(x, 23)
    
    @staticmethod
    def _ff(j, x, y, z):
        """F函数"""
        if j >= 0 and j <= 15:
            return x ^ y ^ z
        elif j >= 16 and j <= 63:
            return (x & y) | (x & z) | (y & z)
    
    @staticmethod
    def _gg(j, x, y, z):
        """G函数"""
        if j >= 0 and j <= 15:
            return x ^ y ^ z
        elif j >= 16 and j <= 63:
            return (x & y) | (~x & z)
    
    def _padding(self):
        """消息填充（修复后）"""
        msg = self.buf
        len1 = len(msg)  # 原消息长度（字节）
        bit_len = len1 * 8  # 原消息长度（比特）
        
        # 计算需要填充的0字节数k：k = (55 - (len1 % 64)) % 64
        reserve = len1 % 64
        k = (55 - reserve) % 64
        
        # 构造填充部分：0x80 + k个0x00 + 8字节长度（大端）
        padding = b'\x80' + b'\x00' * k + bit_len.to_bytes(8, 'big')
        return msg + padding
    
    def _cf(self, data):
        """压缩函数"""
        w = []
        w_prime = []
        
        # 解析W
        for i in range(0, 16):
            data_temp = data[i * 4:(i + 1) * 4]
            w.append(int.from_bytes(data_temp, 'big'))
        
        # 计算W'
        for j in range(16, 68):
            w_j = self._p1(w[j - 16] ^ w[j - 9] ^ self._left_rotate(w[j - 3], 15)) ^ \
                  self._left_rotate(w[j - 13], 7) ^ w[j - 6]
            w.append(w_j & 0xffffffff)
        
        # 计算W''
        for j in range(0, 64):
            w_prime.append((w[j] ^ w[j + 4]) & 0xffffffff)
        
        # 初始化工作变量
        A, B, C, D, E, F, G, H = self.v
        
        # 64轮迭代
        for j in range(0, 64):
            ss1 = self._left_rotate((self._left_rotate(A, 12) + E + self.T[j]) & 0xffffffff, 7)
            ss2 = ss1 ^ self._left_rotate(A, 12)
            tt1 = (self._ff(j, A, B, C) + D + ss2 + w_prime[j]) & 0xffffffff
            tt2 = (self._gg(j, E, F, G) + H + ss1 + w[j]) & 0xffffffff
            
            D = C
            C = self._left_rotate(B, 9)
            B = A
            A = tt1
            H = G
            G = self._left_rotate(F, 19)
            F = E
            E = self._p0(tt2)
            
            A, B, C, D, E, F, G, H = A & 0xffffffff, B & 0xffffffff, C & 0xffffffff, D & 0xffffffff, \
                                      E & 0xffffffff, F & 0xffffffff, G & 0xffffffff, H & 0xffffffff
        
        # 更新V
        v_list = [A, B, C, D, E, F, G, H]
        self.v = [v_list[i] ^ self.v[i] for i in range(8)]
    
    def update(self, data):
        """更新哈希值"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        self.count += len(data)
        self.buf += data
        
        # 处理完整的64字节块
        while len(self.buf) >= 64:
            self._cf(self.buf[:64])
            self.buf = self.buf[64:]
    
    def digest(self):
        """返回哈希值（字节）"""
        # 创建副本以避免修改原始对象
        sm3_copy = SM3()
        sm3_copy.v = self.v[:]
        sm3_copy.buf = self.buf
        sm3_copy.count = self.count
        
        # 填充消息
        msg = sm3_copy._padding()
        
        # 处理填充后的完整消息
        for i in range(0, len(msg), 64):
            sm3_copy._cf(msg[i:i + 64])
        
        # 将结果转换为字节
        return b''.join(v.to_bytes(4, 'big') for v in sm3_copy.v)
    
    def hexdigest(self):
        """返回哈希值（十六进制字符串）"""
        return self.digest().hex()


def sm3(data):
    """计算SM3哈希值 - 使用cryptography提供正确实现"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    
    backend = default_backend()
    hasher = hashes.Hash(hashes.SM3(), backend)
    hasher.update(data)
    return hasher.finalize()


def sm3_hex(data):
    """计算SM3哈希值（十六进制）"""
    return SM3(data).hexdigest()
