#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2 椭圆曲线公钥密码算法实现（国密标准）
基础实现，用于测试验证
"""

import os
import hashlib
from typing import Tuple, Optional
from src.sm3.sm3_impl import sm3

# 尝试使用cryptography库的SM3，如果不可用则使用自定义实现
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    
    def sm3_crypto(data: bytes) -> bytes:
        """使用cryptography库的SM3实现"""
        digest = hashes.Hash(hashes.SM3(), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    # 替换sm3函数
    sm3 = sm3_crypto
    print("使用cryptography库的SM3实现")
    
except ImportError:
    print("使用自定义SM3实现")


class SM2Curve:
    """SM2 椭圆曲线参数"""
    # SM2 曲线参数 (Fp-256)
    P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF  # 素数模
    A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC  # 曲线参数a
    B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93   # 曲线参数b
    N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123   # 基点阶
    G_X = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7   # 基点x坐标
    G_Y = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0   # 基点y坐标

    @classmethod
    def get_generator(cls) -> Tuple[int, int]:
        """获取基点"""
        return (cls.G_X, cls.G_Y)


class SM2Point:
    """SM2 椭圆曲线点"""

    def __init__(self, x: int, y: int, curve: SM2Curve = None):
        self.x = x
        self.y = y
        self.curve = curve or SM2Curve()

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        return f"SM2Point({self.x:064X}, {self.y:064X})"

    def is_infinity(self) -> bool:
        """检查是否为无穷远点"""
        return self.x == 0 and self.y == 0

    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """模逆运算"""
        m0, y, x = m, 0, 1
        if m == 1:
            return 0
        while a > 1:
            q = a // m
            t = m
            m = a % m
            a = t
            t = y
            y = x - q * y
            x = t
        if x < 0:
            x += m0
        return x

    def negate(self) -> 'SM2Point':
        """点取负"""
        return SM2Point(self.x, (self.curve.P - self.y) % self.curve.P, self.curve)

    def add(self, other: 'SM2Point') -> 'SM2Point':
        """点加法"""
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self

        p = self.curve.P

        if self.x == other.x:
            if self.y == other.y:
                # 点倍加
                if self.y == 0:
                    return SM2Point(0, 0, self.curve)  # 无穷远点

                # 计算斜率 λ = (3x² + a) / (2y)
                numerator = (3 * self.x * self.x + self.curve.A) % p
                denominator = (2 * self.y) % p
                lam = (numerator * self.mod_inverse(denominator, p)) % p
            else:
                return SM2Point(0, 0, self.curve)  # 无穷远点
        else:
            # 普通点加
            # λ = (y₂ - y₁) / (x₂ - x₁)
            numerator = (other.y - self.y) % p
            denominator = (other.x - self.x) % p
            lam = (numerator * self.mod_inverse(denominator, p)) % p

        # 计算新点坐标
        x3 = (lam * lam - self.x - other.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p

        return SM2Point(x3, y3, self.curve)

    def multiply(self, k: int) -> 'SM2Point':
        """点乘法（标量乘法）"""
        result = SM2Point(0, 0, self.curve)  # 无穷远点
        current = SM2Point(self.x, self.y, self.curve)

        while k > 0:
            if k & 1:
                result = result.add(current)
            current = current.add(current)
            k >>= 1

        return result


class SM2:
    """SM2 椭圆曲线公钥密码算法"""

    def __init__(self):
        self.curve = SM2Curve()

    def generate_keypair(self) -> Tuple[int, SM2Point]:
        """生成密钥对"""
        # 简化的密钥生成（实际应使用更安全的随机数）
        private_key = int.from_bytes(os.urandom(32), 'big') % self.curve.N
        if private_key == 0:
            private_key = 1

        generator = SM2Point(self.curve.G_X, self.curve.G_Y, self.curve)
        public_key = generator.multiply(private_key)

        return private_key, public_key

    def _kdf(self, z: bytes, klen: int) -> bytes:
        """密钥派生函数 (KDF) - 正确的SM2实现"""
        result = b''
        counter = 1
        while len(result) < klen:
            ct = counter.to_bytes(4, 'big')
            hash_result = sm3(z + ct)
            result += hash_result
            counter += 1
        return result[:klen]

    def encrypt(self, public_key: SM2Point, plaintext: bytes, k_hex: str = None) -> bytes:
        """SM2 加密"""
        try:
            # 生成随机数 k
            if k_hex is not None:
                k = int(k_hex, 16)
            else:
                k = int.from_bytes(os.urandom(32), 'big') % self.curve.N
                if k == 0:
                    k = 1

            # 计算 C1 = k * G
            generator = SM2Point(self.curve.G_X, self.curve.G_Y, self.curve)
            c1 = generator.multiply(k)

            # 计算 k * PB = (x2, y2)
            pb = public_key.multiply(k)

            # 计算 t = KDF(x2 || y2, klen)
            x2_bytes = pb.x.to_bytes(32, 'big')
            y2_bytes = pb.y.to_bytes(32, 'big')
            t = self._kdf(x2_bytes + y2_bytes, len(plaintext))

            # 如果 t 全为0，重新生成 k
            if all(b == 0 for b in t):
                return self.encrypt(public_key, plaintext)

            # 计算 C2 = M ⊕ t
            c2 = bytes(a ^ b for a, b in zip(plaintext, t))

            # 计算 C3 = Hash(x2 || M || y2)
            x2_bytes = pb.x.to_bytes(32, 'big')
            y2_bytes = pb.y.to_bytes(32, 'big')
            c3 = sm3(x2_bytes + plaintext + y2_bytes)

            # 构造密文 C = C1 || C2 || C3
            c1_x = c1.x.to_bytes(32, 'big')
            c1_y = c1.y.to_bytes(32, 'big')
            ciphertext = c1_x + c1_y + c2 + c3

            return ciphertext

        except Exception as e:
            raise ValueError(f"SM2 encryption failed: {e}")

    def decrypt(self, private_key: int, ciphertext: bytes) -> bytes:
        """SM2 解密"""
        try:
            if len(ciphertext) < 96:  # C1(64) + C3(32) + C2至少1字节
                raise ValueError("Ciphertext too short")

            # 解析密文 C1 || C2 || C3
            c1_x = int.from_bytes(ciphertext[0:32], 'big')
            c1_y = int.from_bytes(ciphertext[32:64], 'big')
            c1 = SM2Point(c1_x, c1_y, self.curve)

            c2 = ciphertext[64:64+len(ciphertext)-96]  # C2 长度 = 总长度 - 96
            c3 = ciphertext[64+len(c2):]  # C3 32字节

            # 计算 dB * C1 = (x2, y2)
            pb = c1.multiply(private_key)

            # 计算 t = KDF(x2 || y2, klen)
            x2_bytes = pb.x.to_bytes(32, 'big')
            y2_bytes = pb.y.to_bytes(32, 'big')
            t = self._kdf(x2_bytes + y2_bytes, len(c2))

            # 如果 t 全为0，解密失败
            if all(b == 0 for b in t):
                raise ValueError("Invalid ciphertext")

            # 计算 M = C2 ⊕ t
            plaintext = bytes(a ^ b for a, b in zip(c2, t))

            # 验证 C3 = Hash(x2 || M || y2)
            expected_c3 = sm3(x2_bytes + plaintext + y2_bytes)
            if expected_c3 != c3:
                raise ValueError("Ciphertext verification failed")

            return plaintext

        except Exception as e:
            raise ValueError(f"SM2 decryption failed: {e}")

    def sign(self, private_key: int, message_or_e: bytes, user_id: bytes = b"1234567812345678", k: int = None, use_precomputed_e: bool = False, public_key: SM2Point = None) -> bytes:
        """SM2 签名"""
        try:
            if use_precomputed_e:
                # 直接使用提供的e值
                e = int.from_bytes(message_or_e, 'big')
            else:
                # 计算 ZA = Hash(ENTLA || IDA || a || b || xG || yG || xA || yA)
                id_len = len(user_id) * 8
                entla = id_len.to_bytes(2, 'big')
                
                # 如果提供了公钥，包含在ZA计算中
                if public_key is not None:
                    za = sm3(entla + user_id +
                            self.curve.A.to_bytes(32, 'big') +
                            self.curve.B.to_bytes(32, 'big') +
                            self.curve.G_X.to_bytes(32, 'big') +
                            self.curve.G_Y.to_bytes(32, 'big') +
                            public_key.x.to_bytes(32, 'big') +
                            public_key.y.to_bytes(32, 'big'))
                else:
                    # 否则只使用曲线参数
                    za = sm3(entla + user_id +
                            self.curve.A.to_bytes(32, 'big') +
                            self.curve.B.to_bytes(32, 'big') +
                            self.curve.G_X.to_bytes(32, 'big') +
                            self.curve.G_Y.to_bytes(32, 'big'))

                # 计算 M' = ZA || M
                m_prime = za + message_or_e

                # 计算 e = Hash(M')
                e = int.from_bytes(sm3(m_prime), 'big')

            # 生成随机数 k
            if k is None:
                k = int.from_bytes(os.urandom(32), 'big') % self.curve.N
                if k == 0:
                    k = 1
            else:
                k = k % self.curve.N
                if k == 0:
                    k = 1

            # 计算 (x1, y1) = k * G
            generator = SM2Point(self.curve.G_X, self.curve.G_Y, self.curve)
            p1 = generator.multiply(k)

            # 计算 r = (e + x1) mod n
            r = (e + p1.x) % self.curve.N
            if r == 0 or r + k == self.curve.N:
                # 重新生成 k
                return self.sign(private_key, message_or_e, user_id, use_precomputed_e=use_precomputed_e)

            # 计算 s = (1 + dA)^(-1) * (k - r * dA) mod n
            d_inv = self.mod_inverse((1 + private_key) % self.curve.N, self.curve.N)
            s = (d_inv * (k - r * private_key % self.curve.N) % self.curve.N) % self.curve.N

            if s == 0:
                return self.sign(private_key, message_or_e, user_id, use_precomputed_e=use_precomputed_e)

            # 返回签名 (r, s)
            r_bytes = r.to_bytes(32, 'big')
            s_bytes = s.to_bytes(32, 'big')
            return r_bytes + s_bytes

        except Exception as e:
            raise ValueError(f"SM2 signing failed: {e}")

    def verify(self, public_key: SM2Point, message_or_e: bytes, signature: bytes,
               user_id: bytes = b"1234567812345678", use_precomputed_e: bool = False) -> bool:
        """SM2 验签"""
        try:
            if len(signature) != 64:
                return False

            r = int.from_bytes(signature[0:32], 'big')
            s = int.from_bytes(signature[32:64], 'big')

            # 检查 r, s 范围
            if not (1 <= r <= self.curve.N - 1) or not (1 <= s <= self.curve.N - 1):
                return False

            if use_precomputed_e:
                # 直接使用提供的e值
                e = int.from_bytes(message_or_e, 'big')
            else:
                # 计算 ZA
                id_len = len(user_id) * 8
                entla = id_len.to_bytes(2, 'big')
                za = sm3(entla + user_id +
                        self.curve.A.to_bytes(32, 'big') +
                        self.curve.B.to_bytes(32, 'big') +
                        self.curve.G_X.to_bytes(32, 'big') +
                        self.curve.G_Y.to_bytes(32, 'big') +
                        public_key.x.to_bytes(32, 'big') +
                        public_key.y.to_bytes(32, 'big'))

                # 计算 M' = ZA || M
                m_prime = za + message_or_e

                # 计算 e = Hash(M')
                e = int.from_bytes(sm3(m_prime), 'big')

            # 计算 t = (r + s) mod n
            t = (r + s) % self.curve.N
            if t == 0:
                return False

            # 计算 (x1', y1') = s*G + t*PA
            generator = SM2Point(self.curve.G_X, self.curve.G_Y, self.curve)
            p1 = generator.multiply(s).add(public_key.multiply(t))

            # 计算 R = (e + x1') mod n
            expected_r = (e + p1.x) % self.curve.N

            return expected_r == r

        except Exception as e:
            return False

    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """模逆运算"""
        return SM2Point.mod_inverse(a, m)


# 全局SM2实例
sm2_instance = SM2()


def sm2_encrypt(public_key_hex: str, plaintext_hex: str, k_hex: str = None) -> str:
    """SM2 加密接口"""
    try:
        # 解析公钥
        public_key_x = int(public_key_hex[:64], 16)
        public_key_y = int(public_key_hex[64:], 16)
        public_key = SM2Point(public_key_x, public_key_y)

        # 解析明文
        plaintext = bytes.fromhex(plaintext_hex)

        # 执行加密
        ciphertext = sm2_instance.encrypt(public_key, plaintext, k_hex)

        return ciphertext.hex().upper()

    except ValueError as e:
        # 对于输入格式错误，抛出异常
        raise ValueError(f"Invalid input format: {e}")
    except Exception as e:
        raise ValueError(f"SM2 encryption failed: {e}")


def sm2_decrypt(private_key_hex: str, ciphertext_hex: str) -> str:
    """SM2 解密接口"""
    try:
        # 解析私钥
        private_key = int(private_key_hex, 16)

        # 解析密文
        ciphertext = bytes.fromhex(ciphertext_hex)

        # 解密
        plaintext = sm2_instance.decrypt(private_key, ciphertext)

        return plaintext.hex().upper()

    except ValueError as e:
        # 对于输入格式错误，抛出异常
        raise ValueError(f"Invalid input format: {e}")
    except Exception as e:
        raise ValueError(f"SM2 decryption failed: {e}")


def sm2_sign(private_key_hex: str, message_or_e_hex: str, user_id_hex: str = "31323334353637383132333435363738", k_hex: str = None, use_precomputed_e: bool = False, public_key_hex: str = None) -> str:
    """SM2 签名接口"""
    try:
        # 解析私钥
        private_key = int(private_key_hex, 16)

        # 解析消息或e
        message_or_e = bytes.fromhex(message_or_e_hex)

        # 解析用户ID
        user_id = bytes.fromhex(user_id_hex)

        # 解析k（如果提供）
        k = int(k_hex, 16) if k_hex else None

        # 解析公钥（如果提供）
        public_key = None
        if public_key_hex:
            public_key_x = int(public_key_hex[:64], 16)
            public_key_y = int(public_key_hex[64:], 16)
            public_key = SM2Point(public_key_x, public_key_y)

        # 签名
        signature = sm2_instance.sign(private_key, message_or_e, user_id, k, use_precomputed_e, public_key)

        return signature.hex().upper()

    except Exception as e:
        raise ValueError(f"SM2 signing failed: {e}")


def sm2_verify(public_key_hex: str, message_hex: str, signature_hex: str,
               user_id_hex: str = "31323334353637383132333435363738", use_precomputed_e: bool = False) -> bool:
    """SM2 验签接口"""
    try:
        # 解析公钥
        public_key_x = int(public_key_hex[:64], 16)
        public_key_y = int(public_key_hex[64:], 16)
        public_key = SM2Point(public_key_x, public_key_y)

        # 解析消息或e
        message = bytes.fromhex(message_hex)

        # 解析签名
        signature = bytes.fromhex(signature_hex)

        # 解析用户ID
        user_id = bytes.fromhex(user_id_hex)

        # 验签
        return sm2_instance.verify(public_key, message, signature, user_id, use_precomputed_e)

    except ValueError as e:
        # 对于输入格式错误，抛出异常
        raise ValueError(f"Invalid input format: {e}")
    except Exception as e:
        # 对于其他异常（如验签失败），返回False
        return False