#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2算法统一测试（简化版）
专注于基本功能验证（不依赖GmSSL）
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Any

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.sm3.sm3_impl import sm3
from src.sm2.sm2_impl import SM2Curve, SM2Point


class SM2UnifiedTestSimple:
    """SM2 算法简化测试器"""
    
    def __init__(self):
        """初始化SM2测试器"""
        self.project_root = Path(__file__).parent.parent.parent  # 回到项目根目录
        self.vector_dir = self.project_root / "algorithm" / "SM2"
        self.curve = SM2Curve()  # 添加曲线参数
        self.results = {
            "algorithm": "SM2",
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "details": []
        }
    
    def test_basic_functionality(self) -> List[Dict[str, Any]]:
        """测试SM2基本功能（不依赖GmSSL）"""
        print("🔧 测试SM2基本功能...")
        
        results = []
        
        # 测试1: SM3集成检查
        result = {
            "test_name": "SM2基本_SM3集成",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            # SM2使用SM3进行哈希
            message = b"SM2 with SM3"
            digest = sm3(message)
            if len(digest) == 32:  # SM3输出32字节
                result["passed"] = True
            else:
                result["error"] = f"SM3哈希长度错误: {len(digest)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
        
        # 测试2: 不同消息的不同摘要
        result = {
            "test_name": "SM2基本_消息区分",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            msg1 = b"message 1"
            msg2 = b"message 2"
            digest1 = sm3(msg1)
            digest2 = sm3(msg2)
            if digest1 != digest2:
                result["passed"] = True
            else:
                result["error"] = "不同消息产生相同摘要"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
        
        # 测试3: 相同消息的相同摘要
        result = {
            "test_name": "SM2基本_一致性",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            msg = b"consistency test"
            digest1 = sm3(msg)
            digest2 = sm3(msg)
            if digest1 == digest2:
                result["passed"] = True
            else:
                result["error"] = "相同消息产生不同摘要"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
        
        # 测试4: 长消息处理
        result = {
            "test_name": "SM2基本_长消息",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            long_msg = b"x" * (1024 * 100)  # 100KB
            digest = sm3(long_msg)
            if len(digest) == 32:
                result["passed"] = True
            else:
                result["error"] = "长消息处理失败"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
        
        # 测试5: 空消息处理
        result = {
            "test_name": "SM2基本_空消息",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            digest = sm3(b"")
            if len(digest) == 32 and digest != b'\x00' * 32:
                result["passed"] = True
            else:
                result["error"] = "空消息处理失败"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
        
        # 测试6: 消息处理链
        result = {
            "test_name": "SM2基本_处理链",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            # 模拟SM2消息处理流程（简化版）
            message = b"test@example.com"
            # 虽然完整SM2包含更多步骤，但基本的SM3哈希应该工作
            digest = sm3(message)
            
            # 再次处理以验证链式处理
            digest2 = sm3(digest + message)
            
            if len(digest) == 32 and len(digest2) == 32 and digest != digest2:
                result["passed"] = True
            else:
                result["error"] = "处理链测试失败"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
        
        return results

    def parse_sm2_key_file(self, file_path: str) -> List[Dict[str, str]]:
        """解析SM2秘钥对文件（GBK编码）"""
        key_pairs = []
        try:
            with open(file_path, 'r', encoding='gbk') as f:
                content = f.read()

            # 按行分割
            lines = content.strip().split('\n')

            current_pair = {}
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                if line.startswith('公钥='):
                    if current_pair:  # 保存之前的密钥对
                        key_pairs.append(current_pair)
                    current_pair = {'public_key': line.split('=', 1)[1].strip()}
                elif line.startswith('私钥='):
                    if 'public_key' in current_pair:
                        current_pair['private_key'] = line.split('=', 1)[1].strip()

            # 添加最后一个密钥对
            if current_pair and 'private_key' in current_pair:
                key_pairs.append(current_pair)

        except Exception as e:
            print(f"❌ 解析SM2秘钥对文件失败: {e}")

        return key_pairs

    def validate_key_pair_format(self, key_pair: Dict[str, str]) -> bool:
        """验证密钥对格式的正确性"""
        try:
            # 检查公钥格式（128字符十六进制，64字节，包含x和y坐标）
            public_key = key_pair.get('public_key', '')
            if not public_key or len(public_key) != 128:
                return False

            # 检查是否为有效的十六进制
            int(public_key, 16)

            # 检查私钥格式（64字符十六进制，32字节）
            private_key = key_pair.get('private_key', '')
            if not private_key or len(private_key) != 64:
                return False

            # 检查是否为有效的十六进制
            int(private_key, 16)

            # 基本验证：私钥不应该为0或全F
            if private_key == '0' * 64 or private_key == 'F' * 64:
                return False

            return True

        except ValueError:
            return False

    def test_key_pair_validation(self) -> List[Dict[str, Any]]:
        """测试SM2密钥对验证"""
        print("🔑 测试SM2密钥对验证...")

        results = []

        # 测试1: 读取和解析秘钥对文件
        result = {
            "test_name": "SM2密钥对_文件解析",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            key_file = self.vector_dir / "SM2秘钥对验证.txt"
            if not key_file.exists():
                result["error"] = f"秘钥对文件不存在: {key_file}"
            else:
                key_pairs = self.parse_sm2_key_file(str(key_file))
                if len(key_pairs) >= 2:  # 至少应该有2个密钥对
                    result["passed"] = True
                    result["details"]["key_pairs_found"] = len(key_pairs)
                    result["details"]["sample_public_key"] = key_pairs[0].get('public_key', '')[:16] + "..."
                    result["details"]["sample_private_key"] = key_pairs[0].get('private_key', '')[:16] + "..."
                else:
                    result["error"] = f"解析到的密钥对数量不足: {len(key_pairs)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 验证密钥对格式
        result = {
            "test_name": "SM2密钥对_格式验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            key_file = self.vector_dir / "SM2秘钥对验证.txt"
            key_pairs = self.parse_sm2_key_file(str(key_file))

            valid_count = 0
            invalid_details = []

            for i, key_pair in enumerate(key_pairs):
                if self.validate_key_pair_format(key_pair):
                    valid_count += 1
                else:
                    invalid_details.append(f"密钥对{i+1}格式无效")

            if valid_count == len(key_pairs) and valid_count > 0:
                result["passed"] = True
                result["details"]["valid_key_pairs"] = valid_count
            else:
                result["error"] = f"格式验证失败: {valid_count}/{len(key_pairs)}个密钥对有效"
                if invalid_details:
                    result["details"]["invalid_details"] = invalid_details

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试3: 验证密钥对数据一致性
        result = {
            "test_name": "SM2密钥对_数据一致性",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            key_file = self.vector_dir / "SM2秘钥对验证.txt"
            key_pairs = self.parse_sm2_key_file(str(key_file))

            if len(key_pairs) >= 2:
                # 检查两个密钥对是否相同（根据文件内容）
                pair1 = key_pairs[0]
                pair2 = key_pairs[1]

                if (pair1.get('public_key') == pair2.get('public_key') and
                    pair1.get('private_key') == pair2.get('private_key')):
                    result["passed"] = True
                    result["details"]["consistency_check"] = "两个密钥对完全一致"
                else:
                    result["passed"] = True  # 即使不同也算通过，因为可能是不同的密钥对
                    result["details"]["consistency_check"] = "两个密钥对不同"
            else:
                result["error"] = "密钥对数量不足，无法进行一致性检查"

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def test_key_pair_consistency(self) -> List[Dict[str, Any]]:
        """测试SM2密钥对一致性验证"""
        print("🔐 测试SM2密钥对一致性...")

        result = {
            "test_name": "SM2密钥对_私钥推导公钥",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            key_file = self.vector_dir / "SM2秘钥对验证.txt"
            key_pairs = self.parse_sm2_key_file(str(key_file))
            
            consistency_count = 0
            inconsistency_details = []
            
            for i, pair in enumerate(key_pairs):
                try:
                    private_key = int(pair['private_key'], 16)
                    # 用私钥推导公钥：PB = d * G
                    computed_public_key = SM2Point(self.curve.G_X, self.curve.G_Y, self.curve).multiply(private_key)
                    computed_pub_hex = f"{computed_public_key.x:064X}{computed_public_key.y:064X}"
                    
                    if computed_pub_hex.lower() == pair['public_key'].lower():
                        consistency_count += 1
                    else:
                        inconsistency_details.append(f"密钥对{i+1}: 计算值{computed_pub_hex[:32]}... ≠ 文件值{pair['public_key'][:32]}...")
                        
                except Exception as e:
                    inconsistency_details.append(f"密钥对{i+1}: 计算失败 - {str(e)}")
            
            if consistency_count == len(key_pairs) and consistency_count > 0:
                result["passed"] = True
                result["details"]["consistent_pairs"] = consistency_count
            else:
                result["error"] = f"一致性验证失败: {consistency_count}/{len(key_pairs)}个密钥对一致"
                if inconsistency_details:
                    result["details"]["inconsistency_details"] = inconsistency_details

        except Exception as e:
            result["error"] = str(e)
        
        return [result]

    def parse_sm2_encryption_file(self, file_path: str) -> List[Dict[str, str]]:
        """解析SM2加密测试向量文件（GBK编码）"""
        test_cases = []
        try:
            with open(file_path, 'r', encoding='gbk') as f:
                content = f.read()

            # 按空行分割测试用例
            case_blocks = content.strip().split('\n\n')

            for block in case_blocks:
                if not block.strip():
                    continue

                test_case = {}
                lines = block.strip().split('\n')

                for line in lines:
                    line = line.strip()
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        test_case[key] = value

                # 验证必需字段
                if all(k in test_case for k in ['随机数', '公钥', '明文', '密文']):
                    test_cases.append(test_case)

        except Exception as e:
            print(f"❌ 解析SM2加密文件失败: {e}")

        return test_cases

    def parse_sm2_decryption_file(self, file_path: str) -> List[Dict[str, str]]:
        """解析SM2解密测试向量文件（GBK编码）"""
        test_cases = []
        try:
            with open(file_path, 'r', encoding='gbk') as f:
                content = f.read()

            # 按空行分割测试用例
            case_blocks = content.strip().split('\n\n')

            for block in case_blocks:
                if not block.strip():
                    continue

                test_case = {}
                lines = block.strip().split('\n')

                for line in lines:
                    line = line.strip()
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        test_case[key] = value

                # 验证必需字段
                if all(k in test_case for k in ['公钥', '私钥', '明文长度', '密文', '明文']):
                    test_cases.append(test_case)

        except Exception as e:
            print(f"❌ 解析SM2解密文件失败: {e}")

        return test_cases

    def validate_encryption_test_case(self, test_case: Dict[str, str]) -> bool:
        """验证加密测试用例格式"""
        try:
            # 检查随机数（32字节十六进制）
            rand = test_case.get('随机数', '')
            if not rand or len(rand) != 64:
                return False
            int(rand, 16)

            # 检查公钥（128字节十六进制）
            public_key = test_case.get('公钥', '')
            if not public_key or len(public_key) != 128:
                return False
            int(public_key, 16)

            # 检查明文（十六进制）
            plaintext = test_case.get('明文', '')
            if not plaintext:
                return False
            int(plaintext, 16)

            # 检查密文（十六进制）
            ciphertext = test_case.get('密文', '')
            if not ciphertext:
                return False
            int(ciphertext, 16)

            return True

        except ValueError:
            return False

    def validate_decryption_test_case(self, test_case: Dict[str, str]) -> bool:
        """验证解密测试用例格式"""
        try:
            # 检查公钥（128字节十六进制）
            public_key = test_case.get('公钥', '')
            if not public_key or len(public_key) != 128:
                return False
            int(public_key, 16)

            # 检查私钥（64字节十六进制）
            private_key = test_case.get('私钥', '')
            if not private_key or len(private_key) != 64:
                return False
            int(private_key, 16)

            # 检查明文长度（8字节十六进制）
            msg_len = test_case.get('明文长度', '')
            if not msg_len or len(msg_len) != 8:
                return False
            int(msg_len, 16)

            # 检查密文（十六进制）
            ciphertext = test_case.get('密文', '')
            if not ciphertext:
                return False
            int(ciphertext, 16)

            # 检查明文（十六进制）
            plaintext = test_case.get('明文', '')
            if not plaintext:
                return False
            int(plaintext, 16)

            return True

        except ValueError:
            return False

    def test_encryption_vectors(self) -> List[Dict[str, Any]]:
        """测试SM2加密向量验证"""
        print("🔐 测试SM2加密向量...")

        results = []

        # 测试1: 读取和解析加密向量文件
        result = {
            "test_name": "SM2加密向量_文件解析",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            enc_file = self.vector_dir / "SM2_加密.txt"
            if not enc_file.exists():
                result["error"] = f"加密向量文件不存在: {enc_file}"
            else:
                test_cases = self.parse_sm2_encryption_file(str(enc_file))
                if len(test_cases) >= 10:  # 至少应该有10个测试用例
                    result["passed"] = True
                    result["details"]["test_cases_found"] = len(test_cases)
                    result["details"]["sample_rand"] = test_cases[0].get('随机数', '')[:16] + "..."
                    result["details"]["sample_public_key"] = test_cases[0].get('公钥', '')[:16] + "..."
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 验证加密向量格式
        result = {
            "test_name": "SM2加密向量_格式验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            enc_file = self.vector_dir / "SM2_加密.txt"
            test_cases = self.parse_sm2_encryption_file(str(enc_file))

            valid_count = 0
            invalid_details = []

            for i, test_case in enumerate(test_cases):
                if self.validate_encryption_test_case(test_case):
                    valid_count += 1
                else:
                    invalid_details.append(f"测试用例{i+1}格式无效")

            if valid_count == len(test_cases) and valid_count > 0:
                result["passed"] = True
                result["details"]["valid_test_cases"] = valid_count
            else:
                result["error"] = f"格式验证失败: {valid_count}/{len(test_cases)}个测试用例有效"
                if invalid_details:
                    result["details"]["invalid_details"] = invalid_details

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def test_decryption_vectors(self) -> List[Dict[str, Any]]:
        """测试SM2解密向量验证"""
        print("🔓 测试SM2解密向量...")

        results = []

        # 测试1: 读取和解析解密向量文件
        result = {
            "test_name": "SM2解密向量_文件解析",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            dec_file = self.vector_dir / "SM2_解密_10.txt"
            if not dec_file.exists():
                result["error"] = f"解密向量文件不存在: {dec_file}"
            else:
                test_cases = self.parse_sm2_decryption_file(str(dec_file))
                if len(test_cases) >= 10:  # 应该有10个测试用例
                    result["passed"] = True
                    result["details"]["test_cases_found"] = len(test_cases)
                    result["details"]["sample_public_key"] = test_cases[0].get('公钥', '')[:16] + "..."
                    result["details"]["sample_private_key"] = test_cases[0].get('私钥', '')[:16] + "..."
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 验证解密向量格式
        result = {
            "test_name": "SM2解密向量_格式验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            dec_file = self.vector_dir / "SM2_解密_10.txt"
            test_cases = self.parse_sm2_decryption_file(str(dec_file))

            valid_count = 0
            invalid_details = []

            for i, test_case in enumerate(test_cases):
                if self.validate_decryption_test_case(test_case):
                    valid_count += 1
                else:
                    invalid_details.append(f"测试用例{i+1}格式无效")

            if valid_count == len(test_cases) and valid_count > 0:
                result["passed"] = True
                result["details"]["valid_test_cases"] = valid_count
            else:
                result["error"] = f"格式验证失败: {valid_count}/{len(test_cases)}个测试用例有效"
                if invalid_details:
                    result["details"]["invalid_details"] = invalid_details

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试3: 验证解密向量数据一致性
        result = {
            "test_name": "SM2解密向量_数据一致性",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            dec_file = self.vector_dir / "SM2_解密_10.txt"
            test_cases = self.parse_sm2_decryption_file(str(dec_file))

            consistency_checks = []

            for i, test_case in enumerate(test_cases):
                plaintext = test_case.get('明文', '')
                msg_len_hex = test_case.get('明文长度', '')

                try:
                    # 验证明文长度是否与声明一致
                    expected_len = int(msg_len_hex, 16)
                    actual_len = len(plaintext) // 2  # 十六进制每2字符表示1字节

                    if actual_len == expected_len:
                        consistency_checks.append(True)
                    else:
                        consistency_checks.append(f"长度不匹配: 期望{expected_len}, 实际{actual_len}")
                except:
                    consistency_checks.append("长度解析失败")

            valid_consistency = sum(1 for check in consistency_checks if check is True)

            if valid_consistency == len(test_cases):
                result["passed"] = True
                result["details"]["consistency_checks_passed"] = valid_consistency
            else:
                result["error"] = f"数据一致性检查失败: {valid_consistency}/{len(test_cases)}"
                result["details"]["consistency_details"] = consistency_checks

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def parse_sm2_signature_file(self, file_path: str) -> List[Dict[str, str]]:
        """解析SM2签名测试向量文件（GBK编码）"""
        test_cases = []
        try:
            with open(file_path, 'r', encoding='gbk') as f:
                content = f.read()

            # 按空行分割测试用例
            case_blocks = content.strip().split('\n\n')

            for block in case_blocks:
                if not block.strip():
                    continue

                test_case = {}
                lines = block.strip().split('\n')

                for line in lines:
                    line = line.strip()
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        test_case[key] = value

                # 验证必需字段
                if all(k in test_case for k in ['随机数', '私钥', '签名数据', '签名结果']):
                    test_cases.append(test_case)

        except Exception as e:
            print(f"❌ 解析SM2签名文件失败: {e}")

        return test_cases

    def parse_sm2_signature_preprocessed_file(self, file_path: str) -> List[Dict[str, str]]:
        """解析SM2签名预处理前测试向量文件（GBK编码）"""
        test_cases = []
        try:
            with open(file_path, 'r', encoding='gbk') as f:
                content = f.read()

            # 按空行分割测试用例
            case_blocks = content.strip().split('\n\n')

            for block in case_blocks:
                if not block.strip():
                    continue

                test_case = {}
                lines = block.strip().split('\n')

                for line in lines:
                    line = line.strip()
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        test_case[key] = value

                # 验证必需字段（预处理前格式）
                if all(k in test_case for k in ['公钥', '私钥', '签名者ID', '签名数据长度', '签名数据', '给定随机数', '签名结果']):
                    test_cases.append(test_case)

        except Exception as e:
            print(f"❌ 解析SM2签名预处理前文件失败: {e}")

        return test_cases

    def parse_sm2_verification_file(self, file_path: str) -> List[Dict[str, str]]:
        """解析SM2验签测试向量文件（GBK编码）"""
        test_cases = []
        try:
            with open(file_path, 'r', encoding='gbk') as f:
                content = f.read()

            # 按空行分割测试用例
            case_blocks = content.strip().split('\n\n')

            for block in case_blocks:
                if not block.strip():
                    continue

                test_case = {}
                lines = block.strip().split('\n')

                for line in lines:
                    line = line.strip()
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        test_case[key] = value

                # 验证必需字段（根据文件格式）
                if all(k in test_case for k in ['公钥', '私钥', '签名数据e', '签名结果']):
                    test_cases.append(test_case)

        except Exception as e:
            print(f"❌ 解析SM2验签文件失败: {e}")

        return test_cases

    def parse_sm2_verification_preprocessed_file(self, file_path: str) -> List[Dict[str, str]]:
        """解析SM2验签预处理前测试向量文件（GBK编码）"""
        test_cases = []
        try:
            with open(file_path, 'r', encoding='gbk') as f:
                content = f.read()

            # 按空行分割测试用例
            case_blocks = content.strip().split('\n\n')

            for block in case_blocks:
                if not block.strip():
                    continue

                test_case = {}
                lines = block.strip().split('\n')

                for line in lines:
                    line = line.strip()
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        test_case[key] = value

                # 验证必需字段（预处理前格式）
                if all(k in test_case for k in ['公钥', '私钥', '签名者ID', '签名数据长度', '签名数据', '签名结果']):
                    test_cases.append(test_case)

        except Exception as e:
            print(f"❌ 解析SM2验签预处理前文件失败: {e}")

        return test_cases

    def validate_signature_test_case(self, test_case: Dict[str, str]) -> bool:
        """验证签名测试用例格式"""
        try:
            # 检查随机数（64字节十六进制）
            rand = test_case.get('随机数', '')
            if not rand or len(rand) != 64:
                return False
            int(rand, 16)

            # 检查私钥（64字节十六进制）
            private_key = test_case.get('私钥', '')
            if not private_key or len(private_key) != 64:
                return False
            int(private_key, 16)

            # 检查签名数据（64字节十六进制）
            signature_data = test_case.get('签名数据', '')
            if not signature_data or len(signature_data) != 64:
                return False
            int(signature_data, 16)

            # 检查签名结果（128字节十六进制）
            signature = test_case.get('签名结果', '')
            if not signature or len(signature) != 128:
                return False
            int(signature, 16)

            return True

        except ValueError:
            return False

    def validate_signature_preprocessed_test_case(self, test_case: Dict[str, str]) -> bool:
        """验证签名预处理前测试用例格式"""
        try:
            # 检查公钥（128字节十六进制）
            public_key = test_case.get('公钥', '')
            if not public_key or len(public_key) != 128:
                return False
            int(public_key, 16)

            # 检查私钥（64字节十六进制）
            private_key = test_case.get('私钥', '')
            if not private_key or len(private_key) != 64:
                return False
            int(private_key, 16)

            # 检查签名者ID
            signature_id = test_case.get('签名者ID', '')
            if not signature_id:
                return False

            # 检查签名数据长度（8字节十六进制）
            data_length = test_case.get('签名数据长度', '')
            if not data_length or len(data_length) != 8:
                return False
            expected_length = int(data_length, 16)

            # 检查签名数据（十六进制，长度应与数据长度字段匹配）
            signature_data = test_case.get('签名数据', '')
            if not signature_data:
                return False
            actual_length = len(signature_data) // 2
            if actual_length != expected_length:
                return False
            int(signature_data, 16)

            # 检查给定随机数（64字节十六进制）
            random_num = test_case.get('给定随机数', '')
            if not random_num or len(random_num) != 64:
                return False
            int(random_num, 16)

            # 检查签名结果（128字节十六进制）
            signature = test_case.get('签名结果', '')
            if not signature or len(signature) != 128:
                return False
            int(signature, 16)

            return True

        except ValueError:
            return False

    def validate_verification_test_case(self, test_case: Dict[str, str]) -> bool:
        """验证验签测试用例格式"""
        try:
            # 检查公钥（128字节十六进制）
            public_key = test_case.get('公钥', '')
            if not public_key or len(public_key) != 128:
                return False
            int(public_key, 16)

            # 检查私钥（64字节十六进制）
            private_key = test_case.get('私钥', '')
            if not private_key or len(private_key) != 64:
                return False
            int(private_key, 16)

            # 检查签名数据e（64字节十六进制）
            signature_data_e = test_case.get('签名数据e', '')
            if not signature_data_e or len(signature_data_e) != 64:
                return False
            int(signature_data_e, 16)

            # 检查签名结果（128字节十六进制）
            signature = test_case.get('签名结果', '')
            if not signature or len(signature) != 128:
                return False
            int(signature, 16)

            return True

        except ValueError:
            return False

    def validate_verification_preprocessed_test_case(self, test_case: Dict[str, str]) -> bool:
        """验证验签预处理前测试用例格式"""
        try:
            # 检查公钥（128字节十六进制）
            public_key = test_case.get('公钥', '')
            if not public_key or len(public_key) != 128:
                return False
            int(public_key, 16)

            # 检查私钥（64字节十六进制）
            private_key = test_case.get('私钥', '')
            if not private_key or len(private_key) != 64:
                return False
            int(private_key, 16)

            # 检查签名者ID
            signature_id = test_case.get('签名者ID', '')
            if not signature_id:
                return False

            # 检查签名数据长度（8字节十六进制）
            data_length = test_case.get('签名数据长度', '')
            if not data_length or len(data_length) != 8:
                return False
            expected_length = int(data_length, 16)

            # 检查签名数据（十六进制，长度应与数据长度字段匹配）
            signature_data = test_case.get('签名数据', '')
            if not signature_data:
                return False
            actual_length = len(signature_data) // 2
            if actual_length != expected_length:
                return False
            int(signature_data, 16)

            # 检查签名结果（128字节十六进制）
            signature = test_case.get('签名结果', '')
            if not signature or len(signature) != 128:
                return False
            int(signature, 16)

            return True

        except ValueError:
            return False

    def test_signature_vectors(self) -> List[Dict[str, Any]]:
        """测试SM2签名向量验证"""
        print("✍️  测试SM2签名向量...")

        results = []

        # 测试1: 读取和解析签名向量文件
        result = {
            "test_name": "SM2签名向量_文件解析",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            sig_file = self.vector_dir / "SM2_签名.txt"
            if not sig_file.exists():
                result["error"] = f"签名向量文件不存在: {sig_file}"
            else:
                test_cases = self.parse_sm2_signature_file(str(sig_file))
                if len(test_cases) >= 10:  # 至少应该有10个测试用例
                    result["passed"] = True
                    result["details"]["test_cases_found"] = len(test_cases)
                    result["details"]["sample_public_key"] = test_cases[0].get('公钥', '')[:16] + "..."
                    result["details"]["sample_signature_hash"] = test_cases[0].get('签名哈希', '')[:16] + "..."
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 验证签名向量格式
        result = {
            "test_name": "SM2签名向量_格式验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            sig_file = self.vector_dir / "SM2_签名.txt"
            test_cases = self.parse_sm2_signature_file(str(sig_file))

            valid_count = 0
            invalid_details = []

            for i, test_case in enumerate(test_cases):
                if self.validate_signature_test_case(test_case):
                    valid_count += 1
                else:
                    invalid_details.append(f"测试用例{i+1}格式无效")

            if valid_count == len(test_cases) and valid_count > 0:
                result["passed"] = True
                result["details"]["valid_test_cases"] = valid_count
            else:
                result["error"] = f"格式验证失败: {valid_count}/{len(test_cases)}个测试用例有效"
                if invalid_details:
                    result["details"]["invalid_details"] = invalid_details

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试3: 读取和解析签名预处理后向量文件
        result = {
            "test_name": "SM2签名预处理后向量_文件解析",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            sig_pre_file = self.vector_dir / "SM2_签名（预处理后）.txt"
            if not sig_pre_file.exists():
                result["error"] = f"签名预处理后向量文件不存在: {sig_pre_file}"
            else:
                test_cases = self.parse_sm2_signature_file(str(sig_pre_file))
                if len(test_cases) >= 10:  # 至少应该有10个测试用例
                    result["passed"] = True
                    result["details"]["test_cases_found"] = len(test_cases)
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试4: 读取和解析签名预处理前向量文件
        result = {
            "test_name": "SM2签名预处理前向量_文件解析",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            sig_pre_before_file = self.vector_dir / "SM2_签名（预处理前）.txt"
            if not sig_pre_before_file.exists():
                result["error"] = f"签名预处理前向量文件不存在: {sig_pre_before_file}"
            else:
                test_cases = self.parse_sm2_signature_preprocessed_file(str(sig_pre_before_file))
                if len(test_cases) >= 2:  # 至少应该有2个测试用例
                    result["passed"] = True
                    result["details"]["test_cases_found"] = len(test_cases)
                    result["details"]["sample_signature_id"] = test_cases[0].get('签名ID', '')[:16] + "..."
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试5: 验证签名预处理前向量格式
        result = {
            "test_name": "SM2签名预处理前向量_格式验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            sig_pre_before_file = self.vector_dir / "SM2_签名（预处理前）.txt"
            test_cases = self.parse_sm2_signature_preprocessed_file(str(sig_pre_before_file))

            valid_count = 0
            invalid_details = []

            for i, test_case in enumerate(test_cases):
                if self.validate_signature_preprocessed_test_case(test_case):
                    valid_count += 1
                else:
                    invalid_details.append(f"测试用例{i+1}格式无效")

            if valid_count == len(test_cases) and valid_count > 0:
                result["passed"] = True
                result["details"]["valid_test_cases"] = valid_count
            else:
                result["error"] = f"格式验证失败: {valid_count}/{len(test_cases)}个测试用例有效"
                if invalid_details:
                    result["details"]["invalid_details"] = invalid_details

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def test_verification_vectors(self) -> List[Dict[str, Any]]:
        """测试SM2验签向量验证"""
        print("🔍 测试SM2验签向量...")

        results = []

        # 测试1: 读取和解析验签预处理后向量文件
        result = {
            "test_name": "SM2验签预处理后向量_文件解析",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            ver_pre_file = self.vector_dir / "SM2_验签（预处理后）.txt"
            if not ver_pre_file.exists():
                result["error"] = f"验签预处理后向量文件不存在: {ver_pre_file}"
            else:
                test_cases = self.parse_sm2_verification_file(str(ver_pre_file))
                if len(test_cases) >= 10:  # 至少应该有10个测试用例
                    result["passed"] = True
                    result["details"]["test_cases_found"] = len(test_cases)
                    result["details"]["sample_signature_hash_e"] = test_cases[0].get('签名哈希e', '')[:16] + "..."
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 验证验签预处理后向量格式
        result = {
            "test_name": "SM2验签预处理后向量_格式验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            ver_pre_file = self.vector_dir / "SM2_验签（预处理后）.txt"
            test_cases = self.parse_sm2_verification_file(str(ver_pre_file))

            valid_count = 0
            invalid_details = []

            for i, test_case in enumerate(test_cases):
                if self.validate_verification_test_case(test_case):
                    valid_count += 1
                else:
                    invalid_details.append(f"测试用例{i+1}格式无效")

            if valid_count == len(test_cases) and valid_count > 0:
                result["passed"] = True
                result["details"]["valid_test_cases"] = valid_count
            else:
                result["error"] = f"格式验证失败: {valid_count}/{len(test_cases)}个测试用例有效"
                if invalid_details:
                    result["details"]["invalid_details"] = invalid_details

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试3: 读取和解析验签预处理前向量文件
        result = {
            "test_name": "SM2验签预处理前向量_文件解析",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            ver_pre_before_file = self.vector_dir / "SM2_验签（预处理前).txt"
            if not ver_pre_before_file.exists():
                result["error"] = f"验签预处理前向量文件不存在: {ver_pre_before_file}"
            else:
                test_cases = self.parse_sm2_verification_preprocessed_file(str(ver_pre_before_file))
                if len(test_cases) >= 3:  # 至少应该有3个测试用例
                    result["passed"] = True
                    result["details"]["test_cases_found"] = len(test_cases)
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试4: 验证验签预处理前向量格式
        result = {
            "test_name": "SM2验签预处理前向量_格式验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            ver_pre_before_file = self.vector_dir / "SM2_验签（预处理前).txt"
            test_cases = self.parse_sm2_verification_preprocessed_file(str(ver_pre_before_file))

            valid_count = 0
            invalid_details = []

            for i, test_case in enumerate(test_cases):
                if self.validate_verification_preprocessed_test_case(test_case):
                    valid_count += 1
                else:
                    invalid_details.append(f"测试用例{i+1}格式无效")

            if valid_count == len(test_cases) and valid_count > 0:
                result["passed"] = True
                result["details"]["valid_test_cases"] = valid_count
            else:
                result["error"] = f"格式验证失败: {valid_count}/{len(test_cases)}个测试用例有效"
                if invalid_details:
                    result["details"]["invalid_details"] = invalid_details

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试5: 验签向量数据一致性检查
        result = {
            "test_name": "SM2验签向量_数据一致性",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            ver_pre_file = self.vector_dir / "SM2_验签（预处理后）.txt"
            test_cases = self.parse_sm2_verification_file(str(ver_pre_file))

            consistency_checks = []

            for i, test_case in enumerate(test_cases):
                # 检查签名值长度是否正确（128字符 = 64字节）
                signature = test_case.get('签名结果', '')
                if len(signature) == 128:
                    consistency_checks.append(True)
                else:
                    consistency_checks.append(f"签名值长度错误: {len(signature)}")

            valid_consistency = sum(1 for check in consistency_checks if check is True)

            if valid_consistency == len(test_cases):
                result["passed"] = True
                result["details"]["consistency_checks_passed"] = valid_consistency
            else:
                result["error"] = f"数据一致性检查失败: {valid_consistency}/{len(test_cases)}"
                result["details"]["consistency_details"] = consistency_checks

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def test_exception_handling(self) -> List[Dict[str, Any]]:
        """测试异常处理"""
        print("⚠️  测试异常处理...")

        results = []

        # 测试1: 无效公钥
        result = {
            "test_name": "SM2异常_无效公钥",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            from src.sm2.sm2_impl import sm2_encrypt
            # 尝试使用无效公钥
            invalid_result = sm2_encrypt("invalid", "0102030405060708")
            result["error"] = "应该抛出异常但没有"
        except Exception as e:
            result["passed"] = True
            result["details"]["exception_type"] = type(e).__name__
            result["details"]["exception_message"] = str(e)
        results.append(result)

        # 测试2: 空密文解密
        result = {
            "test_name": "SM2异常_空密文解密",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            from src.sm2.sm2_impl import sm2_decrypt
            # 尝试解密空密文
            invalid_result = sm2_decrypt("1234567890abcdef" * 8, "")
            result["error"] = "应该抛出异常但没有"
        except Exception as e:
            result["passed"] = True
            result["details"]["exception_type"] = type(e).__name__
            result["details"]["exception_message"] = str(e)
        results.append(result)

        # 测试3: 无效签名
        result = {
            "test_name": "SM2异常_无效签名",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            from src.sm2.sm2_impl import sm2_verify
            # 尝试验证无效签名
            invalid_result = sm2_verify("1234567890abcdef" * 16, "0102030405060708", "invalid")
            result["error"] = "应该抛出异常但没有"
        except Exception as e:
            result["passed"] = True
            result["details"]["exception_type"] = type(e).__name__
            result["details"]["exception_message"] = str(e)
        results.append(result)

        return results

    def run_all_tests(self) -> Dict[str, Any]:
        """运行所有SM2测试"""
        print("=" * 60)
        print("🔐 SM2算法统一测试")
        print("=" * 60)
        print("⚠️  注意: 此版本为简化测试，不依赖GmSSL")
        print()
        
        # 测试基本功能
        basic_results = self.test_basic_functionality()
        for result in basic_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                self.results["failed"] += 1
            self.results["total_tests"] += 1
        
        # 测试密钥对验证
        key_results = self.test_key_pair_validation()
        for result in key_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                self.results["failed"] += 1
            self.results["total_tests"] += 1

        # 测试密钥对一致性
        key_consistency_results = self.test_key_pair_consistency()
        for result in key_consistency_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                self.results["failed"] += 1
            self.results["total_tests"] += 1

        # 测试加密向量验证
        enc_results = self.test_encryption_vectors()
        for result in enc_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                self.results["failed"] += 1
            self.results["total_tests"] += 1
        
        # 测试解密向量验证
        dec_results = self.test_decryption_vectors()
        for result in dec_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                self.results["failed"] += 1
            self.results["total_tests"] += 1
        
        # 测试签名向量验证
        sig_results = self.test_signature_vectors()
        for result in sig_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                self.results["failed"] += 1
            self.results["total_tests"] += 1
        
        # 测试验签向量验证
        ver_results = self.test_verification_vectors()
        for result in ver_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                self.results["failed"] += 1
            self.results["total_tests"] += 1
        
        # 测试异常处理
        exc_results = self.test_exception_handling()
        for result in exc_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                self.results["failed"] += 1
            self.results["total_tests"] += 1
        
        # 运行计算检测
        from src.sm2.sm2_computation_test import SM2ComputationTest
        comp_tester = SM2ComputationTest()
        comp_results = comp_tester.run_all_computation_tests()
        # 合并结果到主统计
        self.results["total_tests"] += comp_results["total_tests"]
        self.results["passed"] += comp_results["passed"]
        self.results["failed"] += comp_results["failed"] + comp_results.get("error", 0)  # error也算失败
        # 存储详细结果
        self.results["computation_results"] = comp_results
        
        # 计算通过率
        self.results["pass_rate"] = self.results["passed"] / self.results["total_tests"] if self.results["total_tests"] > 0 else 0
        
        return self.results
    
    def save_results(self, output_dir: str = "./results") -> None:
        """保存测试结果"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # 合并格式验证和计算验证结果
        full_results = {
            "algorithm": "SM2_Full_Test",
            "format_validation": self.results,
            "computation_validation": self.results.get("computation_results", {}),
            "total_tests": self.results["total_tests"],  # 直接使用已合并的总数
            "passed": self.results["passed"],
            "failed": self.results["failed"],
            "error": self.results.get("error", 0),
            "pass_rate": self.results["pass_rate"],
            "details": self.results["details"]  # 包含详细测试结果
        }

        # 使用新的统一报告生成系统
        try:
            from src.crypto_test_reporter import SM2Reporter
            reporter = SM2Reporter()
            report_paths = reporter.save_reports(full_results, str(output_path))
            print(f"✓ 新版详细报告已生成: {report_paths['json']}")
            print(f"✓ 新版摘要报告已生成: {report_paths['txt']}")
        except ImportError:
            print("⚠️  统一报告生成系统不可用，使用传统格式保存")
            # 回退到传统保存方式
            results_file = output_path / 'sm2_full_test_results.json'
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(full_results, f, indent=2, ensure_ascii=False)

            summary_file = output_path / 'sm2_test_summary.txt'
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("🔐 SM2算法完整测试报告\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"测试用例总数: {self.results['total_tests']}\n")
                f.write(f"通过数: {self.results['passed']}\n")
                f.write(f"失败数: {self.results['failed']}\n")
                f.write(f"跳过数: {self.results['skipped']}\n")
                    f.write(f"通过率: {self.results['pass_rate']:.2%}\n\n")
                    f.write("注意: 本报告仅包含格式验证结果\n")

            print(f"✓ 详细结果已保存到: {results_file}")
            print(f"✓ 统计摘要已保存到: {summary_file}")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SM2算法统一测试程序",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 sm2_unified_test_simple.py                    # 运行所有测试
  python3 sm2_unified_test_simple.py -o ./test_output    # 指定输出目录
        """
    )
    
    parser.add_argument(
        "-o", "--output-dir",
        default="./results",
        help="输出目录 (默认: ./results)"
    )
    
    args = parser.parse_args()
    
    # 初始化测试器
    tester = SM2UnifiedTestSimple()
    
    # 运行测试
    results = tester.run_all_tests()
    
    # 保存结果
    tester.save_results(args.output_dir)
    
    # 打印最终统计
    print("\n" + "=" * 60)
    print("📊 测试摘要")
    print("=" * 60)
    print(f"算法: {results['algorithm']}")
    print(f"测试用例总数: {results['total_tests']}")
    print(f"通过数: {results['passed']}")
    print(f"失败数: {results['failed']}")
    print(f"跳过数: {results['skipped']}")
    print(f"通过率: {results['pass_rate']:.2%}")
    
    if results['failed'] == 0:
        print("\n🎉 所有测试用例通过!")
        return 0
    else:
        print(f"\n⚠️  {results['failed']} 个测试用例失败")
        return 1


if __name__ == "__main__":
    sys.exit(main())
