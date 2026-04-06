#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2 计算检测程序
对测试向量执行实际SM2运算验证
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Any
import threading

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.sm2.sm2_impl import sm2_encrypt, sm2_decrypt, sm2_sign, sm2_verify, SM2Curve
from src.sm3.sm3_impl import sm3


class SM2ComputationTest:
    """SM2 计算检测器"""

    def __init__(self):
        """初始化计算检测器"""
        self.project_root = Path(__file__).parent.parent.parent  # 回到项目根目录
        self.vector_dir = self.project_root / "algorithm" / "SM2"
        self.curve = SM2Curve()  # 添加曲线参数
        self.results = {
            "algorithm": "SM2_Computation",
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "error": 0,
            "details": []
        }

    def _run_with_timeout(self, func, timeout_seconds=5):
        """使用超时运行函数"""
        result = [None]
        exception = [None]
        
        def wrapper():
            try:
                result[0] = func()
            except Exception as e:
                exception[0] = e
        
        thread = threading.Thread(target=wrapper)
        thread.start()
        thread.join(timeout_seconds)
        
        if thread.is_alive():
            raise TimeoutError("计算超时")
        if exception[0]:
            raise exception[0]
        return result[0]

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

                # 验证必需字段（根据文件格式）
                if all(k in test_case for k in ['随机数', '私钥', '签名数据', '签名结果']):
                    test_cases.append(test_case)

        except Exception as e:
            print(f"❌ 解析SM2签名文件失败: {e}")

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

    def parse_sm2_signature_preprocessed_file(self, file_path: str) -> List[Dict[str, str]]:
        """解析SM2签名预处理前E值验证文件（GBK编码）"""
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
                if all(k in test_case for k in ['签名数据', '签名数据的E值']):
                    test_cases.append(test_case)

        except Exception as e:
            print(f"❌ 解析SM2签名预处理前文件失败: {e}")

        return test_cases

    def parse_sm2_verification_preprocessed_file(self, file_path: str) -> List[Dict[str, str]]:
        """解析SM2验签预处理前验证文件（GBK编码）"""
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

                # 验证必需字段（根据预处理前文件格式）
                if all(k in test_case for k in ['公钥', '签名数据e', '签名结果']):
                    test_cases.append(test_case)

        except Exception as e:
            print(f"❌ 解析SM2验签预处理前文件失败: {e}")

        return test_cases

    def test_encryption_computation(self) -> List[Dict[str, Any]]:
        """测试SM2加密计算验证"""
        print("🔐 测试SM2加密计算...")

        results = []

        # 测试1: 读取和解析加密向量文件
        result = {
            "test_name": "SM2加密计算_文件解析",
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
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 执行加密计算验证
        result = {
            "test_name": "SM2加密计算_运算验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            enc_file = self.vector_dir / "SM2_加密.txt"
            test_cases = self.parse_sm2_encryption_file(str(enc_file))

            passed_count = 0
            failed_count = 0
            error_count = 0
            computation_details = []

            def timeout_handler():
                raise TimeoutError("计算超时")

            for i, test_case in enumerate(test_cases):
                try:
                    public_key = test_case.get('公钥', '')
                    plaintext = test_case.get('明文', '')
                    expected_ciphertext = test_case.get('密文', '')
                    k_value = test_case.get('随机数', '')

                    # 使用超时运行加密计算
                    computed_ciphertext = self._run_with_timeout(
                        lambda: sm2_encrypt(public_key, plaintext, k_value), 
                        timeout_seconds=5
                    )

                    # 比较结果
                    if computed_ciphertext.upper() == expected_ciphertext.upper():
                        passed_count += 1
                        status = "通过"
                        detail = f"用例{i+1}: 计算结果与预期一致"
                    else:
                        failed_count += 1
                        status = "失败"
                        detail = f"用例{i+1}: 计算结果({computed_ciphertext[:32]}...) ≠ 预期({expected_ciphertext[:32]}...)"

                    computation_details.append({
                        "case_id": i + 1,
                        "status": status,
                        "detail": detail,
                        "computed": computed_ciphertext,
                        "expected": expected_ciphertext
                    })

                except Exception as e:
                    error_count += 1
                    computation_details.append({
                        "case_id": i + 1,
                        "status": "错误",
                        "detail": f"计算失败: {str(e)}",
                        "computed": "",
                        "expected": expected_ciphertext
                    })

            result["passed"] = failed_count == 0 and error_count == 0
            result["details"]["passed_count"] = passed_count
            result["details"]["failed_count"] = failed_count
            result["details"]["error_count"] = error_count
            result["details"]["computation_details"] = computation_details

            if not result["passed"]:
                result["error"] = f"加密计算验证失败: {failed_count}失败, {error_count}错误"

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def test_decryption_computation(self) -> List[Dict[str, Any]]:
        """测试SM2解密计算验证"""
        print("🔓 测试SM2解密计算...")

        results = []

        # 测试1: 读取和解析解密向量文件
        result = {
            "test_name": "SM2解密计算_文件解析",
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
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 执行解密计算验证
        result = {
            "test_name": "SM2解密计算_运算验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            dec_file = self.vector_dir / "SM2_解密_10.txt"
            test_cases = self.parse_sm2_decryption_file(str(dec_file))

            passed_count = 0
            failed_count = 0
            error_count = 0
            computation_details = []

            for i, test_case in enumerate(test_cases):
                try:
                    private_key = test_case.get('私钥', '')
                    ciphertext = test_case.get('密文', '')
                    expected_plaintext = test_case.get('明文', '')

                    # 使用超时运行解密计算
                    computed_plaintext = self._run_with_timeout(
                        lambda: sm2_decrypt(private_key, ciphertext), 
                        timeout_seconds=5
                    )

                    # 比较结果
                    if computed_plaintext.upper() == expected_plaintext.upper():
                        passed_count += 1
                        status = "通过"
                        detail = f"用例{i+1}: 计算结果与预期一致"
                    else:
                        failed_count += 1
                        status = "失败"
                        detail = f"用例{i+1}: 计算结果({computed_plaintext}) ≠ 预期({expected_plaintext})"

                    computation_details.append({
                        "case_id": i + 1,
                        "status": status,
                        "detail": detail,
                        "computed": computed_plaintext,
                        "expected": expected_plaintext
                    })

                except Exception as e:
                    error_count += 1
                    computation_details.append({
                        "case_id": i + 1,
                        "status": "错误",
                        "detail": f"计算失败: {str(e)}",
                        "computed": "",
                        "expected": expected_plaintext
                    })

            result["passed"] = failed_count == 0 and error_count == 0
            result["details"]["passed_count"] = passed_count
            result["details"]["failed_count"] = failed_count
            result["details"]["error_count"] = error_count
            result["details"]["computation_details"] = computation_details

            if not result["passed"]:
                result["error"] = f"解密计算验证失败: {failed_count}失败, {error_count}错误"

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def test_signature_computation(self) -> List[Dict[str, Any]]:
        """测试SM2签名计算验证"""
        print("✍️  测试SM2签名计算...")

        results = []

        # 测试1: 读取和解析签名向量文件
        result = {
            "test_name": "SM2签名计算_文件解析",
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
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 执行签名计算验证
        result = {
            "test_name": "SM2签名计算_运算验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            sig_file = self.vector_dir / "SM2_签名.txt"
            test_cases = self.parse_sm2_signature_file(str(sig_file))

            passed_count = 0
            failed_count = 0
            error_count = 0
            computation_details = []

            for i, test_case in enumerate(test_cases):
                try:
                    private_key = test_case.get('私钥', '')
                    message = test_case.get('签名数据', '')
                    expected_signature = test_case.get('签名结果', '')
                    k_value = test_case.get('随机数', '')
                    user_id_hex = test_case.get('签名者ID', '31323334353637383132333435363738')  # 默认user_id
                    
                    # 使用超时运行签名计算
                    computed_signature = self._run_with_timeout(
                        lambda: sm2_sign(private_key, message, user_id_hex=user_id_hex, k_hex=k_value, use_precomputed_e=True), 
                        timeout_seconds=5
                    )

                    # 比较结果
                    if computed_signature.upper() == expected_signature.upper():
                        passed_count += 1
                        status = "通过"
                        detail = f"用例{i+1}: 计算结果与预期一致"
                    else:
                        failed_count += 1
                        status = "失败"
                        detail = f"用例{i+1}: 计算结果({computed_signature[:32]}...) ≠ 预期({expected_signature[:32]}...)"

                    computation_details.append({
                        "case_id": i + 1,
                        "status": status,
                        "detail": detail,
                        "computed": computed_signature,
                        "expected": expected_signature
                    })

                except Exception as e:
                    error_count += 1
                    computation_details.append({
                        "case_id": i + 1,
                        "status": "错误",
                        "detail": f"计算失败: {str(e)}",
                        "computed": "",
                        "expected": expected_signature
                    })

            result["passed"] = failed_count == 0 and error_count == 0
            result["details"]["passed_count"] = passed_count
            result["details"]["failed_count"] = failed_count
            result["details"]["error_count"] = error_count
            result["details"]["computation_details"] = computation_details

            if not result["passed"]:
                result["error"] = f"签名计算验证失败: {failed_count}失败, {error_count}错误"

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def test_verification_computation(self) -> List[Dict[str, Any]]:
        """测试SM2验签计算验证"""
        print("🔍 测试SM2验签计算...")

        results = []

        # 测试1: 读取和解析验签向量文件
        result = {
            "test_name": "SM2验签计算_文件解析",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            ver_file = self.vector_dir / "SM2_验签（预处理后）.txt"
            if not ver_file.exists():
                result["error"] = f"验签向量文件不存在: {ver_file}"
            else:
                test_cases = self.parse_sm2_verification_file(str(ver_file))
                if len(test_cases) >= 10:  # 至少应该有10个测试用例
                    result["passed"] = True
                    result["details"]["test_cases_found"] = len(test_cases)
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 执行验签计算验证
        result = {
            "test_name": "SM2验签计算_运算验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            ver_file = self.vector_dir / "SM2_验签（预处理后）.txt"
            test_cases = self.parse_sm2_verification_file(str(ver_file))

            passed_count = 0
            failed_count = 0
            error_count = 0
            computation_details = []

            for i, test_case in enumerate(test_cases):
                try:
                    public_key = test_case.get('公钥', '')
                    message = test_case.get('签名数据e', '')  # 使用签名数据e作为消息
                    signature = test_case.get('签名结果', '')
                    user_id_hex = test_case.get('签名者ID', '31323334353637383132333435363738')  # 默认user_id

                    # 使用超时运行验签计算
                    verification_result = self._run_with_timeout(
                        lambda: sm2_verify(public_key, message, signature, user_id_hex=user_id_hex, use_precomputed_e=True), 
                        timeout_seconds=5
                    )

                    if verification_result:
                        passed_count += 1
                        status = "通过"
                        detail = f"用例{i+1}: 验签成功"
                    else:
                        failed_count += 1
                        status = "失败"
                        detail = f"用例{i+1}: 验签失败"

                    computation_details.append({
                        "case_id": i + 1,
                        "status": status,
                        "detail": detail,
                        "verification_result": verification_result
                    })

                except Exception as e:
                    error_count += 1
                    computation_details.append({
                        "case_id": i + 1,
                        "status": "错误",
                        "detail": f"计算失败: {str(e)}",
                        "verification_result": False
                    })

            result["passed"] = failed_count == 0 and error_count == 0
            result["details"]["passed_count"] = passed_count
            result["details"]["failed_count"] = failed_count
            result["details"]["error_count"] = error_count
            result["details"]["computation_details"] = computation_details

            if not result["passed"]:
                result["error"] = f"验签计算验证失败: {failed_count}失败, {error_count}错误"

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def test_signature_preprocessed_e_computation(self) -> List[Dict[str, Any]]:
        """测试SM2签名预处理前E值验证"""
        print("📝 测试SM2签名预处理前E值验证...")

        results = []

        # 测试1: 读取和解析文件
        result = {
            "test_name": "SM2签名预处理前E值验证_文件解析",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            sig_pre_file = self.vector_dir / "SM2_签名预处理前E值验证.txt"
            if not sig_pre_file.exists():
                result["error"] = f"签名预处理前文件不存在: {sig_pre_file}"
            else:
                test_cases = self.parse_sm2_signature_preprocessed_file(str(sig_pre_file))
                if len(test_cases) > 0:
                    result["passed"] = True
                    result["details"]["test_cases_found"] = len(test_cases)
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 执行E值验证
        result = {
            "test_name": "SM2签名预处理前E值验证_运算验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            sig_pre_file = self.vector_dir / "SM2_签名预处理前E值验证.txt"
            test_cases = self.parse_sm2_signature_preprocessed_file(str(sig_pre_file))

            passed_count = 0
            failed_count = 0
            error_count = 0
            computation_details = []

            for i, test_case in enumerate(test_cases):
                try:
                    message = test_case.get('签名数据', '')
                    expected_e = test_case.get('签名数据的E值', '')
                    user_id_hex = test_case.get('签名者ID', '31323334353637383132333435363738')  # 默认ID的hex
                    user_id = bytes.fromhex(user_id_hex)
                    public_key_hex = test_case.get('公钥', '')

                    # 计算E值：SM3(ZA || M)
                    id_len = len(user_id) * 8
                    entla = id_len.to_bytes(2, 'big')
                    
                    # ZA计算（根据测试向量格式，可能不包含公钥）
                    za = sm3(entla + user_id +
                            self.curve.A.to_bytes(32, 'big') +
                            self.curve.B.to_bytes(32, 'big') +
                            self.curve.G_X.to_bytes(32, 'big') +
                            self.curve.G_Y.to_bytes(32, 'big'))
                    
                    m_prime = za + bytes.fromhex(message)
                    computed_e = sm3(m_prime).hex()

                    # 比较结果
                    if computed_e.upper() == expected_e.upper():
                        passed_count += 1
                        status = "通过"
                        detail = f"用例{i+1}: E值计算正确"
                    else:
                        failed_count += 1
                        status = "失败"
                        detail = f"用例{i+1}: 计算E({computed_e}) ≠ 预期({expected_e})"

                    computation_details.append({
                        "case_id": i + 1,
                        "status": status,
                        "detail": detail,
                        "computed_e": computed_e,
                        "expected_e": expected_e
                    })

                except Exception as e:
                    error_count += 1
                    computation_details.append({
                        "case_id": i + 1,
                        "status": "错误",
                        "detail": f"计算失败: {str(e)}",
                        "computed_e": "",
                        "expected_e": expected_e
                    })

            result["passed"] = failed_count == 0 and error_count == 0
            result["details"]["passed_count"] = passed_count
            result["details"]["failed_count"] = failed_count
            result["details"]["error_count"] = error_count
            result["details"]["computation_details"] = computation_details

            if not result["passed"]:
                result["error"] = f"E值验证失败: {failed_count}失败, {error_count}错误"

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def test_verification_preprocessed_computation(self) -> List[Dict[str, Any]]:
        """测试SM2验签预处理前验证"""
        print("🔍 测试SM2验签预处理前验证...")

        results = []

        # 测试1: 读取和解析文件
        result = {
            "test_name": "SM2验签预处理前验证_文件解析",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            ver_pre_file = self.vector_dir / "SM2_验签（预处理前).txt"
            if not ver_pre_file.exists():
                result["error"] = f"验签预处理前文件不存在: {ver_pre_file}"
            else:
                test_cases = self.parse_sm2_verification_preprocessed_file(str(ver_pre_file))
                if len(test_cases) > 0:
                    result["passed"] = True
                    result["details"]["test_cases_found"] = len(test_cases)
                else:
                    result["error"] = f"解析到的测试用例数量不足: {len(test_cases)}"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 执行验签验证
        result = {
            "test_name": "SM2验签预处理前验证_运算验证",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            ver_pre_file = self.vector_dir / "SM2_验签（预处理前).txt"
            test_cases = self.parse_sm2_verification_preprocessed_file(str(ver_pre_file))

            passed_count = 0
            failed_count = 0
            error_count = 0
            computation_details = []

            for i, test_case in enumerate(test_cases):
                try:
                    public_key = test_case.get('公钥', '')
                    message = test_case.get('签名数据e', '')
                    signature = test_case.get('签名结果', '')
                    user_id_hex = test_case.get('签名者ID', '31323334353637383132333435363738')  # 默认user_id

                    # 使用超时运行验签计算
                    verification_result = self._run_with_timeout(
                        lambda: sm2_verify(public_key, message, signature, user_id_hex=user_id_hex, use_precomputed_e=False), 
                        timeout_seconds=5
                    )

                    if verification_result:
                        passed_count += 1
                        status = "通过"
                        detail = f"用例{i+1}: 验签成功"
                    else:
                        failed_count += 1
                        status = "失败"
                        detail = f"用例{i+1}: 验签失败"

                    computation_details.append({
                        "case_id": i + 1,
                        "status": status,
                        "detail": detail,
                        "verification_result": verification_result
                    })

                except Exception as e:
                    error_count += 1
                    computation_details.append({
                        "case_id": i + 1,
                        "status": "错误",
                        "detail": f"计算失败: {str(e)}",
                        "verification_result": False
                    })

            result["passed"] = failed_count == 0 and error_count == 0
            result["details"]["passed_count"] = passed_count
            result["details"]["failed_count"] = failed_count
            result["details"]["error_count"] = error_count
            result["details"]["computation_details"] = computation_details

            if not result["passed"]:
                result["error"] = f"验签预处理前验证失败: {failed_count}失败, {error_count}错误"

        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def run_all_computation_tests(self) -> Dict[str, Any]:
        """运行所有SM2计算检测"""
        print("=" * 60)
        print("🧮 SM2算法计算检测")
        print("=" * 60)

        # 测试加密计算
        enc_results = self.test_encryption_computation()
        for result in enc_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                if "error" in result and result["error"]:
                    self.results["error"] += 1
                else:
                    self.results["failed"] += 1
            self.results["total_tests"] += 1

        # 测试解密计算
        dec_results = self.test_decryption_computation()
        for result in dec_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                if "error" in result and result["error"]:
                    self.results["error"] += 1
                else:
                    self.results["failed"] += 1
            self.results["total_tests"] += 1

        # 测试签名计算
        sig_results = self.test_signature_computation()
        for result in sig_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                if "error" in result and result["error"]:
                    self.results["error"] += 1
                else:
                    self.results["failed"] += 1
            self.results["total_tests"] += 1

        # 测试验签计算
        ver_results = self.test_verification_computation()
        for result in ver_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                if "error" in result and result["error"]:
                    self.results["error"] += 1
                else:
                    self.results["failed"] += 1
            self.results["total_tests"] += 1

        # 测试签名预处理前E值验证
        sig_pre_e_results = self.test_signature_preprocessed_e_computation()
        for result in sig_pre_e_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                if "error" in result and result["error"]:
                    self.results["error"] += 1
                else:
                    self.results["failed"] += 1
            self.results["total_tests"] += 1

        # 测试验签预处理前验证
        ver_pre_results = self.test_verification_preprocessed_computation()
        for result in ver_pre_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                if "error" in result and result["error"]:
                    self.results["error"] += 1
                else:
                    self.results["failed"] += 1
            self.results["total_tests"] += 1

        # 计算通过率
        successful_tests = self.results["passed"]
        self.results["success_rate"] = successful_tests / self.results["total_tests"] if self.results["total_tests"] > 0 else 0

        return self.results

    def save_computation_results(self, output_dir: str = "./results") -> None:
        """保存计算检测结果"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        results_file = output_path / 'sm2_computation_results.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        summary_file = output_path / 'sm2_computation_summary.txt'
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("🧮 SM2算法计算检测报告\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"测试用例总数: {self.results['total_tests']}\n")
            f.write(f"通过数: {self.results['passed']}\n")
            f.write(f"失败数: {self.results['failed']}\n")
            f.write(f"错误数: {self.results['error']}\n")
            f.write(f"成功率: {self.results['success_rate']:.2%}\n\n")

            f.write("详细结果:\n")
            for detail in self.results['details']:
                status = "✅" if detail['passed'] else "❌"
                f.write(f"  {status} {detail['test_name']}\n")
                if not detail['passed'] and detail.get('error'):
                    f.write(f"    错误: {detail['error']}\n")

        print(f"✓ 计算检测结果已保存到: {results_file}")
        print(f"✓ 计算检测摘要已保存到: {summary_file}")


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(
        description="SM2计算检测程序",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 sm2_computation_test.py                    # 运行所有计算检测
  python3 sm2_computation_test.py -o ./test_output    # 指定输出目录
        """
    )

    parser.add_argument(
        "-o", "--output-dir",
        default="./results",
        help="输出目录 (默认: ./results)"
    )

    args = parser.parse_args()

    # 初始化计算检测器
    tester = SM2ComputationTest()

    # 运行计算检测
    results = tester.run_all_computation_tests()

    # 保存结果
    tester.save_computation_results(args.output_dir)

    # 打印最终统计
    print("\n" + "=" * 60)
    print("📊 计算检测摘要")
    print("=" * 60)
    print(f"算法: {results['algorithm']}")
    print(f"测试用例总数: {results['total_tests']}")
    print(f"通过数: {results['passed']}")
    print(f"失败数: {results['failed']}")
    print(f"错误数: {results['error']}")
    print(f"成功率: {results['success_rate']:.2%}")

    if results['failed'] == 0 and results['error'] == 0:
        print("\n🎉 所有计算检测通过!")
        return 0
    else:
        print(f"\n⚠️  {results['failed']} 个计算检测失败, {results['error']} 个计算错误")
        return 1


if __name__ == "__main__":
    sys.exit(main())