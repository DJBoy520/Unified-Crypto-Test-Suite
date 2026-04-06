#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM3算法统一测试入口
合并所有SM3相关测试功能
"""

import os
import sys
import json
import hashlib
import hmac
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.sm3.sm3_impl import SM3, sm3

class SM3UnifiedTest:
    """SM3算法统一测试器"""

    def __init__(self):
        """初始化SM3测试器"""
        self.project_root = Path(__file__).parent.parent.parent
        self.vector_dir = self.project_root / "algorithm" / "SM3"
        self.results = {
            "algorithm": "SM3",
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "details": []
        }

    def parse_sm3_file(self, filename: str) -> List[Dict[str, Any]]:
        """解析SM3测试向量文件"""
        filepath = self.vector_dir / filename
        if not filepath.exists():
            print(f"⚠️  文件不存在: {filepath}")
            # 返回包含跳过状态的结果，用于测试报告
            return [{
                "test_name": f"文件:{filename}_加载",
                "passed": False,
                "error": f"文件不存在: {filepath}",
                "details": {"status": "skipped"}
            }]

        test_cases = []

        try:
            with open(filepath, 'r', encoding='gbk', errors='ignore') as f:
                content = f.read()

            # 按空行分割测试用例
            blocks = content.split('\n\n')
            for block in blocks:
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

                        # 解析不同类型的字段
                        if key == "消息长度" or key == "明文长度":
                            test_case["message_len"] = int(value, 16)
                        elif key == "消息" or key == "明文":
                            test_case["message"] = bytes.fromhex(value.replace(' ', ''))
                        elif key == "杂凑值":
                            test_case["digest"] = bytes.fromhex(value.replace(' ', ''))
                        elif key == "密文":
                            # 对于HMAC文件，密文是HMAC值
                            test_case["hmac"] = bytes.fromhex(value.replace(' ', ''))
                        elif key == "密钥":
                            test_case["key"] = bytes.fromhex(value.replace(' ', ''))
                        elif key == "HMAC":
                            test_case["hmac"] = bytes.fromhex(value.replace(' ', ''))

                if test_case:
                    test_cases.append(test_case)

        except Exception as e:
            print(f"⚠️  解析文件失败 {filename}: {e}")
            # 返回包含错误信息的结果
            return [{
                "test_name": f"文件:{filename}_解析",
                "passed": False,
                "error": f"解析失败: {str(e)}",
                "details": {"status": "failed", "file": filename}
            }]

        return test_cases

    def sm3_hash(self, message: bytes) -> bytes:
        """计算SM3哈希值（用统一接口，委托sm3_impl模块）"""
        # 使用sm3_impl中的sm3函数，该函数由cryptography库支持
        from src.sm3.sm3_impl import sm3
        return sm3(message)

    def sm3_hmac(self, key: bytes, message: bytes) -> bytes:
        """计算SM3-HMAC值（用统一接口）"""
        # SM3-HMAC使用SM3作为基础哈希函数
        # 实现标准的HMAC-SM3
        from src.sm3.sm3_impl import sm3
        
        hash_len = 32  # SM3输出32字节
        if len(key) > 64:
            key = sm3(key)
        if len(key) < 64:
            key = key + b'\x00' * (64 - len(key))
        
        opad = bytes(x ^ 0x5c for x in key)
        ipad = bytes(x ^ 0x36 for x in key)
        
        return sm3(opad + sm3(ipad + message))

    def test_hash_vectors(self) -> List[Dict[str, Any]]:
        """测试SM3哈希向量"""
        print("🔢 测试SM3哈希向量...")

        results = []

        # 查找哈希测试文件
        hash_files = ["SM3_10.txt"]

        for filename in hash_files:
            test_cases = self.parse_sm3_file(filename)

            for i, test_case in enumerate(test_cases):
                result = {
                    "test_name": f"SM3哈希_{filename}_{i+1}",
                    "passed": False,
                    "error": "",
                    "details": {}
                }

                try:
                    message = test_case.get("message")
                    expected_digest = test_case.get("digest")

                    if not message or not expected_digest:
                        result["error"] = "缺少消息或期望摘要"
                        results.append(result)
                        continue

                    # 计算SM3哈希
                    actual_digest = self.sm3_hash(message)

                    if actual_digest == expected_digest:
                        result["passed"] = True
                    else:
                        result["error"] = f"哈希结果不匹配: 期望{expected_digest.hex()}, 实际{actual_digest.hex()}"

                except Exception as e:
                    result["error"] = str(e)

                results.append(result)

        return results

    def test_hmac_vectors(self) -> List[Dict[str, Any]]:
        """测试SM3-HMAC向量"""
        print("🔐 测试SM3-HMAC向量...")

        results = []

        # 查找HMAC测试文件
        hmac_files = ["SM3_HMAC_5.txt"]

        for filename in hmac_files:
            test_cases = self.parse_sm3_file(filename)

            for i, test_case in enumerate(test_cases):
                result = {
                    "test_name": f"SM3-HMAC_{filename}_{i+1}",
                    "passed": False,
                    "error": "",
                    "details": {}
                }

                try:
                    key = test_case.get("key")
                    message = test_case.get("message")
                    expected_hmac = test_case.get("hmac")

                    if not key or not message or not expected_hmac:
                        result["error"] = "缺少密钥、消息或期望HMAC"
                        results.append(result)
                        continue

                    # 计算SM3-HMAC
                    actual_hmac = self.sm3_hmac(key, message)

                    if actual_hmac == expected_hmac:
                        result["passed"] = True
                    else:
                        result["error"] = f"HMAC结果不匹配: 期望{expected_hmac.hex()}, 实际{actual_hmac.hex()}"

                except Exception as e:
                    result["error"] = str(e)

                results.append(result)

        return results

    def test_basic_functionality(self) -> List[Dict[str, Any]]:
        """测试基本功能"""
        print("🔧 测试SM3基本功能...")

        results = []

        # 测试1: 输出长度检查
        result = {
            "test_name": "SM3基本_输出长度",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            digest = self.sm3_hash(b"test")
            if len(digest) == 32:  # SM3输出32字节
                result["passed"] = True
            else:
                result["error"] = f"输出长度错误: {len(digest)}字节，期望32字节"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试2: 一致性检查
        result = {
            "test_name": "SM3基本_一致性检查",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            msg = b"test message for consistency"
            digest1 = self.sm3_hash(msg)
            digest2 = self.sm3_hash(msg)
            if digest1 == digest2:
                result["passed"] = True
            else:
                result["error"] = "相同消息产生不同的哈希值"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试3: 差异性检查
        result = {
            "test_name": "SM3基本_差异性检查",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            digest1 = self.sm3_hash(b"message1")
            digest2 = self.sm3_hash(b"message2")
            if digest1 != digest2:
                result["passed"] = True
            else:
                result["error"] = "不同消息产生相同的哈希值"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试4: 空消息处理
        result = {
            "test_name": "SM3基本_空消息",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            digest = self.sm3_hash(b"")
            if len(digest) == 32 and digest != b'\x00' * 32:
                result["passed"] = True
            else:
                result["error"] = "空消息处理错误"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        # 测试5: 大消息处理
        result = {
            "test_name": "SM3基本_大消息",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            # 处理1KB的消息（进一步减少大小）
            large_msg = b"x" * (1 * 1024)
            digest = self.sm3_hash(large_msg)
            if len(digest) == 32:
                result["passed"] = True
            else:
                result["error"] = "大消息处理错误"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)

        return results

    def run_all_tests(self, output_dir: str = "./test_reports") -> Dict[str, Any]:
        """运行所有SM3测试"""
        print("=" * 60)
        print("🔐 SM3算法统一测试")
        print("=" * 60)

        # 1. 执行基本功能测试（保留原逻辑）
        basic_results = self.test_basic_functionality()
        # 2. 启用哈希向量测试（原跳过部分）
        hash_results = self.test_hash_vectors()
        # 3. 启用HMAC向量测试（原跳过部分）
        hmac_results = self.test_hmac_vectors()
        # 4. 合并所有测试结果
        self.results["details"] = basic_results + hash_results + hmac_results
        self.results["total_tests"] = len(self.results["details"])
        self.results["passed"] = sum(1 for d in self.results["details"] if d["passed"])
        self.results["failed"] = sum(1 for d in self.results["details"] if not d["passed"] and "error" in d)
        self.results["pass_rate"] = self.results["passed"] / self.results["total_tests"] if self.results["total_tests"] > 0 else 0
        # 5. 生成报告
        from src.crypto_test_reporter import SM3Reporter
        reporter = SM3Reporter()
        reporter.save_reports(self.results, output_dir=output_dir)
        return self.results

    def save_results(self, output_dir: str = "./results") -> None:
        """保存测试结果"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        results_file = output_path / 'sm3_test_results.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        summary_file = output_path / 'sm3_test_summary.txt'
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("🔐 SM3算法测试报告\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"测试用例总数: {self.results['total_tests']}\n")
            f.write(f"通过数: {self.results['passed']}\n")
            f.write(f"失败数: {self.results['failed']}\n")
            f.write(f"跳过数: {self.results['skipped']}\n")
            f.write(f"通过率: {self.results['pass_rate']:.2%}\n\n")

            f.write("详细结果:\n")
            for detail in self.results['details']:
                status = "✅" if detail['passed'] else "❌"
                f.write(f"  {status} {detail['test_name']}\n")
                if not detail['passed'] and detail.get('error'):
                    f.write(f"    错误: {detail['error']}\n")

        print(f"✓ 详细结果已保存到: {results_file}")
        print(f"✓ 统计摘要已保存到: {summary_file}")


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(
        description="SM3算法统一测试程序",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 sm3_unified_test.py                    # 运行所有测试
  python3 sm3_unified_test.py -o ./test_output    # 指定输出目录
        """
    )

    parser.add_argument(
        "-o", "--output-dir",
        default="./results",
        help="输出目录 (默认: ./results)"
    )

    args = parser.parse_args()

    # 初始化测试器
    tester = SM3UnifiedTest()

    # 运行测试
    results = tester.run_all_tests(output_dir=args.output_dir)

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