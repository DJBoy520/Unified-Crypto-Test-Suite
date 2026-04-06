#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4算法统一测试（简化版）
专注于基本功能验证而不是精确向量匹配
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Any

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.sm4.sm4_impl import SM4, sm4_encrypt, sm4_decrypt
from src.sm4.sm4_comprehensive_test import SM4ComprehensiveTest


class SM4UnifiedTest:
    """SM4 算法统一测试器"""
    
    def __init__(self):
        """初始化SM4测试器"""
        self.project_root = Path(__file__).parent
        self.vector_dir = self.project_root / "algorithm" / "SM4"
        self.results = {
            "algorithm": "SM4",
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "details": []
        }
    
    def test_basic_functionality(self) -> List[Dict[str, Any]]:
        """测试SM4基本功能"""
        print("🔧 测试SM4基本功能...")
        
        results = []
        
        # 测试1: 密钥长度检查
        result = {
            "test_name": "SM4基本_密钥长度",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            # SM4必须使用16字节密钥
            key = b"0123456789ABCDEF"  # 16字节
            cipher = SM4(key)
            result["passed"] = True
        except ValueError as e:
            result["error"] = str(e)
        except Exception as e:
            result["error"] = f"初始化失败: {str(e)}"
        results.append(result)
        
        # 测试2: 加密/解密一致性
        result = {
            "test_name": "SM4基本_加解密一致性",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            key = b"0123456789ABCDEF"  # 16字节
            plaintext = b"This is plaintext message for testing!"
            
            # 加密
            ciphertext = sm4_encrypt(key, plaintext)
            
            # 解密
            decrypted = sm4_decrypt(key, ciphertext)
            
            # 检查解密后去除填充的数据
            if decrypted.rstrip(b'\x00') == plaintext:
                result["passed"] = True
            else:
                result["error"] = f"解密结果不匹配"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
        
        # 测试3: 密钥不同导致结果不同
        result = {
            "test_name": "SM4基本_密钥敏感性",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            key1 = b"AAAABBBBCCCCDDDD"  # 16字节
            key2 = b"EEEEFFFFGGGGHHHH"  # 16字节
            plaintext = b"Same plaintext message by 16 byte"
            
            cipher1 = sm4_encrypt(key1, plaintext)
            cipher2 = sm4_encrypt(key2, plaintext)
            
            if cipher1 != cipher2:
                result["passed"] = True
            else:
                result["error"] = "不同密钥产生相同密文"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
        
        # 测试4: 明文不同导致结果不同
        result = {
            "test_name": "SM4基本_明文敏感性",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            key = b"Key1234567890AB!"  # 16字节
            plaintext1 = b"Message Number 1"
            plaintext2 = b"Message Number 2"
            
            cipher1 = sm4_encrypt(key, plaintext1)
            cipher2 = sm4_encrypt(key, plaintext2)
            
            if cipher1 != cipher2:
                result["passed"] = True
            else:
                result["error"] = "不同明文产生相同密文"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
        
        # 测试5: 大数据处理
        result = {
            "test_name": "SM4基本_大数据处理",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            key = b"LargeDataTestKey"  # 16字节
            # 使用较小的数据避免超时
            plaintext = b"x" * (64 * 1024)  # 64KB
            
            ciphertext = sm4_encrypt(key, plaintext)
            decrypted = sm4_decrypt(key, ciphertext)
            
            if decrypted.rstrip(b'\x00') == plaintext:
                result["passed"] = True
            else:
                result["error"] = "大数据处理失败"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
        
        # 测试6: 重复加密测试
        result = {
            "test_name": "SM4基本_重复加密",
            "passed": False,
            "error": "",
            "details": {}
        }
        try:
            key = b"RepeatKeyTest!~!"  # 16字节
            plaintext = b"Test message content"
            
            # 加密两次
            cipher1 = sm4_encrypt(key, plaintext)
            cipher2 = sm4_encrypt(key, plaintext)
            
            if cipher1 == cipher2:
                result["passed"] = True
            else:
                result["error"] = "相同输入产生不同密文"
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
        
        return results
    
    def run_all_tests(self) -> Dict[str, Any]:
        """运行所有SM4测试"""
        print("=" * 60)
        print("🔐 SM4算法统一测试")
        print("=" * 60)
        
        # 测试基本功能
        basic_results = self.test_basic_functionality()
        for result in basic_results:
            self.results["details"].append(result)
            if result["passed"]:
                self.results["passed"] += 1
            else:
                self.results["failed"] += 1
            self.results["total_tests"] += 1
        
        # 启用向量测试
        print("运行SM4向量测试...")
        comp_test = SM4ComprehensiveTest(vector_dir=str(self.vector_dir), output_dir="./test_reports")
        comp_results = comp_test.run_all_tests()
        self.results.update(comp_results)
        
        # 计算通过率
        self.results["pass_rate"] = self.results["passed"] / self.results["total_tests"] if self.results["total_tests"] > 0 else 0
        
        return self.results
    
    def save_results(self, output_dir: str = "./results") -> None:
        """保存测试结果"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        results_file = output_path / 'sm4_test_results.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        summary_file = output_path / 'sm4_test_summary.txt'
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("🔐 SM4算法测试报告\n")
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
        description="SM4算法统一测试程序",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 sm4_unified_test_simple.py                    # 运行所有测试
  python3 sm4_unified_test_simple.py -o ./test_output    # 指定输出目录
        """
    )
    
    parser.add_argument(
        "-o", "--output-dir",
        default="./results",
        help="输出目录 (默认: ./results)"
    )
    
    args = parser.parse_args()
    
    # 初始化测试器
    tester = SM4UnifiedTest()
    
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
