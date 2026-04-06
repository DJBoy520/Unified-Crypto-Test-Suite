#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4算法完整测试套件
- 解析测试向量文件
- 执行多模式测试验证
- 生成统一测试报告

使用: python sm4_comprehensive_test.py [--vector-dir <path>] [--output-dir <path>] [--verbose]
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.sm4.sm4_vector_parser import SM4VectorParser, parse_sm4_vector_file
from src.sm4.sm4_vector_validator import SM4VectorValidator, validate_all_sm4_vectors
from src.crypto_test_reporter import SM4Reporter


class SM4ComprehensiveTest:
    """SM4完整测试套件"""
    
    def __init__(self, vector_dir: str, output_dir: str = "./test_reports", verbose: bool = True):
        """
        初始化测试套件
        
        Args:
            vector_dir: 测试向量目录
            output_dir: 输出报告目录
            verbose: 是否输出详细信息
        """
        self.vector_dir = vector_dir
        self.output_dir = output_dir
        self.verbose = verbose
        self.validator = SM4VectorValidator(verbose=verbose)
        self.test_results = {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "error": 0,
            "details": [],
            "file_results": {}
        }
    
    def _log(self, message: str, level: str = "INFO"):
        """记录日志"""
        if self.verbose:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [{level}] {message}")
    
    def run_all_tests(self) -> Dict[str, Any]:
        """
        运行所有测试
        
        Returns:
            测试结果汇总
        """
        self._log("=" * 80)
        self._log("🚀 SM4算法完整测试套件启动")
        self._log("=" * 80)
        
        # 步骤1: 收集测试向量文件
        self._log("\n📁 第1步: 收集测试向量文件")
        sm4_files = self._collect_test_files()
        
        if not sm4_files:
            self._log("❌ 未找到SM4测试向量文件！", "ERROR")
            return self._generate_final_results()
        
        self._log(f"✓ 找到 {len(sm4_files)} 个测试向量文件")
        for filename in sm4_files:
            self._log(f"  • {filename}")
        
        # 步骤2: 验证所有文件
        self._log("\n🧪 第2步: 执行测试向量验证")
        self._validate_all_files(sm4_files)
        
        # 步骤3: 生成报告
        self._log("\n📊 第3步: 生成测试报告")
        self._generate_reports()
        
        # 显示结果摘要
        self._print_summary()
        
        return self._generate_final_results()
    
    def _collect_test_files(self) -> List[str]:
        """收集测试向量文件"""
        if not os.path.isdir(self.vector_dir):
            self._log(f"❌ 目录不存在: {self.vector_dir}", "ERROR")
            return []
        
        sm4_files = sorted([
            f for f in os.listdir(self.vector_dir)
            if f.upper().startswith('SM4') and f.upper().endswith('.TXT')
        ])
        
        return sm4_files
    
    def _validate_all_files(self, sm4_files: List[str]):
        """验证所有SM4测试向量文件"""
        for filename in sm4_files:
            file_path = os.path.join(self.vector_dir, filename)
            self._log(f"\n📄 验证文件: {filename}")
            
            try:
                # 解析文件
                vectors = parse_sm4_vector_file(file_path)
                
                if not vectors:
                    self._log(f"  ⚠️ 文件为空或无法解析", "WARN")
                    self.test_results["error"] += 1
                    continue
                
                self._log(f"  ✓ 解析成功，获得 {len(vectors)} 个测试向量")
                
                # 验证每个向量
                file_passed = 0
                file_failed = 0
                file_error = 0
                
                for i, vector in enumerate(vectors):
                    mode = vector.get('mode', 'UNKNOWN')
                    
                    result = self.validator.validate_vector(vector, mode)
                    result['file'] = filename
                    result['index'] = i + 1
                    
                    self.test_results["details"].append(result)
                    self.test_results["total_tests"] += 1
                    
                    if '_error' in vector:
                        file_error += 1
                        self.test_results["error"] += 1
                    elif result.get('passed'):
                        file_passed += 1
                        self.test_results["passed"] += 1
                    elif result.get('passed') is None:
                        file_error += 1
                        self.test_results["error"] += 1
                    else:
                        file_failed += 1
                        self.test_results["failed"] += 1
                    
                    # 输出单个测试结果
                    status_icon = "✓" if result.get('passed') else "✗" if result.get('passed') is False else "⊘"
                    self._log(f"  {status_icon} 向量 {i+1} ({mode}): {result.get('error', 'PASS')}")
                
                # 记录文件结果
                self.test_results["file_results"][filename] = {
                    "total": len(vectors),
                    "passed": file_passed,
                    "failed": file_failed,
                    "error": file_error
                }
                
                self._log(f"  📈 文件结果: {file_passed}/{len(vectors)} 通过")
            
            except Exception as e:
                self._log(f"  ❌ 异常: {str(e)}", "ERROR")
                self.test_results["error"] += 1
    
    def _generate_reports(self):
        """生成测试报告"""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            
            reporter = SM4Reporter()
            
            self._log(f"  生成SM4测试报告...")
            report_files = reporter.save_reports(self.test_results, self.output_dir)
            
            self._log(f"  ✓ JSON报告: {report_files['json']}")
            self._log(f"  ✓ TXT报告: {report_files['txt']}")
        
        except Exception as e:
            self._log(f"❌ 报告生成失败: {str(e)}", "ERROR")
    
    def _print_summary(self):
        """打印结果摘要"""
        self._log("\n" + "=" * 80)
        self._log("📋 测试结果摘要")
        self._log("=" * 80)
        
        total = self.test_results["total_tests"]
        passed = self.test_results["passed"]
        failed = self.test_results["failed"]
        error = self.test_results["error"]
        
        if total > 0:
            pass_rate = passed / (total - error) * 100 if (total - error) > 0 else 0
        else:
            pass_rate = 0
        
        self._log(f"总测试用例: {total}")
        self._log(f"✓ 通过: {passed}")
        self._log(f"✗ 失败: {failed}")
        self._log(f"⊘ 错误: {error}")
        self._log(f"通过率: {pass_rate:.2f}%")
        self._log("")
        
        # 按模式统计
        self._log("📊 按模式统计:")
        mode_stats = {}
        for detail in self.test_results["details"]:
            mode = detail.get('mode', 'UNKNOWN')
            if mode not in mode_stats:
                mode_stats[mode] = {"total": 0, "passed": 0}
            mode_stats[mode]["total"] += 1
            if detail.get('passed'):
                mode_stats[mode]["passed"] += 1
        
        for mode in sorted(mode_stats.keys()):
            stats = mode_stats[mode]
            rate = stats["passed"] / stats["total"] * 100 if stats["total"] > 0 else 0
            self._log(f"  • {mode:15} {stats['passed']:3}/{stats['total']:3} ({rate:6.2f}%)")
        
        self._log("=" * 80)
    
    def _generate_final_results(self) -> Dict[str, Any]:
        """生成最终结果"""
        total = self.test_results["total_tests"]
        passed = self.test_results["passed"]
        failed = self.test_results["failed"]
        error = self.test_results["error"]
        
        valid_tests = total - error
        if valid_tests > 0:
            pass_rate = passed / valid_tests * 100
        else:
            pass_rate = 0
        
        return {
            "summary": {
                "total_tests": total,
                "passed": passed,
                "failed": failed,
                "error": error,
                "pass_rate_percent": round(pass_rate, 2),
                "test_timestamp": datetime.now().isoformat()
            },
            "detailed_results": self.test_results
        }


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="SM4算法完整测试套件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python sm4_comprehensive_test.py
  python sm4_comprehensive_test.py --vector-dir /path/to/vectors
  python sm4_comprehensive_test.py --output-dir ./my_reports --verbose
        """
    )
    
    parser.add_argument(
        '--vector-dir',
        default='./algorithm/SM4',
        help='测试向量目录 (默认: ./algorithm/SM4)'
    )
    
    parser.add_argument(
        '--output-dir',
        default='./test_reports',
        help='输出报告目录 (默认: ./test_reports)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        default=True,
        help='输出详细信息 (默认: 启用)'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='禁用详细信息输出'
    )
    
    args = parser.parse_args()
    
    # 处理 verbose 和 quiet 选项
    verbose = args.verbose and not args.quiet
    
    # 创建测试套件并运行
    test_suite = SM4ComprehensiveTest(
        vector_dir=args.vector_dir,
        output_dir=args.output_dir,
        verbose=verbose
    )
    
    results = test_suite.run_all_tests()
    
    # 返回合适的退出码
    if results['summary']['pass_rate_percent'] >= 95:
        return 0
    elif results['summary']['pass_rate_percent'] >= 80:
        return 1
    else:
        return 2


if __name__ == '__main__':
    sys.exit(main())
