#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
密码算法统一测试主程序
调用所有算法的测试入口：SM2, SM3, SM4, RSA
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Any

class CryptoTestSuite:
    """密码算法测试套件"""

    def __init__(self):
        """初始化测试套件"""
        self.project_root = Path(__file__).parent
        self.results = {
            "test_suite": "密码算法测试套件",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "algorithms": {},
            "summary": {
                "total_algorithms": 0,
                "total_tests": 0,
                "total_passed": 0,
                "total_failed": 0,
                "total_skipped": 0,
                "overall_pass_rate": 0.0
            }
        }

    def run_algorithm_test(self, algorithm_name: str, test_script: str, args: List[str] = None) -> Dict[str, Any]:
        """运行单个算法的测试"""
        print(f"\n{'='*20} 开始测试 {algorithm_name} {'='*20}")

        result = {
            "algorithm": algorithm_name,
            "success": False,
            "exit_code": -1,
            "error": "",
            "details": {}
        }

        try:
            # 构建命令
            cmd = [sys.executable, test_script]
            if args:
                cmd.extend(args)

            # 运行测试脚本
            import subprocess
            process = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=300  # 5分钟超时
            )

            result["exit_code"] = process.returncode
            result["success"] = (process.returncode == 0)

            # 解析输出
            output = process.stdout
            error = process.stderr

            if result["success"]:
                print(f"✅ {algorithm_name} 测试完成")
            else:
                print(f"❌ {algorithm_name} 测试失败")
                result["error"] = error

            # 尝试读取结果文件
            results_file = self.project_root / "results" / f"{algorithm_name.lower()}_test_results.json"
            if results_file.exists():
                try:
                    with open(results_file, 'r', encoding='utf-8') as f:
                        result["details"] = json.load(f)
                except Exception as e:
                    print(f"⚠️  无法读取 {algorithm_name} 结果文件: {e}")

        except subprocess.TimeoutExpired:
            result["error"] = f"{algorithm_name} 测试超时"
            print(f"⏰ {algorithm_name} 测试超时")
        except Exception as e:
            result["error"] = str(e)
            print(f"💥 {algorithm_name} 测试异常: {e}")

        return result

    def run_all_tests(self, output_dir: str = "./results") -> Dict[str, Any]:
        """运行所有算法测试"""
        print("=" * 80)
        print("🔐 密码算法统一测试套件")
        print("=" * 80)
        print(f"开始时间: {self.results['timestamp']}")
        print(f"输出目录: {output_dir}")
        print()

        # 定义要测试的算法
        algorithms = [
            {
                "name": "SM2",
                "script": "src/sm2/sm2_unified_test_simple.py",
                "args": ["-o", output_dir]
            },
            {
                "name": "SM3",
                "script": "src/sm3/sm3_unified_test.py",
                "args": ["-o", output_dir]
            },
            {
                "name": "SM4",
                "script": "src/sm4/sm4_unified_test_simple.py",
                "args": ["-o", output_dir]
            },
            {
                "name": "RSA",
                "script": "src/rsa/rsa_unified_test.py",
                "args": ["-o", output_dir]
            }
        ]

        # 运行每个算法的测试
        for alg_config in algorithms:
            alg_name = alg_config["name"]
            alg_script = alg_config["script"]
            alg_args = alg_config["args"]

            # 检查脚本是否存在
            script_path = self.project_root / alg_script
            if not script_path.exists():
                print(f"⚠️  跳过 {alg_name}: 脚本文件不存在 {alg_script}")
                continue

            # 运行测试
            alg_result = self.run_algorithm_test(alg_name, alg_script, alg_args)
            self.results["algorithms"][alg_name] = alg_result

            # 累加统计信息 - 所有运行的算法都计入总数
            self.results["summary"]["total_algorithms"] += 1
            # 即使算法执行失败，也尝试从结果文件中获取统计信息
            if "details" in alg_result:
                details = alg_result["details"]
                self.results["summary"]["total_tests"] += details.get("total_tests", 0)
                self.results["summary"]["total_passed"] += details.get("passed", 0)
                self.results["summary"]["total_failed"] += details.get("failed", 0)
                self.results["summary"]["total_skipped"] += details.get("skipped", 0)

        # 计算总体通过率
        total_tests = self.results["summary"]["total_tests"]
        total_passed = self.results["summary"]["total_passed"]
        if total_tests > 0:
            self.results["summary"]["overall_pass_rate"] = total_passed / total_tests

        return self.results

    def save_results(self, output_dir: str = "./results") -> None:
        """保存测试结果"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # 保存详细结果
        results_file = output_path / 'crypto_test_suite_results.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        # 保存汇总报告
        summary_file = output_path / 'crypto_test_suite_summary.txt'
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("🔐 密码算法测试套件报告\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"测试时间: {self.results['timestamp']}\n")
            f.write(f"测试算法数: {self.results['summary']['total_algorithms']}\n")
            f.write(f"总测试用例: {self.results['summary']['total_tests']}\n")
            f.write(f"总通过数: {self.results['summary']['total_passed']}\n")
            f.write(f"总失败数: {self.results['summary']['total_failed']}\n")
            f.write(f"总跳过数: {self.results['summary']['total_skipped']}\n")
            f.write(f"总体通过率: {self.results['summary']['overall_pass_rate']:.2%}\n\n")

            f.write("各算法结果:\n")
            for alg_name, alg_result in self.results["algorithms"].items():
                status = "✅" if alg_result["success"] else "❌"
                f.write(f"  {status} {alg_name}\n")

                if alg_result["success"] and "details" in alg_result:
                    details = alg_result["details"]
                    passed = details.get("passed", 0)
                    total = details.get("total_tests", 0)
                    if total > 0:
                        rate = passed / total * 100
                        f.write(f"    测试用例: {passed}/{total} ({rate:.1f}%)\n")

                if not alg_result["success"] and alg_result.get("error"):
                    f.write(f"    错误: {alg_result['error'][:100]}...\n")

        print(f"✓ 详细结果已保存到: {results_file}")
        print(f"✓ 汇总报告已保存到: {summary_file}")

    def print_summary(self) -> None:
        """打印测试摘要"""
        print("\n" + "=" * 80)
        print("📊 测试套件摘要")
        print("=" * 80)
        summary = self.results["summary"]
        print(f"测试算法数: {summary['total_algorithms']}")
        print(f"总测试用例: {summary['total_tests']}")
        print(f"总通过数: {summary['total_passed']}")
        print(f"总失败数: {summary['total_failed']}")
        print(f"总跳过数: {summary['total_skipped']}")
        print(f"总体通过率: {summary['overall_pass_rate']:.2%}")

        print("\n各算法状态:")
        for alg_name, alg_result in self.results["algorithms"].items():
            status = "✅ 通过" if alg_result["success"] else "❌ 失败"
            print(f"  {alg_name}: {status}")

        if summary['total_failed'] == 0:
            print("\n🎉 所有测试通过!")
        else:
            print(f"\n⚠️  {summary['total_failed']} 个测试失败")


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(
        description="密码算法统一测试套件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 crypto_test_suite.py                    # 运行所有算法测试
  python3 crypto_test_suite.py -o ./test_output    # 指定输出目录
  python3 crypto_test_suite.py --algorithms SM2 SM4  # 只测试指定算法
        """
    )

    parser.add_argument(
        "-o", "--output-dir",
        default="./results",
        help="输出目录 (默认: ./results)"
    )
    parser.add_argument(
        "--algorithms",
        nargs="*",
        choices=["SM2", "SM3", "SM4", "RSA"],
        help="指定要测试的算法 (默认: 全部)"
    )

    args = parser.parse_args()

    # 初始化测试套件
    test_suite = CryptoTestSuite()

    # 运行测试
    results = test_suite.run_all_tests(args.output_dir)

    # 保存结果
    test_suite.save_results(args.output_dir)

    # 打印摘要
    test_suite.print_summary()

    # 返回退出码
    if results["summary"]["total_failed"] == 0:
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())