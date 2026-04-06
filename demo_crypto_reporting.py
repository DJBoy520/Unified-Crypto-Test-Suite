#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一加密算法测试报告生成系统演示
展示如何使用新的报告生成系统
"""

import os
import sys
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.crypto_test_reporter import (
    SM2Reporter,
    SM3Reporter,
    SM4Reporter,
    MultiAlgorithmReporter,
    generate_sm2_report,
    generate_multi_algorithm_report
)


def demo_sm2_report():
    """演示SM2单算法报告生成"""
    print("=" * 60)
    print("🇨🇳 SM2单算法报告生成演示")
    print("=" * 60)

    # 模拟SM2测试结果
    mock_sm2_results = {
        "total_tests": 40,
        "passed": 36,
        "failed": 4,
        "skipped": 0,
        "error": 0,
        "pass_rate": 0.9,
        "details": [
            {
                "test_name": "SM2基本功能验证",
                "passed": True,
                "details": {"test_type": "basic"}
            },
            {
                "test_name": "SM2密钥对验证",
                "passed": True,
                "details": {"key_pairs": 10}
            },
            {
                "test_name": "SM2加密计算验证",
                "passed": False,
                "error": "计算结果不匹配",
                "details": {"failed_cases": 5}
            }
        ]
    }

    # 使用类方式生成报告
    print("📊 使用SM2Reporter类生成报告...")
    reporter = SM2Reporter()
    report_paths = reporter.save_reports(mock_sm2_results, "./demo_reports")

    print(f"✓ JSON报告: {report_paths['json']}")
    print(f"✓ TXT报告: {report_paths['txt']}")

    # 使用便捷函数生成报告
    print("\n🔧 使用便捷函数生成报告...")
    quick_paths = generate_sm2_report(mock_sm2_results, "./demo_reports/quick")
    print(f"✓ 快速生成JSON报告: {quick_paths['json']}")
    print(f"✓ 快速生成TXT报告: {quick_paths['txt']}")


def demo_multi_algorithm_report():
    """演示多算法报告生成"""
    print("\n" + "=" * 60)
    print("🌐 多算法报告生成演示")
    print("=" * 60)

    # 模拟多个算法的测试结果
    mock_results = {
        "SM2": {
            "total_tests": 40,
            "passed": 36,
            "failed": 4,
            "skipped": 0,
            "error": 0,
            "pass_rate": 0.9,
            "details": [
                {"test_name": "SM2基本功能", "passed": True},
                {"test_name": "SM2加密", "passed": False, "error": "计算错误"}
            ]
        },
        "SM3": {
            "total_tests": 20,
            "passed": 20,
            "failed": 0,
            "skipped": 0,
            "error": 0,
            "pass_rate": 1.0,
            "details": [
                {"test_name": "SM3哈希测试", "passed": True},
                {"test_name": "SM3向量验证", "passed": True}
            ]
        },
        "SM4": {
            "total_tests": 30,
            "passed": 28,
            "failed": 2,
            "skipped": 0,
            "error": 0,
            "pass_rate": 0.933,
            "details": [
                {"test_name": "SM4加密", "passed": True},
                {"test_name": "SM4解密", "passed": False, "error": "模式错误"}
            ]
        }
    }

    # 使用MultiAlgorithmReporter生成合并报告
    print("📈 生成多算法合并报告...")
    multi_reporter = MultiAlgorithmReporter()
    combined_paths = multi_reporter.save_combined_reports(mock_results, "./demo_reports")

    print(f"✓ 合并JSON报告: {combined_paths['json']}")
    print(f"✓ 合并TXT报告: {combined_paths['txt']}")

    # 使用便捷函数生成合并报告
    print("\n🚀 使用便捷函数生成合并报告...")
    quick_combined_paths = generate_multi_algorithm_report(mock_results, "./demo_reports/quick_combined")
    print(f"✓ 快速合并JSON报告: {quick_combined_paths['json']}")
    print(f"✓ 快速合并TXT报告: {quick_combined_paths['txt']}")


def demo_real_sm2_test():
    """演示使用真实SM2测试数据生成报告"""
    print("\n" + "=" * 60)
    print("🔬 真实SM2测试报告生成演示")
    print("=" * 60)

    try:
        # 运行真实的SM2测试
        from src.sm2.sm2_unified_test_simple import SM2UnifiedTestSimple

        print("🏃 运行SM2统一测试...")
        tester = SM2UnifiedTestSimple()
        test_results = tester.run_all_tests()

        print("📋 生成真实测试报告...")
        real_paths = generate_sm2_report(test_results, "./demo_reports/real_sm2")
        print(f"✓ 真实JSON报告: {real_paths['json']}")
        print(f"✓ 真实TXT报告: {real_paths['txt']}")

    except Exception as e:
        print(f"❌ 真实测试运行失败: {e}")
        print("请确保所有依赖都已正确安装")


def show_report_structure():
    """展示报告的文件结构"""
    print("\n" + "=" * 60)
    print("📁 报告文件结构说明")
    print("=" * 60)

    structure = """
./reports/
├── SM2_TEST_20240325_143052.json          # SM2详细JSON报告
├── SM2_TEST_20240325_143052.txt           # SM2摘要TXT报告
├── ALL_CRYPTO_TEST_20240325_143053.json   # 多算法合并JSON报告
└── ALL_CRYPTO_TEST_20240325_143053.txt    # 多算法合并TXT报告

报告内容包含:
📊 元数据: 报告ID、算法类型、生成时间、测试时长
🖥️  环境信息: Python版本、操作系统、CPU、内存等
📈 摘要统计: 总测试数、通过数、失败数、通过率
🔍 详细结果: 每个测试用例的执行结果和错误信息
❌ 失败分析: 失败原因分类和常见错误模式
⚡ 性能指标: 算法执行速度和资源使用情况
✅ 合规性检查: 国密标准符合性验证
💡 改进建议: 基于测试结果的优化建议
"""

    print(structure)


def main():
    """主演示函数"""
    print("🚀 统一加密算法测试报告生成系统演示")
    print("本演示将展示如何使用新的报告生成系统")

    # 创建演示目录
    os.makedirs("./demo_reports", exist_ok=True)
    os.makedirs("./demo_reports/quick", exist_ok=True)
    os.makedirs("./demo_reports/quick_combined", exist_ok=True)
    os.makedirs("./demo_reports/real_sm2", exist_ok=True)

    # 运行各种演示
    demo_sm2_report()
    demo_multi_algorithm_report()
    demo_real_sm2_test()
    show_report_structure()

    print("\n" + "=" * 60)
    print("✅ 演示完成！")
    print("生成的报告文件保存在 ./demo_reports/ 目录中")
    print("=" * 60)


if __name__ == "__main__":
    main()