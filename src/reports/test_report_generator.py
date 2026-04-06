#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试报告生成器
从测试结果JSON文件生成各种格式的测试报告
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime


class TestReportGenerator:
    """测试报告生成器"""

    def __init__(self):
        """初始化报告生成器"""
        self.results = {}

    def load_results(self, results_file: str) -> bool:
        """加载测试结果文件"""
        try:
            with open(results_file, 'r', encoding='utf-8') as f:
                self.results = json.load(f)
            return True
        except Exception as e:
            print(f"❌ 加载结果文件失败: {e}")
            return False

    def generate_text_report(self, output_file: str) -> None:
        """生成文本格式报告"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("🔐 密码算法测试报告\n")
            f.write("=" * 80 + "\n\n")

            if "timestamp" in self.results:
                f.write(f"测试时间: {self.results['timestamp']}\n")

            if "summary" in self.results:
                summary = self.results["summary"]
                f.write(f"测试算法数: {summary.get('total_algorithms', 0)}\n")
                f.write(f"总测试用例: {summary.get('total_tests', 0)}\n")
                f.write(f"总通过数: {summary.get('total_passed', 0)}\n")
                f.write(f"总失败数: {summary.get('total_failed', 0)}\n")
                f.write(f"总跳过数: {summary.get('total_skipped', 0)}\n")
                f.write(f"总体通过率: {summary.get('overall_pass_rate', 0):.2%}\n\n")

            f.write("各算法详细结果:\n")
            f.write("-" * 50 + "\n")

            if "algorithms" in self.results:
                for alg_name, alg_result in self.results["algorithms"].items():
                    status = "✅ 通过" if alg_result.get("success", False) else "❌ 失败"
                    f.write(f"\n{alg_name}算法: {status}\n")

                    if alg_result.get("success") and "details" in alg_result:
                        details = alg_result["details"]
                        f.write(f"  测试用例总数: {details.get('total_tests', 0)}\n")
                        f.write(f"  通过数: {details.get('passed', 0)}\n")
                        f.write(f"  失败数: {details.get('failed', 0)}\n")
                        f.write(f"  跳过数: {details.get('skipped', 0)}\n")

                        total = details.get('total_tests', 0)
                        passed = details.get('passed', 0)
                        if total > 0:
                            rate = passed / total * 100
                            f.write(f"  通过率: {rate:.1f}%\n")

                    if not alg_result.get("success"):
                        error = alg_result.get("error", "未知错误")
                        f.write(f"  错误信息: {error[:200]}...\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("报告生成时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")

        print(f"✅ 文本报告已保存到: {output_file}")

    def generate_html_report(self, output_file: str) -> None:
        """生成HTML格式报告"""
        html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>密码算法测试报告</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; text-align: center; margin-bottom: 30px; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .metric {{ text-align: center; padding: 10px; background: white; border-radius: 5px; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #27ae60; }}
        .metric-label {{ font-size: 14px; color: #7f8c8d; }}
        .algorithm {{ margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .algorithm.success {{ border-color: #27ae60; background-color: #d5f4e6; }}
        .algorithm.failure {{ border-color: #e74c3c; background-color: #fadbd8; }}
        .status {{ font-weight: bold; }}
        .success {{ color: #27ae60; }}
        .failure {{ color: #e74c3c; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 密码算法测试报告</h1>

        <div class="summary">
            <h2>📊 测试汇总</h2>
            <div class="summary-grid">
"""

        if "summary" in self.results:
            summary = self.results["summary"]
            html_content += f"""
                <div class="metric">
                    <div class="metric-value">{summary.get('total_algorithms', 0)}</div>
                    <div class="metric-label">测试算法数</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{summary.get('total_tests', 0)}</div>
                    <div class="metric-label">总测试用例</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{summary.get('total_passed', 0)}</div>
                    <div class="metric-label">总通过数</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{summary.get('overall_pass_rate', 0):.1%}</div>
                    <div class="metric-label">总体通过率</div>
                </div>
"""

        html_content += """
            </div>
        </div>

        <h2>🔍 各算法详细结果</h2>
"""

        if "algorithms" in self.results:
            for alg_name, alg_result in self.results["algorithms"].items():
                status_class = "success" if alg_result.get("success", False) else "failure"
                status_text = "✅ 通过" if alg_result.get("success", False) else "❌ 失败"

                html_content += f"""
        <div class="algorithm {status_class}">
            <h3>{alg_name}算法 <span class="status">{status_text}</span></h3>
"""

                if alg_result.get("success") and "details" in alg_result:
                    details = alg_result["details"]
                    html_content += f"""
            <table>
                <tr><th>指标</th><th>数值</th></tr>
                <tr><td>测试用例总数</td><td>{details.get('total_tests', 0)}</td></tr>
                <tr><td>通过数</td><td>{details.get('passed', 0)}</td></tr>
                <tr><td>失败数</td><td>{details.get('failed', 0)}</td></tr>
                <tr><td>跳过数</td><td>{details.get('skipped', 0)}</td></tr>
"""

                    total = details.get('total_tests', 0)
                    passed = details.get('passed', 0)
                    if total > 0:
                        rate = passed / total * 100
                        html_content += f"<tr><td>通过率</td><td>{rate:.1f}%</td></tr>"

                    html_content += "</table>"

                if not alg_result.get("success"):
                    error = alg_result.get("error", "未知错误")
                    html_content += f"<p><strong>错误信息:</strong> {error[:200]}...</p>"

                html_content += "</div>"

        html_content += f"""
        <hr>
        <p style="text-align: center; color: #7f8c8d;">
            报告生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </p>
    </div>
</body>
</html>"""

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"✅ HTML报告已保存到: {output_file}")

    def generate_markdown_report(self, output_file: str) -> None:
        """生成Markdown格式报告"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# 🔐 密码算法测试报告\n\n")

            if "timestamp" in self.results:
                f.write(f"**测试时间:** {self.results['timestamp']}\n\n")

            if "summary" in self.results:
                summary = self.results["summary"]
                f.write("## 📊 测试汇总\n\n")
                f.write("| 指标 | 数值 |\n")
                f.write("|------|------|\n")
                f.write(f"| 测试算法数 | {summary.get('total_algorithms', 0)} |\n")
                f.write(f"| 总测试用例 | {summary.get('total_tests', 0)} |\n")
                f.write(f"| 总通过数 | {summary.get('total_passed', 0)} |\n")
                f.write(f"| 总失败数 | {summary.get('total_failed', 0)} |\n")
                f.write(f"| 总跳过数 | {summary.get('total_skipped', 0)} |\n")
                f.write(f"| 总体通过率 | {summary.get('overall_pass_rate', 0):.2%} |\n\n")

            f.write("## 🔍 各算法详细结果\n\n")

            if "algorithms" in self.results:
                for alg_name, alg_result in self.results["algorithms"].items():
                    status = "✅ 通过" if alg_result.get("success", False) else "❌ 失败"
                    f.write(f"### {alg_name}算法 {status}\n\n")

                    if alg_result.get("success") and "details" in alg_result:
                        details = alg_result["details"]
                        f.write("| 指标 | 数值 |\n")
                        f.write("|------|------|\n")
                        f.write(f"| 测试用例总数 | {details.get('total_tests', 0)} |\n")
                        f.write(f"| 通过数 | {details.get('passed', 0)} |\n")
                        f.write(f"| 失败数 | {details.get('failed', 0)} |\n")
                        f.write(f"| 跳过数 | {details.get('skipped', 0)} |\n")

                        total = details.get('total_tests', 0)
                        passed = details.get('passed', 0)
                        if total > 0:
                            rate = passed / total * 100
                            f.write(f"| 通过率 | {rate:.1f}% |\n")

                        f.write("\n")

                    if not alg_result.get("success"):
                        error = alg_result.get("error", "未知错误")
                        f.write(f"**错误信息:** {error[:200]}...\n\n")

            f.write("---\n")
            f.write(f"*报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")

        print(f"✅ Markdown报告已保存到: {output_file}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="测试报告生成器")
    parser.add_argument("-i", "--input", required=True, help="测试结果JSON文件路径")
    parser.add_argument("-o", "--output", help="输出目录")
    parser.add_argument("-f", "--format", choices=["txt", "html", "md", "all"],
                       default="all", help="报告格式 (默认: all)")

    args = parser.parse_args()

    # 初始化报告生成器
    generator = TestReportGenerator()

    # 加载结果文件
    if not generator.load_results(args.input):
        sys.exit(1)

    # 确定输出目录
    output_dir = args.output or os.path.dirname(args.input)
    os.makedirs(output_dir, exist_ok=True)

    # 生成报告
    base_name = os.path.splitext(os.path.basename(args.input))[0]

    if args.format in ["txt", "all"]:
        txt_file = os.path.join(output_dir, f"{base_name}_report.txt")
        generator.generate_text_report(txt_file)

    if args.format in ["html", "all"]:
        html_file = os.path.join(output_dir, f"{base_name}_report.html")
        generator.generate_html_report(html_file)

    if args.format in ["md", "all"]:
        md_file = os.path.join(output_dir, f"{base_name}_report.md")
        generator.generate_markdown_report(md_file)


if __name__ == "__main__":
    main()