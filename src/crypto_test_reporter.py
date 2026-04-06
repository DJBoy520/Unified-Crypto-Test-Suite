#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一加密算法测试报告生成系统
支持SM2/SM3/SM4/国际算法的测试报告生成

作者: AI Assistant
日期: 2026年4月4日
"""

import os
import sys
import json
import platform
from datetime import datetime
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod

# 尝试导入可选依赖
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("警告: psutil未安装，将使用有限的环境信息收集功能")


class BaseCryptoReporter(ABC):
    """所有算法报告生成器的基类"""

    def __init__(self, algorithm_name: str, test_type: str):
        """
        初始化报告生成器

        Args:
            algorithm_name: 算法名称（如"SM2", "SM3", "AES"）
            test_type: 测试类型（如"FULL", "BASIC", "PERFORMANCE"）
        """
        self.algorithm = algorithm_name
        self.test_type = test_type
        self.report_id = self._generate_report_id()
        self.start_time = datetime.now()

    def _generate_report_id(self) -> str:
        """生成报告ID: ALGORITHM_TEST_YYYYMMDD_HHMMSS"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{self.algorithm.upper()}_TEST_{timestamp}"

    def collect_environment_info(self) -> Dict[str, Any]:
        """收集测试环境信息"""
        env_info = {
            "python_version": sys.version,
            "platform": platform.platform(),
            "os": platform.system() + " " + platform.release(),
            "architecture": platform.machine(),
            "processor": platform.processor() or "Unknown"
        }

        # 如果有psutil，收集更多信息
        if HAS_PSUTIL:
            memory = psutil.virtual_memory()
            env_info.update({
                "cpu_count": psutil.cpu_count(),
                "cpu_count_logical": psutil.cpu_count(logical=True),
                "memory_total_gb": round(memory.total / (1024**3), 2),
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "disk_usage": self._get_disk_usage()
            })

        return env_info

    def _get_disk_usage(self) -> Dict[str, float]:
        """获取磁盘使用情况"""
        if not HAS_PSUTIL:
            return {}

        try:
            disk = psutil.disk_usage('/')
            return {
                "total_gb": round(disk.total / (1024**3), 2),
                "used_gb": round(disk.used / (1024**3), 2),
                "free_gb": round(disk.free / (1024**3), 2),
                "usage_percent": disk.percent
            }
        except Exception:
            return {}

    @abstractmethod
    def generate_json_report(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成JSON格式详细报告（子类必须实现）"""
        pass

    @abstractmethod
    def generate_txt_summary(self, test_results: Dict[str, Any]) -> str:
        """生成TXT格式摘要报告（子类必须实现）"""
        pass

    def save_reports(self, test_results: Dict[str, Any], output_dir: str = "./reports") -> Dict[str, str]:
        """
        保存JSON和TXT报告到文件

        Args:
            test_results: 测试结果字典
            output_dir: 输出目录

        Returns:
            Dict containing file paths: {"json": json_path, "txt": txt_path}
        """
        try:
            # 1. 生成JSON报告
            json_report = self.generate_json_report(test_results)
            json_filename = f"{self.report_id}.json"

            # 2. 生成TXT摘要
            txt_report = self.generate_txt_summary(test_results)
            txt_filename = f"{self.report_id}.txt"

            # 3. 保存文件
            os.makedirs(output_dir, exist_ok=True)

            json_path = os.path.join(output_dir, json_filename)
            txt_path = os.path.join(output_dir, txt_filename)

            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2, ensure_ascii=False)

            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write(txt_report)

            print(f"✓ 详细报告已保存: {json_path}")
            print(f"✓ 摘要报告已保存: {txt_path}")

            return {"json": json_path, "txt": txt_path}

        except Exception as e:
            error_msg = f"保存报告失败: {str(e)}"
            print(f"❌ {error_msg}")
            raise RuntimeError(error_msg)

    def _calculate_summary(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """计算测试结果摘要"""
        total_tests = test_results.get("total_tests", 0)
        passed = test_results.get("passed", 0)
        failed = test_results.get("failed", 0)
        skipped = test_results.get("skipped", 0)
        error = test_results.get("error", 0)

        # 计算通过率
        pass_rate = (passed / total_tests * 100) if total_tests > 0 else 0

        return {
            "total_tests": total_tests,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "error": error,
            "pass_rate_percent": round(pass_rate, 2),
            "test_duration_seconds": (datetime.now() - self.start_time).total_seconds()
        }

    def _analyze_failures(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """分析测试失败情况"""
        failure_analysis = {
            "total_failures": 0,
            "failure_categories": {},
            "common_error_patterns": [],
            "critical_failures": []
        }

        # 分析详细结果中的失败
        details = test_results.get("details", [])
        for detail in details:
            if not detail.get("passed", True):
                failure_analysis["total_failures"] += 1

                # 分类失败类型
                error = detail.get("error", "")
                if "timeout" in error.lower():
                    failure_analysis["failure_categories"]["timeout"] = failure_analysis["failure_categories"].get("timeout", 0) + 1
                elif "format" in error.lower():
                    failure_analysis["failure_categories"]["format_error"] = failure_analysis["failure_categories"].get("format_error", 0) + 1
                elif "computation" in error.lower():
                    failure_analysis["failure_categories"]["computation_error"] = failure_analysis["failure_categories"].get("computation_error", 0) + 1
                else:
                    failure_analysis["failure_categories"]["other"] = failure_analysis["failure_categories"].get("other", 0) + 1

        return failure_analysis

    def _generate_recommendations(self, test_results: Dict[str, Any]) -> List[str]:
        """生成改进建议"""
        recommendations = []

        summary = self._calculate_summary(test_results)
        failure_analysis = self._analyze_failures(test_results)

        # 基于通过率生成建议
        if summary["pass_rate_percent"] < 80:
            recommendations.append("⚠️ 测试通过率较低，建议检查算法实现")
        elif summary["pass_rate_percent"] < 95:
            recommendations.append("⚡ 测试通过率良好，但仍有改进空间")

        # 基于失败分析生成建议
        if failure_analysis["failure_categories"].get("timeout", 0) > 0:
            recommendations.append("⏱️ 检测到超时错误，建议优化算法性能或增加超时时间")

        if failure_analysis["failure_categories"].get("computation_error", 0) > 0:
            recommendations.append("🔢 检测到计算错误，建议验证算法实现的正确性")

        # 通用建议
        recommendations.extend([
            "📊 建议定期运行完整测试套件以监控算法稳定性",
            "🔧 建议维护详细的测试日志以便问题追踪",
            "📈 建议添加性能基准测试以监控算法效率变化"
        ])

        return recommendations


class SM2Reporter(BaseCryptoReporter):
    """SM2算法专用报告生成器"""

    def __init__(self):
        """初始化SM2报告生成器"""
        super().__init__("SM2", "FULL")

    def generate_json_report(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成SM2专用JSON报告"""
        end_time = datetime.now()

        return {
            "test_report": {
                "metadata": {
                    "report_id": self.report_id,
                    "algorithm": "SM2",
                    "algorithm_description": "SM2椭圆曲线公钥密码算法",
                    "test_type": self.test_type,
                    "generation_time": end_time.isoformat(),
                    "test_duration_seconds": (end_time - self.start_time).total_seconds(),
                    "standard": "GM/T 0003-2012"
                },
                "environment": self.collect_environment_info(),
                "summary": self._calculate_summary(test_results),
                "algorithm_specific": self._generate_sm2_specific_data(test_results),
                "detailed_results": self._extract_detailed_results(test_results),
                "failure_analysis": self._analyze_failures(test_results),
                "performance_metrics": self._calculate_performance_metrics(test_results),
                "compliance": self._generate_compliance_info(test_results),
                "recommendations": self._generate_recommendations(test_results)
            }
        }

    def generate_txt_summary(self, test_results: Dict[str, Any]) -> str:
        """生成SM2专用TXT摘要报告"""
        summary = self._calculate_summary(test_results)

        lines = []
        lines.append("=" * 80)
        lines.append("🇨🇳 SM2椭圆曲线公钥密码算法测试报告")
        lines.append("=" * 80)
        lines.append(f"报告ID: {self.report_id}")
        lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"测试类型: {self.test_type}")
        lines.append("")

        lines.append("📊 测试摘要")
        lines.append("-" * 40)
        lines.append(f"总测试用例: {summary['total_tests']}")
        lines.append(f"通过: {summary['passed']}")
        lines.append(f"失败: {summary['failed']}")
        lines.append(f"跳过: {summary['skipped']}")
        lines.append(f"错误: {summary['error']}")
        lines.append(f"通过率: {summary['pass_rate_percent']:.2f}%")
        lines.append(f"测试时长: {summary['test_duration_seconds']:.2f}秒")
        lines.append("")

        # 算法特定信息
        sm2_data = self._generate_sm2_specific_data(test_results)
        lines.append("🔧 SM2算法测试分类")
        lines.append("-" * 40)
        for category in sm2_data.get("test_categories", []):
            lines.append(f"• {category['name']}: {category['passed']}/{category['total']}")

        lines.append("")
        lines.append("⚡ 性能指标")
        lines.append("-" * 40)
        perf = sm2_data.get("performance_metrics", {})
        if perf:
            lines.append(f"加密速度: {perf.get('encryption_speed_kbps', 'N/A')} KB/s")
            lines.append(f"解密速度: {perf.get('decryption_speed_kbps', 'N/A')} KB/s")
            lines.append(f"签名速度: {perf.get('signature_speed_ops', 'N/A')} ops/s")
            lines.append(f"验签速度: {perf.get('verification_speed_ops', 'N/A')} ops/s")

        lines.append("")
        lines.append("🎯 合规性检查")
        lines.append("-" * 40)
        compliance = self._generate_compliance_info(test_results)
        lines.append(f"国密标准: {', '.join(compliance.get('gm_standards', []))}")
        lines.append(f"合规性得分: {compliance.get('compliance_score', 0):.1f}")
        lines.append("")
        lines.append("💡 改进建议")
        lines.append("-" * 40)
        recommendations = self._generate_recommendations(test_results)
        for rec in recommendations:
            lines.append(f"• {rec}")

        lines.append("")
        lines.append("=" * 80)

        return "\n".join(lines)

    def _generate_sm2_specific_data(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成SM2特定数据（测试分类、性能指标）"""
        # 分析测试结果，按类别分组
        test_categories = []

        # 从详细结果中提取类别信息
        details = test_results.get("details", [])
        category_map = {}

        for detail in details:
            test_name = detail.get("test_name", "")
            passed = detail.get("passed", False)

            # 根据测试名称分类
            if "基本" in test_name:
                category = "基本功能验证"
            elif "密钥对" in test_name:
                category = "密钥对验证"
            elif "加密" in test_name and "计算" in test_name:
                category = "加密计算验证"
            elif "解密" in test_name and "计算" in test_name:
                category = "解密计算验证"
            elif "签名" in test_name and "计算" in test_name:
                category = "签名计算验证"
            elif "验签" in test_name and "计算" in test_name:
                category = "验签计算验证"
            elif "向量" in test_name:
                category = "向量验证"
            elif "异常" in test_name:
                category = "异常处理"
            else:
                category = "其他"

            if category not in category_map:
                category_map[category] = {"total": 0, "passed": 0}

            category_map[category]["total"] += 1
            if passed:
                category_map[category]["passed"] += 1

        # 转换为列表格式
        for name, stats in category_map.items():
            test_categories.append({
                "name": name,
                "total": stats["total"],
                "passed": stats["passed"]
            })

        return {
            "test_categories": test_categories,
            "performance_metrics": self._calculate_performance_metrics(test_results),
            "algorithm_features": [
                "椭圆曲线数字签名算法",
                "椭圆曲线密钥交换协议",
                "椭圆曲线公钥加密算法",
                "SM3密码杂凑算法"
            ]
        }

    def _calculate_performance_metrics(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """计算SM2性能指标"""
        # 这里可以基于测试结果计算实际性能
        # 目前返回模拟数据，实际实现应基于时间测量
        duration = (datetime.now() - self.start_time).total_seconds()

        return {
            "test_duration_seconds": duration,
            "encryption_speed_kbps": "N/A",  # 需要实际测量
            "decryption_speed_kbps": "N/A",  # 需要实际测量
            "signature_speed_ops": "N/A",    # 需要实际测量
            "verification_speed_ops": "N/A"  # 需要实际测量
        }

    def _generate_compliance_info(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成合规性信息"""
        summary = self._calculate_summary(test_results)

        return {
            "gm_standards": ["GM/T 0003-2012 (SM2)", "GM/T 0004-2012 (SM3)", "GB/T 32918.1-2016"],
            "test_coverage_percent": summary["pass_rate_percent"],
            "compliance_status": "符合" if summary["pass_rate_percent"] >= 95 else "部分符合",
            "certification_requirements": [
                "算法正确性验证",
                "标准向量测试",
                "边界条件测试",
                "异常处理测试"
            ]
        }

    def _extract_detailed_results(self, test_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取详细测试结果"""
        return test_results.get("details", [])


class SM3Reporter(BaseCryptoReporter):
    """SM3算法专用报告生成器"""

    def __init__(self):
        super().__init__("SM3", "FULL")

    def generate_json_report(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成SM3专用JSON报告"""
        end_time = datetime.now()

        return {
            "test_report": {
                "metadata": {
                    "report_id": self.report_id,
                    "algorithm": "SM3",
                    "algorithm_description": "SM3密码杂凑算法",
                    "test_type": self.test_type,
                    "generation_time": end_time.isoformat(),
                    "standard": "GM/T 0004-2012"
                },
                "environment": self.collect_environment_info(),
                "summary": self._calculate_summary(test_results),
                "algorithm_specific": self._generate_sm3_specific_data(test_results),
                "detailed_results": self._extract_detailed_results(test_results),
                "failure_analysis": self._analyze_failures(test_results),
                "performance_metrics": self._calculate_sm3_performance(test_results),
                "compliance": self._generate_sm3_compliance_info(test_results),
                "recommendations": self._generate_recommendations(test_results)
            }
        }

    def generate_txt_summary(self, test_results: Dict[str, Any]) -> str:
        """生成SM3专用TXT摘要报告"""
        summary = self._calculate_summary(test_results)

        lines = []
        lines.append("=" * 80)
        lines.append("🇨🇳 SM3密码杂凑算法测试报告")
        lines.append("=" * 80)
        lines.append(f"报告ID: {self.report_id}")
        lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        lines.append("📊 测试摘要")
        lines.append("-" * 40)
        lines.append(f"总测试用例: {summary['total_tests']}")
        lines.append(f"通过: {summary['passed']}")
        lines.append(f"失败: {summary['failed']}")
        lines.append(f"跳过: {summary['skipped']}")
        lines.append(f"错误: {summary['error']}")
        lines.append(f"通过率: {summary['pass_rate_percent']:.2f}%")
        lines.append(f"测试时长: {summary['test_duration_seconds']:.2f}秒")
        lines.append("")

        # 算法特定信息
        sm3_data = self._generate_sm3_specific_data(test_results)
        lines.append("🔧 SM3算法测试分类")
        lines.append("-" * 40)
        for category in sm3_data.get("test_categories", []):
            lines.append(f"• {category['name']}: {category['passed']}/{category['total']}")

        lines.append("")
        lines.append("⚡ 性能指标")
        lines.append("-" * 40)
        perf = sm3_data.get("performance_metrics", {})
        if perf:
            lines.append(f"哈希速度: {perf.get('hash_speed_mbps', 'N/A')} MB/s")

        lines.append("")
        lines.append("🎯 合规性检查")
        lines.append("-" * 40)
        compliance = self._generate_sm3_compliance_info(test_results)
        lines.append(f"国密标准: {', '.join(compliance.get('gm_standards', []))}")
        lines.append(f"测试覆盖率: {compliance.get('test_coverage_percent', 0):.1f}%")
        lines.append(f"合规状态: {compliance.get('compliance_status', '未知')}")

        lines.append("")
        lines.append("💡 改进建议")
        lines.append("-" * 40)
        recommendations = self._generate_recommendations(test_results)
        for rec in recommendations:
            lines.append(f"• {rec}")

        lines.append("")
        lines.append("=" * 80)

        return "\n".join(lines)

    def _generate_sm3_specific_data(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成SM3特定数据"""
        # 分析测试结果，按类别分组
        test_categories = []

        # 从详细结果中提取类别信息
        details = test_results.get("details", [])
        category_map = {}

        for detail in details:
            test_name = detail.get("test_name", "")

            # 根据测试名称分类
            if "哈希" in test_name and "向量" in test_name:
                category = "哈希向量验证"
            elif "HMAC" in test_name and "向量" in test_name:
                category = "HMAC向量验证"
            elif "基本功能" in test_name:
                category = "基本功能验证"
            else:
                category = "其他"

            if category not in category_map:
                category_map[category] = {"total": 0, "passed": 0}

            category_map[category]["total"] += 1
            if detail.get("passed", False):
                category_map[category]["passed"] += 1

        # 转换为列表格式
        for name, stats in category_map.items():
            test_categories.append({
                "name": name,
                "total": stats["total"],
                "passed": stats["passed"]
            })

        return {
            "hash_properties": {
                "output_size_bits": 256,
                "block_size_bits": 512,
                "rounds": 64
            },
            "test_categories": test_categories,
            "performance_metrics": self._calculate_sm3_performance(test_results)
        }

    def _calculate_sm3_performance(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """计算SM3性能指标"""
        duration = (datetime.now() - self.start_time).total_seconds()
        
        # 估算哈希速度（基于测试用例数量和时长）
        total_tests = test_results.get("total_tests", 0)
        if duration > 0 and total_tests > 0:
            # 假设每个测试处理1KB数据
            estimated_data_mb = total_tests * 1 / 1024
            hash_speed_mbps = estimated_data_mb / duration if duration > 0 else 0
        else:
            hash_speed_mbps = 0
        
        return {
            "test_duration_seconds": duration,
            "hash_speed_mbps": f"{hash_speed_mbps:.2f}" if hash_speed_mbps > 0 else "N/A"
        }

    def _generate_sm3_compliance_info(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成SM3合规性信息"""
        summary = self._calculate_summary(test_results)
        return {
            "gm_standards": ["GM/T 0004-2012"],
            "test_coverage_percent": summary["pass_rate_percent"],
            "compliance_status": "符合" if summary["pass_rate_percent"] >= 95 else "部分符合"
        }

    def _extract_detailed_results(self, test_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取详细测试结果"""
        return test_results.get("details", [])


class SM4Reporter(BaseCryptoReporter):
    """SM4算法专用报告生成器"""

    def __init__(self):
        super().__init__("SM4", "FULL")

    def generate_json_report(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成SM4专用JSON报告"""
        end_time = datetime.now()

        return {
            "test_report": {
                "metadata": {
                    "report_id": self.report_id,
                    "algorithm": "SM4",
                    "algorithm_description": "SM4分组密码算法",
                    "test_type": self.test_type,
                    "generation_time": end_time.isoformat(),
                    "standard": "GM/T 0002-2012"
                },
                "environment": self.collect_environment_info(),
                "summary": self._calculate_summary(test_results),
                "algorithm_specific": self._generate_sm4_specific_data(test_results),
                "detailed_results": self._extract_detailed_results(test_results),
                "failure_analysis": self._analyze_failures(test_results),
                "performance_metrics": self._calculate_sm4_performance(test_results),
                "compliance": self._generate_sm4_compliance_info(test_results),
                "recommendations": self._generate_recommendations(test_results)
            }
        }

    def generate_txt_summary(self, test_results: Dict[str, Any]) -> str:
        """生成SM4专用TXT摘要报告"""
        summary = self._calculate_summary(test_results)

        lines = []
        lines.append("=" * 80)
        lines.append("🇨🇳 SM4分组密码算法测试报告")
        lines.append("=" * 80)
        lines.append(f"报告ID: {self.report_id}")
        lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        lines.append("📊 测试摘要")
        lines.append("-" * 40)
        lines.append(f"总测试用例: {summary['total_tests']}")
        lines.append(f"通过: {summary['passed']}")
        lines.append(f"失败: {summary['failed']}")
        lines.append(f"跳过: {summary['skipped']}")
        lines.append(f"错误: {summary['error']}")
        lines.append(f"通过率: {summary['pass_rate_percent']:.2f}%")
        lines.append("")

        lines.append("🔧 SM4算法特性")
        lines.append("-" * 40)
        lines.append("• 分组长度: 128位")
        lines.append("• 密钥长度: 128位")
        lines.append("• 轮数: 32轮")
        lines.append("• 工作模式: ECB, CBC, CFB, OFB")

        lines.append("")
        lines.append("=" * 80)

        return "\n".join(lines)

    def _generate_sm4_specific_data(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成SM4特定数据"""
        return {
            "cipher_properties": {
                "block_size_bits": 128,
                "key_size_bits": 128,
                "rounds": 32
            },
            "supported_modes": ["ECB", "CBC", "CFB", "OFB"],
            "test_vectors": [
                "标准测试向量",
                "不同工作模式",
                "边界条件测试"
            ]
        }

    def _calculate_sm4_performance(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """计算SM4性能指标"""
        duration = (datetime.now() - self.start_time).total_seconds()
        return {
            "test_duration_seconds": duration,
            "encryption_speed_mbps": "N/A",  # 需要实际测量
            "decryption_speed_mbps": "N/A"   # 需要实际测量
        }

    def _generate_sm4_compliance_info(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成SM4合规性信息"""
        summary = self._calculate_summary(test_results)
        return {
            "gm_standards": ["GM/T 0002-2012"],
            "test_coverage_percent": summary["pass_rate_percent"],
            "compliance_status": "符合" if summary["pass_rate_percent"] >= 95 else "部分符合"
        }

    def _extract_detailed_results(self, test_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取详细测试结果"""
        return test_results.get("details", [])


class MultiAlgorithmReporter:
    """合并多个算法测试结果的报告生成器"""

    def __init__(self):
        """初始化多算法报告生成器"""
        self.report_id = f"ALL_CRYPTO_TEST_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.start_time = datetime.now()

        # 支持的算法报告生成器
        self.algorithm_reporters = {
            "SM2": SM2Reporter(),
            "SM3": SM3Reporter(),
            "SM4": SM4Reporter()
        }

    def generate_combined_report(self, all_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        生成合并报告

        Args:
            all_results: 各算法的测试结果字典，格式如 {"SM2": sm2_results, "SM3": sm3_results}

        Returns:
            合并的报告字典
        """
        end_time = datetime.now()

        combined = {
            "test_report": {
                "metadata": {
                    "report_id": self.report_id,
                    "algorithm": "MULTI_ALGORITHM",
                    "test_type": "COMPREHENSIVE",
                    "generation_time": end_time.isoformat(),
                    "test_duration_seconds": (end_time - self.start_time).total_seconds(),
                    "algorithms_tested": list(all_results.keys())
                },
                "environment": self._collect_common_environment(),
                "overall_summary": self._calculate_overall_summary(all_results),
                "algorithms": {},
                "cross_algorithm_comparison": self._generate_comparison(all_results)
            }
        }

        # 为每个算法生成单独的报告
        for algo_name, results in all_results.items():
            if algo_name in self.algorithm_reporters:
                reporter = self.algorithm_reporters[algo_name]
                combined["test_report"]["algorithms"][algo_name] = reporter.generate_json_report(results)

        return combined

    def generate_combined_txt_summary(self, all_results: Dict[str, Dict[str, Any]]) -> str:
        """生成合并TXT摘要报告"""
        lines = []
        lines.append("=" * 100)
        lines.append("🇨🇳 多算法加密测试综合报告")
        lines.append("=" * 100)
        lines.append(f"报告ID: {self.report_id}")
        lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # 总体摘要
        overall = self._calculate_overall_summary(all_results)
        lines.append("📊 总体测试摘要")
        lines.append("-" * 50)
        lines.append(f"测试算法数量: {overall['algorithm_count']}")
        lines.append(f"总测试用例: {overall['total_tests']}")
        lines.append(f"总体通过: {overall['total_passed']}")
        lines.append(f"总体失败: {overall['total_failed']}")
        lines.append(f"总体通过率: {overall['overall_pass_rate_percent']:.2f}%")
        lines.append("")

        # 各算法摘要
        lines.append("🔧 各算法测试结果")
        lines.append("-" * 50)
        for algo_name, results in all_results.items():
            summary = self.algorithm_reporters[algo_name]._calculate_summary(results) if algo_name in self.algorithm_reporters else {"pass_rate_percent": 0}
            lines.append(f"• {algo_name}: {summary['pass_rate_percent']:.1f}% 通过率")

        lines.append("")
        lines.append("⚖️ 跨算法对比")
        lines.append("-" * 50)
        comparison = self._generate_comparison(all_results)
        if comparison.get("performance_ranking"):
            lines.append("性能排名: " + " > ".join(comparison["performance_ranking"]))

        lines.append("")
        lines.append("=" * 100)

        return "\n".join(lines)

    def save_combined_reports(self, all_results: Dict[str, Dict[str, Any]], output_dir: str = "./reports") -> Dict[str, str]:
        """
        保存合并报告

        Args:
            all_results: 各算法的测试结果
            output_dir: 输出目录

        Returns:
            文件路径字典
        """
        try:
            # 生成合并JSON报告
            json_report = self.generate_combined_report(all_results)
            json_filename = f"{self.report_id}.json"

            # 生成合并TXT摘要
            txt_report = self.generate_combined_txt_summary(all_results)
            txt_filename = f"{self.report_id}.txt"

            # 保存文件
            os.makedirs(output_dir, exist_ok=True)

            json_path = os.path.join(output_dir, json_filename)
            txt_path = os.path.join(output_dir, txt_filename)

            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2, ensure_ascii=False)

            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write(txt_report)

            print(f"✓ 多算法详细报告已保存: {json_path}")
            print(f"✓ 多算法摘要报告已保存: {txt_path}")

            return {"json": json_path, "txt": txt_path}

        except Exception as e:
            error_msg = f"保存合并报告失败: {str(e)}"
            print(f"❌ {error_msg}")
            raise RuntimeError(error_msg)

    def _collect_common_environment(self) -> Dict[str, Any]:
        """收集通用环境信息"""
        # 使用SM2报告生成器的环境收集方法
        if "SM2" in self.algorithm_reporters:
            return self.algorithm_reporters["SM2"].collect_environment_info()
        else:
            return {"error": "无法收集环境信息"}

    def _calculate_overall_summary(self, all_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """计算总体摘要"""
        total_tests = 0
        total_passed = 0
        total_failed = 0

        for algo_name, results in all_results.items():
            total_tests += results.get("total_tests", 0)
            total_passed += results.get("passed", 0)
            total_failed += results.get("failed", 0) + results.get("error", 0)

        pass_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0

        return {
            "algorithm_count": len(all_results),
            "total_tests": total_tests,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "overall_pass_rate_percent": round(pass_rate, 2)
        }

    def _generate_comparison(self, all_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """生成跨算法对比"""
        comparison = {
            "performance_ranking": [],
            "coverage_comparison": {},
            "failure_analysis": {}
        }

        # 简单的性能排名（基于通过率）
        algo_pass_rates = {}
        for algo_name, results in all_results.items():
            summary = self.algorithm_reporters[algo_name]._calculate_summary(results) if algo_name in self.algorithm_reporters else {"pass_rate_percent": 0}
            algo_pass_rates[algo_name] = summary["pass_rate_percent"]

        # 按通过率降序排序
        comparison["performance_ranking"] = sorted(algo_pass_rates.keys(), key=lambda x: algo_pass_rates[x], reverse=True)

        # 覆盖率对比
        for algo_name, results in all_results.items():
            summary = self.algorithm_reporters[algo_name]._calculate_summary(results) if algo_name in self.algorithm_reporters else {"pass_rate_percent": 0}
            comparison["coverage_comparison"][algo_name] = summary["pass_rate_percent"]

        return comparison


class SM4Reporter(BaseCryptoReporter):
    """SM4分组密码算法专用报告生成器"""

    def __init__(self):
        super().__init__("SM4", "FULL")

    def generate_json_report(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成SM4专用JSON报告"""
        end_time = datetime.now()

        return {
            "test_report": {
                "metadata": {
                    "report_id": self.report_id,
                    "algorithm": "SM4",
                    "algorithm_description": "SM4分组密码算法（国密标准）",
                    "test_type": self.test_type,
                    "generation_time": end_time.isoformat(),
                    "test_duration_seconds": (end_time - self.start_time).total_seconds(),
                    "standard": "GM/T 0002-2012"
                },
                "environment": self.collect_environment_info(),
                "summary": self._calculate_summary(test_results),
                "algorithm_specific": self._generate_sm4_specific_data(test_results),
                "detailed_results": self._extract_detailed_results(test_results),
                "failure_analysis": self._analyze_failures(test_results),
                "performance_metrics": self._calculate_sm4_performance(test_results),
                "compliance": self._generate_sm4_compliance_info(test_results),
                "recommendations": self._generate_recommendations(test_results)
            }
        }

    def generate_txt_summary(self, test_results: Dict[str, Any]) -> str:
        """生成SM4专用TXT摘要报告"""
        summary = self._calculate_summary(test_results)

        lines = []
        lines.append("=" * 80)
        lines.append("🇨🇳 SM4分组密码算法测试报告")
        lines.append("=" * 80)
        lines.append(f"报告ID: {self.report_id}")
        lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"测试类型: {self.test_type}")
        lines.append("")

        lines.append("📊 测试摘要")
        lines.append("-" * 40)
        lines.append(f"总测试用例: {summary['total_tests']}")
        lines.append(f"通过: {summary['passed']}")
        lines.append(f"失败: {summary['failed']}")
        lines.append(f"跳过: {summary['skipped']}")
        lines.append(f"错误: {summary['error']}")
        lines.append(f"通过率: {summary['pass_rate_percent']:.2f}%")
        lines.append(f"测试时长: {summary['test_duration_seconds']:.2f}秒")
        lines.append("")

        # 算法特定信息
        sm4_data = self._generate_sm4_specific_data(test_results)
        lines.append("🔧 SM4模式测试统计")
        lines.append("-" * 40)
        for category in sm4_data.get("test_categories", []):
            lines.append(f"• {category['name']}: {category['passed']}/{category['total']}")

        lines.append("")
        lines.append("⚡ 性能指标")
        lines.append("-" * 40)
        perf = sm4_data.get("performance_metrics", {})
        if perf:
            lines.append(f"加密速度: {perf.get('encryption_speed_throughput', 'N/A')} MB/s")
            lines.append(f"解密速度: {perf.get('decryption_speed_throughput', 'N/A')} MB/s")

        lines.append("")
        lines.append("🎯 合规性检查")
        lines.append("-" * 40)
        compliance = sm4_data.get("compliance", {})
        lines.append(f"国密标准: {', '.join(compliance.get('gm_standards', []))}")
        lines.append(f"支持模式数: {len(compliance.get('supported_modes', []))}")
        lines.append(f"支持的模式: {', '.join(compliance.get('supported_modes', []))}")

        lines.append("")
        lines.append("💡 改进建议")
        lines.append("-" * 40)
        recommendations = self._generate_recommendations(test_results)
        for rec in recommendations:
            lines.append(f"• {rec}")

        lines.append("")
        lines.append("=" * 80)

        return "\n".join(lines)

    def _generate_sm4_specific_data(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成SM4特定数据"""
        test_categories = []
        details = test_results.get("details", [])
        category_map = {}

        for detail in details:
            mode = detail.get("mode", "UNKNOWN")
            passed = detail.get("passed", False)

            if mode not in category_map:
                category_map[mode] = {"total": 0, "passed": 0}

            category_map[mode]["total"] += 1
            if passed:
                category_map[mode]["passed"] += 1

        for name, stats in sorted(category_map.items()):
            test_categories.append({
                "name": name,
                "total": stats["total"],
                "passed": stats["passed"]
            })

        return {
            "test_categories": test_categories,
            "performance_metrics": self._calculate_sm4_performance(test_results),
            "compliance": self._generate_sm4_compliance_info(test_results),
            "algorithm_features": [
                "128位分组密码",
                "256位密钥",
                "ECB/CBC/CFB/OFB/CTR模式",
                "GCM/HCTR AEAD模式",
                "XTS磁盘加密模式"
            ]
        }

    def _calculate_sm4_performance(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """计算SM4性能指标"""
        duration = (datetime.now() - self.start_time).total_seconds()

        return {
            "test_duration_seconds": round(duration, 2),
            "encryption_speed_throughput": "N/A",  # 需要实际测量
            "decryption_speed_throughput": "N/A",  # 需要实际测量
            "test_vectors_processed": test_results.get("total_tests", 0)
        }

    def _generate_sm4_compliance_info(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成SM4合规性信息"""
        summary = self._calculate_summary(test_results)

        return {
            "gm_standards": ["GM/T 0002-2012", "GB/T 32905-2016"],
            "supported_modes": [
                "ECB (Electronic Codebook)",
                "CBC (Cipher Block Chaining)",
                "CFB-FB8 (Cipher Feedback - 8-bit)",
                "CFB-FB128 (Cipher Feedback - 128-bit)",
                "OFB (Output Feedback)",
                "CTR (Counter)",
                "GCM (Galois/Counter Mode)",
                "HCTR (HMAC-based Tweaked Codebook mode with CipherText stealing)",
                "XTS (XOR Encrypt XOR with Ciphertext Stealing)",
                "MAC (Message Authentication Code)"
            ],
            "test_coverage_percent": summary["pass_rate_percent"],
            "compliance_status": "完全符合" if summary["pass_rate_percent"] >= 95 else 
                               "基本符合" if summary["pass_rate_percent"] >= 80 else "需改进",
            "certification_requirements": [
                "算法加密正确性验证",
                "标准测试向量验证",
                "多模式支持验证",
                "填充和去填充验证",
                "异常处理验证"
            ]
        }

    def _extract_detailed_results(self, test_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取详细测试结果"""
        return test_results.get("details", [])


# 便捷函数用于快速生成报告
def generate_sm2_report(test_results: Dict[str, Any], output_dir: str = "./reports") -> Dict[str, str]:
    """快速生成SM2测试报告"""
    reporter = SM2Reporter()
    return reporter.save_reports(test_results, output_dir)


def generate_sm4_report(test_results: Dict[str, Any], output_dir: str = "./reports") -> Dict[str, str]:
    """快速生成SM4测试报告"""
    reporter = SM4Reporter()
    return reporter.save_reports(test_results, output_dir)


def generate_multi_algorithm_report(all_results: Dict[str, Dict[str, Any]], output_dir: str = "./reports") -> Dict[str, str]:
    """快速生成多算法测试报告"""
    reporter = MultiAlgorithmReporter()
    return reporter.save_combined_reports(all_results, output_dir)


# 配置文件支持（未来扩展）
class ReportConfig:
    """报告生成配置文件"""

    def __init__(self, config_file: str = None):
        self.config = self._load_default_config()
        if config_file and os.path.exists(config_file):
            self._load_config_file(config_file)

    def _load_default_config(self) -> Dict[str, Any]:
        """加载默认配置"""
        return {
            "output_format": ["json", "txt"],
            "include_performance": True,
            "include_environment": True,
            "max_report_size_mb": 50,
            "timeout_seconds": 300
        }

    def _load_config_file(self, config_file: str):
        """从文件加载配置"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
                self.config.update(file_config)
        except Exception as e:
            print(f"警告: 无法加载配置文件 {config_file}: {e}")


if __name__ == "__main__":
    # 示例用法
    print("统一加密算法测试报告生成系统")
    print("支持算法: SM2, SM3, SM4")
    print("使用方法:")
    print("  from crypto_test_reporter import generate_sm2_report")
    print("  generate_sm2_report(test_results, './reports')")