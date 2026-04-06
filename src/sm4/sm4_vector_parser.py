#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4测试向量通用解析模块
支持解析所有SM4模式的测试向量文件
"""

import re
import os
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class SM4VectorParser:
    """SM4测试向量解析器"""
    
    # 中文字段名映射到英文标准名
    FIELD_MAPPING = {
        '密钥': 'key',
        'key': 'key',
        'KEY': 'key',
        'Key': 'key',
        '初始向量': 'iv',
        'IV': 'iv',
        'iv': 'iv',
        '明文': 'plaintext',
        'plaintext': 'plaintext',
        'Plaintext': 'plaintext',
        '密文': 'ciphertext',
        'ciphertext': 'ciphertext',
        'Ciphertext': 'ciphertext',
        'tag': 'tag',
        'Tag': 'tag',
        '标签': 'tag',
        '附加数据': 'add',
        'add': 'add',
        'Add': 'add',
        'aad': 'add',
        'AAD': 'add',
        'tweak': 'tweak',
        'Tweak': 'tweak',
        '调整值': 'tweak',
        'TWEAK': 'tweak',
        'key2': 'key2',
        'Key2': 'key2',
        '第二密钥': 'key2',
        'KEY2': 'key2',
        '明文长度': 'plaintext_length',
        '密文长度': 'ciphertext_length',
        'plaintext_length': 'plaintext_length',
        'ciphertext_length': 'ciphertext_length',
        '明白': 'plaintext',  # 处理可能的类型错误
    }

    @staticmethod
    def extract_mode_from_filename(filename: str) -> str:
        """从文件名提取加密模式"""
        filename_upper = filename.upper().replace('.TXT', '')
        
        # 映射关系
        mode_keywords = {
            'ECB': 'ECB',
            'CBC': 'CBC',
            'CFB': 'CFB',
            'FB8': 'CFB',
            'FB128': 'CFB',
            'OFB': 'OFB',
            'CTR': 'CTR',
            'GCM': 'GCM',
            'HCTR': 'HCTR',
            'XTS': 'XTS',
            'BC': 'BC',  # 可能是Block Cipher
            'MAC': 'MAC',
            'OFBNLF': 'OFBNLF',
            'GB': 'XTS-GB',  # 中国标准XTS变种
        }
        
        for keyword, mode in mode_keywords.items():
            if keyword in filename_upper:
                # 特殊处理：如果同时包含CFB和FB8/FB128
                if mode == 'CFB':
                    if 'FB8' in filename_upper:
                        return 'CFB-FB8'
                    elif 'FB128' in filename_upper:
                        return 'CFB-FB128'
                    return 'CFB'
                return mode
        
        return 'UNKNOWN'

    @staticmethod
    def parse_field_value(raw_line: str) -> Tuple[str, Optional[str]]:
        """
        解析单行字段
        
        格式支持：
        - 密钥= AABBCCDD...
        - key(0x10 bytes)= AABBCCDD...
        - KEY = AABBCCDD...
        
        Returns:
            (field_name, hex_value) 或 (field_name, None) 如果解析失败
        """
        line = raw_line.strip()
        
        if not line or '=' not in line:
            return None, None
        
        # 分割键和值
        parts = line.split('=', 1)
        if len(parts) != 2:
            return None, None
        
        field_part = parts[0].strip()
        value_part = parts[1].strip()
        
        # 处理带有长度描述的字段，如"key(0x10 bytes)"
        # 使用正则表达式提取字段名
        match = re.match(r'([^(]+?)(?:\([^)]*\))?$', field_part)
        if not match:
            return None, None
        
        field_name = match.group(1).strip()
        
        # 标准化字段名
        standard_field = SM4VectorParser.FIELD_MAPPING.get(field_name, None)
        if standard_field is None:
            # 如果未找到直接匹配，尝试部分匹配
            field_lower = field_name.lower()
            for key, val in SM4VectorParser.FIELD_MAPPING.items():
                if key.lower() in field_lower or field_lower in key.lower():
                    standard_field = val
                    break
        
        if standard_field is None:
            return field_name, None  # 返回原始字段名，让调用者处理
        
        # 清理值：移除空格和可能的前缀
        hex_value = value_part.strip()
        
        # 如果值为空或不是有效十六进制，返回None
        if not hex_value:
            return standard_field, None
        
        # 验证是否是十六进制（允许空格）
        hex_clean = hex_value.replace(' ', '').replace('\t', '')
        if not re.match(r'^[0-9A-Fa-f]*$', hex_clean):
            # 可能包含其他内容，仍然返回
            pass
        
        return standard_field, hex_value

    @staticmethod
    def hex_to_bytes(hex_string: str) -> Optional[bytes]:
        """将十六进制字符串转换为字节"""
        try:
            # 移除空格和换行
            hex_clean = ''.join(hex_string.split()).upper()
            
            if not hex_clean:
                return None
            
            # 确保长度是偶数
            if len(hex_clean) % 2 != 0:
                hex_clean = '0' + hex_clean
            
            return bytes.fromhex(hex_clean)
        except ValueError:
            return None

    @staticmethod
    def parse_test_vector_block(block_lines: List[str]) -> Dict[str, any]:
        """
        解析单个测试向量块
        
        块由一组键值对组成，直到遇到空行或文件结束
        """
        vector = {}
        
        for line in block_lines:
            line = line.strip()
            
            if not line:
                continue
            
            field_name, hex_value = SM4VectorParser.parse_field_value(line)
            
            if field_name is None:
                continue
            
            if hex_value is None:
                # 解析失败，记录为错误字段
                vector[f'_failed_parse_{field_name}'] = line
                continue
            
            # 转换十六进制为字节
            field_bytes = SM4VectorParser.hex_to_bytes(hex_value)
            
            if field_bytes is None:
                vector[f'_failed_hex_{field_name}'] = hex_value
                continue
            
            # 存储为十六进制字符串（便于比对）和字节
            vector[field_name] = hex_value.replace(' ', '').upper()
            vector[f'{field_name}_bytes'] = field_bytes
        
        return vector if vector else None

    @staticmethod
    def parse_sm4_vector_file(file_path: str) -> List[Dict[str, any]]:
        """
        解析SM4测试向量文件
        
        Args:
            file_path: 测试向量文件路径
        
        Returns:
            List of test vectors, each as Dict with keys:
            - key: 密钥 (hex string)
            - iv: 初始向量 (hex string) 
            - plaintext: 明文 (hex string)
            - ciphertext: 密文 (hex string)
            - tag: 认证标签 (hex string, for AEAD modes)
            - add: 附加认证数据 (hex string, for AEAD modes)
            - tweak: 调整值 (hex string, for XTS mode)
            - mode: 加密模式 (从文件名推断)
            - _bytes_* : 对应的字节版本
            - _error: 如果解析失败
        """
        vectors = []
        
        try:
            # 尝试多种编码（优先GB2312，因为测试向量文件通常用此编码）
            content = None
            encodings = ['gb2312', 'gbk', 'gb18030', 'utf-8', 'iso-8859-1', 'latin1']
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except (UnicodeDecodeError, UnicodeEncodeError):
                    continue
            
            if content is None:
                return [{
                    'mode': SM4VectorParser.extract_mode_from_filename(os.path.basename(file_path)),
                    '_error': f'文件编码不支持'
                }]
            
            # 从文件名推断模式
            mode = SM4VectorParser.extract_mode_from_filename(os.path.basename(file_path))
            
            # 分割为行
            lines = content.split('\n')
            
            # 分组处理：相邻的非空行组成一个测试向量块
            current_block = []
            
            for line in lines:
                stripped = line.strip()
                
                if stripped:
                    current_block.append(line)
                else:
                    # 遇到空行，处理当前块
                    if current_block:
                        vector = SM4VectorParser.parse_test_vector_block(current_block)
                        if vector:
                            vector['mode'] = mode
                            vectors.append(vector)
                        current_block = []
            
            # 处理最后一个块
            if current_block:
                vector = SM4VectorParser.parse_test_vector_block(current_block)
                if vector:
                    vector['mode'] = mode
                    vectors.append(vector)
            
            # 如果没有解析到任何向量，返回错误
            if not vectors:
                return [{
                    'mode': mode,
                    '_error': '文件中没有找到有效的测试向量'
                }]
            
            return vectors
        
        except Exception as e:
            return [{
                'mode': SM4VectorParser.extract_mode_from_filename(os.path.basename(file_path)),
                '_error': f'文件处理失败: {str(e)}'
            }]

    @staticmethod
    def parse_all_sm4_vectors(vector_dir: str) -> Dict[str, List[Dict]]:
        """
        解析指定目录下所有SM4测试向量文件
        
        Args:
            vector_dir: 测试向量目录
        
        Returns:
            Dict mapping filename to list of test vectors
        """
        results = {}
        
        if not os.path.isdir(vector_dir):
            return {'_error': f'目录不存在: {vector_dir}'}
        
        # 查找所有.txt文件
        for filename in sorted(os.listdir(vector_dir)):
            if filename.upper().endswith('.TXT') and filename.upper().startswith('SM4'):
                file_path = os.path.join(vector_dir, filename)
                try:
                    vectors = SM4VectorParser.parse_sm4_vector_file(file_path)
                    results[filename] = vectors
                except Exception as e:
                    results[filename] = [{
                        'mode': SM4VectorParser.extract_mode_from_filename(filename),
                        '_error': f'解析异常: {str(e)}'
                    }]
        
        return results


# 便利函数
def parse_sm4_vector_file(file_path: str) -> List[Dict[str, any]]:
    """便利函数：解析单个SM4测试向量文件"""
    return SM4VectorParser.parse_sm4_vector_file(file_path)


def parse_all_sm4_vectors(vector_dir: str) -> Dict[str, List[Dict]]:
    """便利函数：解析目录下所有SM4测试向量文件"""
    return SM4VectorParser.parse_all_sm4_vectors(vector_dir)
