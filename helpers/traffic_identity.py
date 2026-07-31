#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
流量用户标识识别工具 (纯 Python, 无 Java 依赖, 便于单元测试).

当用户未配置 user-identify 映射时, 自动从常见认证 headers 中提取用户标识.
"""


def auto_detect_user_identifier(headers_str):
    """
    当用户未配置 user-identify 映射时, 自动从常见认证 headers 中提取用户标识.
    按优先级依次查找: Cookie / X-Auth-Token / Authorization / X-Token / X-Session 等.
    返回 "auto:<header_name>:<value摘要>" 格式的临时标识, 后续可通过 refresh 刷新.
    """
    if not headers_str:
        return None

    # 常见认证 header 名称 (按优先级)
    auth_header_names = [
        "Cookie", "X-Auth-Token", "Authorization",
        "X-Token", "X-Session", "X-Api-Key",
        "Token", "Auth-Token",
    ]

    for header_name in auth_header_names:
        prefix = header_name + ":"
        for line in headers_str.split("\n"):
            line_stripped = line.strip()
            if line_stripped.lower().startswith(prefix.lower()):
                # 提取 value
                value = line_stripped[len(prefix):].strip()
                if not value:
                    continue
                # 截取摘要 (前 40 字符), 避免过长的标识符
                digest = value[:40]
                return "auto:{}:{}".format(header_name, digest)

    return None
