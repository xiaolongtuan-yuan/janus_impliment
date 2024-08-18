# -*- coding: utf-8 -*-
"""
@Time ： 2024/8/16 16:56
@Auth ： xiaolongtuan
@File ：policy_graph_error.py
"""
class InvalidPolicyGraphError(Exception):
    def __init__(self, message):
        super().__init__(message)

