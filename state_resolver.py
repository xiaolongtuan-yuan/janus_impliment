# -*- coding: utf-8 -*-
"""
@Time ： 2024/8/17 23:52
@Auth ： xiaolongtuan
@File ：state_resolver.py
"""
from enum import Enum

from sympy import symbols, And, Not, simplify

from policy_graph_error import InvalidPolicyGraphError


def decompose_states(states):
    """
    将多个逻辑状态表达式分解为互不相交的细粒度状态。

    参数：
    states (list): 包含逻辑状态表达式的列表。

    返回：
    list: 包含互不相交的状态的列表。
    """
    atomic_states = []

    # 构建细粒度状态：遍历每个状态，并排除其余状态
    for i, state in enumerate(states):
        intersection = state
        for j, other_state in enumerate(states):
            if i != j:
                intersection = And(intersection, Not(other_state))
        atomic_states.append(intersection.simplify())

    return atomic_states


class QUALITY_LEVAL(Enum):
    LOW = 1
    MIDIUM = 2
    HIGH = 3

def union_qos(Qos_set):
    # 每个qos以('min', 'b/w', 'high')这样的3元组表示，'min'与'max'对应，'b/w'可忽略，'high'与'low','midium'对应表示数值的范围，现在求出多个qos的交集
    min_value = QUALITY_LEVAL.HIGH
    max_value = QUALITY_LEVAL.LOW

    for qos_tuple in Qos_set:
        if qos_tuple[0] == 'min':
            min_value = min(QUALITY_LEVAL(qos_tuple[2]), min_value)
        elif qos_tuple[0] == 'max':
            max_value = max(QUALITY_LEVAL(qos_tuple[2]), max_value)
        else:
            raise InvalidPolicyGraphError('错误的Qos表达')
    if min_value > max_value:
        raise InvalidPolicyGraphError('Qos无法合并')
    return (('min', 'b/w', min_value.name), ('max', 'b/w', max_value.name))


if __name__ == '__main__':
    # 示例使用
    connection = symbols('connection')
    states = [
        connection >= 3,  # state_1
        connection < 3,  # state_2
        connection > 8  # state_3
    ]

    # 调用函数
    atomic_states = decompose_states(states)

    # 输出分解后的互不相交状态
    for i, state in enumerate(atomic_states, 1):
        print(f"Atomic State {i}: {state}")
