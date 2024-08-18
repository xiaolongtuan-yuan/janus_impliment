# -*- coding: utf-8 -*-
"""
@Time ： 2024/7/26 11:16
@Auth ： xiaolongtuan
@File ：policy_graph_model.py
"""
import copy
from collections import defaultdict
from enum import Enum
import networkx as nx
from sympy import Implies

from colections_cul import split_into_disjoint_sets
from label_namespace import label_namespace_define, tree_to_dnf, dnf_mapping_2_set
from policy_graph_error import InvalidPolicyGraphError
from state_resolver import decompose_states, union_qos
from topological_sort import topological_sort


class NetworkFunctionBlock(Enum):
    FIREWALL = 1  # 防火墙
    LOAD_BALANCER = 2  # 负载均衡
    VPN = 3  # VPN
    IDS = 4  # 入侵检测系统
    IPS = 5  # 入侵防御系统
    DPI = 6  # 深度包检测
    WAF = 7  # Web Application Firewall
    ROUTER = 8  # 包转发


class Flow:
    src_ip: int
    dst_ip: int
    protocol: str
    dst_port: int

    def __init__(self, src_ip, dst_ip, protocol, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.dst_port = dst_port


class NodeType(Enum):
    '''

    '''
    fnb = 1
    group = 2


class Node:
    type: NodeType

    def __init__(self, label):
        self.label


class NFBNode(Node):  # 中间盒，用优先级匹配操作规则表示
    def __init__(self, nf: NetworkFunctionBlock, match: {}, action: {}, priority=1, qos={}):
        super(nf.name)
        self.qos = qos
        self.type = NodeType.fnb

        self.priority = priority  # 优先级
        self.action = action  # 动作，转发，修改，丢弃
        self.match = match  # 匹配条件

    def is_modify(self):
        if self.action['aciton_type'] in [ActionType.modify]:
            return True
        return False

    def get_output_flow(self):
        if self.action['aciton_type'] in [ActionType.modify]:
            for key, value in self.action['content']:
                self.match[key] = value
        return self.match

    def get_input_flow(self):
        return self.match


# 判断后者是否会捕获前者flow，用于识别依赖
def is_overlap(output_flow, match2):
    for key, value in match2.items():
        if output_flow[key] != value:
            return False
    return True


class ActionType(Enum):
    forward = 1
    drop = 2
    accept = 3
    modify = 4
    logging = 5
    rate_limit = 6
    mirror = 7
    encryption = 8
    dncryption = 9


class GroupNode(Node):  # EPG
    def __init__(self, label, ):
        super(label)
        self.type = NodeType.group


class DiEdge:
    src: str
    dst: str
    attr: {}

    def __init__(self, src_label, dst_label, condition: str, attr={}):
        # 现在attr只设定带宽，且范围为low (< 100 Mbps),medium (> 100 Mbps and < 500 Mbps) & high (> 500 Mbps)
        # condition 表示条件策略，其被区分为动态策略和临时策略，这里是字符串形式如：filed_connections > 2
        self.src = src_label
        self.dst = dst_label
        self.attr = attr  # attr['b/w'] = ('min',high)
        self.condition = condition

    def check_node(self, label):
        if self.src == label or self.dst == label:
            return True
        return False


class Policy:
    '''
    1. 允许的网络端点
    2. 每次通信所需的任何服务功能链遍历
    3. 每个策略图必须严格限制
    '''

    def __init__(self, state_NFs_map: set(tuple), src_EPG: GroupNode, dst_EPG: GroupNode):
        self.state_NFs_map = state_NFs_map
        # 列表顺序代表NF顺序，以及Qos需求，都是放在state（逻辑表达式，提前定义Symbol类变量）下的，
        # 这里的tuple第一个值为NFs(list(NFBNode))， 第二个为Qos
        self.src_EPG = src_EPG
        self.dst_EPG = dst_EPG


class JanusPolicyModel:
    '''
    处理多个策略图冲突模型
    '''

    def __init__(self, label_trees_edges, label_mapping_pairs):
        self.policys = []
        self.label_namespace = label_namespace_define(label_trees=label_trees_edges)
        self.EPGs = set()
        self.EPGs_policy_map = defaultdict(list)
        self.label_mapping_pairs = label_mapping_pairs
        self.label_trees_edges = label_trees_edges

    def add_policy(self, p: Policy):
        self.policys.append(p)

        self.EPGs.add(p.src_EPG.label)
        self.EPGs.add(p.dst_EPG.label)

        self.EPGs_policy_map[p.src_EPG.label].append(p)
        self.EPGs_policy_map[p.dst_EPG.label].append(p)  # 源目的地节点都映射到该policy

    def graph_normalization(self):
        '''
        将所有策略拆分为最小单位graph
        :return:
        '''
        self.label_dfn = tree_to_dnf(edges=self.label_trees_edges, label_mapping_pairs=self.label_mapping_pairs)
        # 将EPG拆分为全局不相关的
        EPGs_dfn_mapping = {}
        for EPG in self.EPGs:
            EPGs_dfn_mapping[EPG] = self.label_dfn[EPG]

        # 将当前EPGs转换为dnf
        label_set_mapping, leaf_sets = dnf_mapping_2_set(EPGs_dfn_mapping)

        # 将当前EPGs拆分为完全互斥
        normalized_EPGs = split_into_disjoint_sets(leaf_sets)

        # 复制、合并 组合约束
        src_dst_policy_map = defaultdict(defaultdict(list))
        for p in self.policys:
            l_EPGs_srcs = []
            l_EPGs_dsts = []
            for little_EPGs in normalized_EPGs:
                if little_EPGs.issubset(label_set_mapping[p.src_EPG.label]):
                    l_EPGs_srcs.append(little_EPGs)

                elif little_EPGs.issubset(label_set_mapping[p.dst_EPG.label]):
                    l_EPGs_dsts.append(little_EPGs)

            for l_EPGs_src in l_EPGs_srcs:
                for l_EPGs_dst in l_EPGs_dsts:
                    # n*m个源目标对
                    for state, NFs_Qos in p.state_NFs_map.items():
                        src_dst_policy_map[(l_EPGs_src, l_EPGs_dst)][state].append(NFs_Qos)

        return src_dst_policy_map

    def graph_union(self, src_dst_states_value_map):
        '''
        首先我得确定什么是冲突的，冲突分为两种，即
        1.
        :param src_dst_policy_map:
        :return:
        '''
        # 在标准图中，所有的EPG都只可能是相等或不想交，所以直接将所有的图放在一张图中
        for (src, dst), states_value_map in src_dst_states_value_map.items():
            # 约束列表
            atomic_state_value_map = defaultdict(list)
            states = list(states_value_map.keys())
            # 对status进行扩充
            atomic_states = decompose_states(states)
            for atomic_state in atomic_states:
                for fa_state in states:
                    if Implies(atomic_state, fa_state):
                        atomic_state_value_map[atomic_state].append(states_value_map[fa_state])
                # 我需要合并该状态下的所有的NFs_Qos
            for atomic_state, NFs_Qos_list in atomic_state_value_map.items():
                final_NFs_Qos = []  # 合并后的NFs_Qos

                constraints = set()  # 依赖约束， 包括原来的前后关系
                NF_set = set()
                Qos_set = set()
                for NFs_Qos in NFs_Qos_list:
                    NFs = NFs_Qos[0]
                    for current_NF, next_NF in zip(NFs, NFs[1:]):
                        constraints.add((current_NF, next_NF))
                        NF_set.add(current_NF)
                        NF_set.add(next_NF)

                    Qos = NFs_Qos[1]
                    Qos_set.add(Qos)

                # 合并QOS
                atomic_qos = union_qos(list(Qos_set))

                # 合并NF链
                for NF in NF_set:
                    for other_NF in NF_set:
                        if (NF != other_NF) and ((NF, other_NF) not in constraints):
                            policy_out_flow = NF.get_output_flow()
                            policy_in_match = other_NF.get_input_flow()
                            if is_overlap(policy_out_flow, policy_in_match):  # 存在依赖关系
                                constraints.add((NF, other_NF))
                atomic_FNs = topological_sort(list(NF_set), list(constraints))
                if atomic_FNs == -1:
                    # 抛出异常，不存在可行的功能盒顺序
                    raise InvalidPolicyGraphError("不存在可行的功能盒顺序")
                atomic_state_value_map[atomic_state] = (atomic_FNs, atomic_qos)
            src_dst_states_value_map[(src, dst)] = atomic_state_value_map
        return src_dst_states_value_map

