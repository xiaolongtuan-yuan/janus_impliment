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

from colections_cul import split_into_disjoint_sets
from label_namespace import label_namespace_define, tree_to_dnf, dnf_mapping_2_set
from policy_graph_error import InvalidPolicyGraphError
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

    def __init__(self, middle_nodes: list(Node), edges: [], src_EPG: GroupNode, dst_EPG: GroupNode):
        self.policy_graph = nx.DiGraph()
        for node in middle_nodes:
            self.policy_graph.add_node(node.label, type=node.type, attr=node)
        self.policy_graph.add_node(src_EPG.label, type=NodeType.group, attr=src_EPG)
        self.policy_graph.add_node(dst_EPG.label, type=NodeType.group, attr=dst_EPG)
        for edge in edges:
            self.policy_graph.add_edge(edge.src, edges.dst, attr=edge.attr)
        self.middle_nodes = middle_nodes
        self.edges = edges

        self.src_EPG = src_EPG
        self.dst_EPG = dst_EPG

    def update_EPGS(self, new_src_label, new_dst_label):  # 修改源，目标节点，以及边的链接，返回新的Policy对象
        nx.DiGraph()
        new_edges = []
        for edge in self.edges:
            if edge.check_node(self.src_EPG) and edge.check_node(self.dst_EPG):
                new_edge = DiEdge(new_src_label, new_dst_label)
            elif edge.check_node(self.src_EPG):
                new_edge = DiEdge(new_src_label, self.dst_EPG.label)
            elif edge.check_node(self.src_EPG):
                new_edge = DiEdge(self.src_EPG.label, new_dst_label)
            else:
                new_edge = copy.deepcopy(edge)

            new_edges.append(new_edge)

        return Policy(middle_nodes=self.middle_nodes, edges=new_edges, src_EPG=GroupNode(label=new_src_label),
                      dst_EPG=GroupNode(label=new_dst_label))


class PolicyModel:
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
        self.EPGs_policy_map[p.src_EPG.label].append(p)

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
        src_dst_policy_map = defaultdict(list)
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
                    new_policy = p.update_EPGS()

                    src_dst_policy_map[(l_EPGs_src, l_EPGs_dst)].append(p)
        return src_dst_policy_map

    def graph_union(self, src_dst_policy_map):
        '''
        首先我得确定什么是冲突的，冲突分为两种，即
        1.
        :param src_dst_policy_map:
        :return:
        '''
        # 在标准图中，所有的EPG都只可能是相等或不想交，所以直接将所有的图放在一张图中
        for (src, dst), policy_list in src_dst_policy_map.items():
            # 约束列表
            constraints = []
            # 1. 组合，确定已有功能盒间的依赖关系作为约束，首先将功能盒转换为优先级匹配规则，根据packge-in 和 创建的package-out来确定依赖关系
            for policy_in in policy_list:
                for policy_out in policy_list:
                    if policy_out == policy_in:
                        continue
                    # 判断是否policy_out创建修改的出流是policy_in要匹配的入流
                    policy_in_match = policy_in.get_input_flow()
                    policy_out_flow = policy_out.get_output_flow()
                    if is_overlap(policy_out_flow, policy_in_match):  # 存在依赖关系
                        constraints.append((policy_out, policy_in))

            # 有向图拓扑求解，根据依赖关系Pyretic使用启发式方法确定功能盒的顺序
            result_policy_list = topological_sort(policy_list, constraints)
            if result_policy_list == -1:
                # 抛出异常，不存在可行的功能盒顺序
                raise InvalidPolicyGraphError("不存在可行的功能盒顺序")
            src_dst_policy_map[(src, dst)] = result_policy_list  # 更新策略盒顺序
        return src_dst_policy_map
