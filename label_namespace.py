# -*- coding: utf-8 -*-
"""
@Time ： 2024/7/26 16:07
@Auth ： xiaolongtuan
@File ：label_namespace.py
"""

from collections import defaultdict


# 并查集，寻找groupNode归属
class UnionFind:
    def __init__(self, size):
        self.parent = list(range(size))
        self.rank = [1] * size

    def find(self, p):  # 找到最大的group
        if self.parent[p] != p:
            self.parent[p] = self.find(self.parent[p])
        return self.parent[p]

    def union(self, p, q):
        rootP = self.find(p)
        rootQ = self.find(q)

        if rootP != rootQ:
            if self.rank[rootP] > self.rank[rootQ]:
                self.parent[rootQ] = rootP
            elif self.rank[rootP] < self.rank[rootQ]:
                self.parent[rootP] = rootQ
            else:
                self.parent[rootQ] = rootP
                self.rank[rootP] += 1

    def connected(self, p, q):
        return self.find(p) == self.find(q)


def label_namespace_define(label_trees: []):
    '''
    形如：
    trees = [
        [(0, 1), (1, 2)],  # 树1
        [(3, 4)],          # 树2
        [(5, 6), (6, 7)]   # 树3
    ]

    任何不具有祖先关系的标签集都是互斥的
    '''
    label_set = set()
    for tree in label_trees:
        for u, v in tree:
            label_set.add(u)
            label_set.add(v)
    num_nodes = len(label_set)

    uf = UnionFind(num_nodes)
    # 合并树中的节点
    for tree in label_trees:
        for u, v in tree:
            uf.union(u, v)

    return uf


def tree_to_dnf(edges, label_mapping_pairs: []):
    # 标签层次结果转为正析取范式
    # 构建子节点的列表
    tree = defaultdict(list)
    for parent, child in edges:
        tree[parent].append(child)

    label_mapping = defaultdict(str)
    for pair in label_mapping_pairs:
        label_mapping[pair[1]] = label_mapping_pairs[0]  # 单项映射，后者包含前者

    # 找到所有节点
    all_nodes = set(tree.keys()).union({child for children in tree.values() for child in children})

    # 找到所有叶节点
    leaf_nodes = all_nodes - set(tree.keys())

    # 初始化结果
    result = {}

    # 从叶节点开始，递归构建表达式
    def build_dnf(node):

        if node in leaf_nodes:
            return str(node)
        if node in result:
            return result[node]

        # 构建当前节点的析取表达式
        sub_label = [build_dnf(child) for child in tree[node]]
        if node in label_mapping:  # 处理标签映射对析取式的影响
            sub_label.append(label_mapping[node])
        children_dnf = ' or '.join(sub_label)
        result[node] = children_dnf
        return children_dnf

    # 构建所有节点的DNF表达式
    for node in all_nodes:
        if node not in result:
            build_dnf(node)

    return result


def dnf_mapping_2_set(dnf_mapping: {}):
    res = {}
    sets = []
    for node, dnf in dnf_mapping.items():
        leaf_set = set(dnf.split(' or '))
        res[node] = leaf_set
        sets.append(leaf_set)

    return res, sets # node-集合映射表，和集合列表



def label_mapping(label_mapping_pairs: []):
    '''
    签映射使组合能够通过捕获不同标签树（例如 租户和位置标签树）之间的标签之间的关系来 避免生成此类不可能的 EPG 组合。
    '''
    label_mapping = {}
    for pair in label_mapping_pairs:
        label_mapping[pair[0]] = pair[1]
        label_mapping[pair[1]] = pair[0]

    return label_mapping
