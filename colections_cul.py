# -*- coding: utf-8 -*-
"""
@Time ： 2024/7/27 00:57
@Auth ： xiaolongtuan
@File ：colections_cul.py
"""
from functools import reduce
from itertools import combinations


def split_into_disjoint_sets(sets):
    # 将EPGs拆分为不相交集合，同时记录他们与原始EPGs的关联，用于后面的约束复制
    all_elements = set().union(*sets)
    disjoint_sets = []

    # 找到所有可能的交集
    all_intersections = []
    for i in reversed(range(1, len(sets) + 1)):
        for combo in combinations(sets, i):
            intersect = set.intersection(*combo)
            if intersect:
                all_intersections.append(intersect)

    # 去重并确保每个元素只出现在一个集合中
    used_elements = set()
    for intersect in all_intersections:
        intersect -= used_elements
        if intersect:
            disjoint_sets.append(intersect)
            used_elements.update(intersect)

    return disjoint_sets


if __name__ == '__main__':
    result = split_into_disjoint_sets(sets=[
        {1, 2, 3, 4},
        {3, 4, 5, 6},
        {1, 4, 7, 8},
        {2, 4, 9, 10}
    ])
    print(result)
