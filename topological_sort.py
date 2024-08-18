# -*- coding: utf-8 -*-
"""
@Time ： 2024/8/16 16:49
@Auth ： xiaolongtuan
@File ：topological_sort.py
"""
from collections import defaultdict, deque


def topological_sort(elements, dependencies):
    # Step 1: Build the graph and compute in-degrees
    graph = defaultdict(list)
    in_degree = {element: 0 for element in elements}

    for u, v in dependencies:
        graph[u].append(v)
        in_degree[v] += 1

    # Step 2: Initialize the queue with nodes having in-degree 0
    queue = deque([element for element in elements if in_degree[element] == 0])

    topological_order = []

    # Step 3: Process nodes in the queue
    while queue:
        node = queue.popleft()
        topological_order.append(node)

        # Decrease the in-degree of adjacent nodes
        for neighbor in graph[node]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    # Step 4: Check if the topological order includes all elements
    if len(topological_order) == len(elements):
        return topological_order
    else:
        return -1


if __name__ == '__main__':

    elements = ['A', 'B', 'C', 'D', 'E', 'F']
    dependencies = [('A', 'C'), ('B', 'C'), ('C', 'E'), ('D', 'E'), ('E', 'F')]

    result = topological_sort(elements, dependencies)
    print(result)
