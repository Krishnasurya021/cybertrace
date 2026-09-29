package com.sentinel.graph;

import java.util.*;

/**
 * ADSA + OOPJ Principle: DATA STRUCTURES, ADJACENCY LIST & GRAPH TRAVERSALS
 * Implements an access graph with BFS and DFS traversals in Java.
 */
public class AccessGraph {
    private Map<String, GraphNode> nodes;

    public AccessGraph() {
        this.nodes = new LinkedHashMap<>();
    }

    public GraphNode getOrCreateNode(String id, String type, String label) {
        return nodes.computeIfAbsent(id, k -> new GraphNode(id, type, label));
    }

    public void addEdge(String srcId, String srcType, String srcLabel,
                        String dstId, String dstType, String dstLabel) {
        GraphNode src = getOrCreateNode(srcId, srcType, srcLabel);
        GraphNode dst = getOrCreateNode(dstId, dstType, dstLabel);
        src.addNeighbor(dst);
    }

    /**
     * Breadth-First Search (BFS) Traversal using java.util.Queue
     * Time Complexity: O(V + E)
     * Demonstrates Queue collection, level-order expansion, and visited set.
     */
    public List<GraphNode> bfs(String startId) {
        List<GraphNode> result = new ArrayList<>();
        if (!nodes.containsKey(startId)) return result;

        Set<String> visited = new HashSet<>();
        Queue<GraphNode> queue = new LinkedList<>();

        GraphNode start = nodes.get(startId);
        visited.add(start.getId());
        queue.offer(start);

        while (!queue.isEmpty()) {
            GraphNode curr = queue.poll();
            result.add(curr);

            for (GraphNode neighbor : curr.getNeighbors()) {
                if (!visited.contains(neighbor.getId())) {
                    visited.add(neighbor.getId());
                    queue.offer(neighbor);
                }
            }
        }
        return result;
    }

    /**
     * Depth-First Search (DFS) Traversal using java.util.Stack
     * Time Complexity: O(V + E)
     * Demonstrates Stack collection, LIFO order traversal.
     */
    public List<GraphNode> dfs(String startId) {
        List<GraphNode> result = new ArrayList<>();
        if (!nodes.containsKey(startId)) return result;

        Set<String> visited = new HashSet<>();
        Stack<GraphNode> stack = new Stack<>();

        stack.push(nodes.get(startId));

        while (!stack.isEmpty()) {
            GraphNode curr = stack.pop();

            if (!visited.contains(curr.getId())) {
                visited.add(curr.getId());
                result.add(curr);

                for (GraphNode neighbor : curr.getNeighbors()) {
                    if (!visited.contains(neighbor.getId())) {
                        stack.push(neighbor);
                    }
                }
            }
        }
        return result;
    }

    public Map<String, GraphNode> getNodes() {
        return nodes;
    }

    public int getNodeCount() {
        return nodes.size();
    }
}
