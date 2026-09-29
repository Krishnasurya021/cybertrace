package com.sentinel.graph;

import java.util.*;

/**
 * SENTINEL OOPJ & ADSA - GraphManager
 * Orchestrates multi-tier access graph modeling and graph algorithms:
 *   APPLICATION -> SOURCE IP -> USERNAME -> SESSION -> RESOURCE
 * Provides Breadth-First Search (BFS) and Depth-First Search (DFS).
 */
public class GraphManager {
    private final Map<String, GraphNode> nodes;
    private final Map<String, List<String>> adjacencyList;

    public GraphManager() {
        this.nodes = new HashMap<>();
        this.adjacencyList = new HashMap<>();
    }

    public void addNode(String id, String type, String label) {
        if (!nodes.containsKey(id)) {
            nodes.put(id, new GraphNode(id, type, label));
            adjacencyList.put(id, new ArrayList<>());
        }
    }

    public void addEdge(String src, String dst) {
        if (nodes.containsKey(src) && nodes.containsKey(dst)) {
            if (!adjacencyList.get(src).contains(dst)) {
                adjacencyList.get(src).add(dst);
            }
        }
    }

    /**
     * Breadth-First Search (BFS) - Explores blast radius from a compromised origin.
     */
    public List<String> bfs(String startNodeId) {
        List<String> visitedOrder = new ArrayList<>();
        if (!nodes.containsKey(startNodeId)) return visitedOrder;

        Set<String> visited = new HashSet<>();
        Queue<String> queue = new LinkedList<>();

        visited.add(startNodeId);
        queue.add(startNodeId);

        while (!queue.isEmpty()) {
            String curr = queue.poll();
            visitedOrder.add(curr);

            for (String neighbor : adjacencyList.getOrDefault(curr, Collections.emptyList())) {
                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    queue.add(neighbor);
                }
            }
        }
        return visitedOrder;
    }

    /**
     * Depth-First Search (DFS) - Discovers attack sequence trajectory chains.
     */
    public List<String> dfs(String startNodeId) {
        List<String> visitedOrder = new ArrayList<>();
        if (!nodes.containsKey(startNodeId)) return visitedOrder;

        Set<String> visited = new HashSet<>();
        dfsRecursive(startNodeId, visited, visitedOrder);
        return visitedOrder;
    }

    private void dfsRecursive(String node, Set<String> visited, List<String> order) {
        visited.add(node);
        order.add(node);

        for (String neighbor : adjacencyList.getOrDefault(node, Collections.emptyList())) {
            if (!visited.contains(neighbor)) {
                dfsRecursive(neighbor, visited, order);
            }
        }
    }

    public int getNodeCount() { return nodes.size(); }
    public Map<String, GraphNode> getNodes() { return Collections.unmodifiableMap(nodes); }
}
