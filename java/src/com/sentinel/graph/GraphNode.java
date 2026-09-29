package com.sentinel.graph;

import java.util.*;

/**
 * OOP Principle: ENCAPSULATION & COLLECTIONS
 * Represents a vertex in the Java Access Pattern Graph.
 */
public class GraphNode {
    private String id;
    private String type; // USER, IP, SESSION, RESOURCE
    private String label;
    private Set<GraphNode> neighbors;

    public GraphNode(String id, String type, String label) {
        this.id = id;
        this.type = type;
        this.label = label;
        this.neighbors = new LinkedHashSet<>();
    }

    public void addNeighbor(GraphNode neighbor) {
        this.neighbors.add(neighbor);
    }

    public String getId() { return id; }
    public String getType() { return type; }
    public String getLabel() { return label; }
    public Set<GraphNode> getNeighbors() { return neighbors; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof GraphNode)) return false;
        GraphNode that = (GraphNode) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return String.format("%s[%s]", type, label);
    }
}
