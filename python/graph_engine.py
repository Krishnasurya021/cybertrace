#!/usr/bin/env python3
"""
SENTINEL — Universal Authentication Security & Access Log Monitoring Platform
Module: ADSA (Advanced Data Structures & Algorithms) Access Pattern Graph Engine

Graph Topology:
  APPLICATION -> SOURCE IP -> USERNAME -> SESSION -> RESOURCE

Data Structures & Algorithms Demonstrated:
1. Graph Representation: Adjacency List (memory-efficient O(V + E))
2. Reverse Adjacency List: For efficient backward traversals and in-degree queries
3. Node Hierarchy: APPLICATION, IP, USER, SESSION, RESOURCE
4. Directed Weighted Edges: Track access frequency and failure weight
5. Breadth-First Search (BFS): Blast Radius analysis using Queue
6. Depth-First Search (DFS): Attack path trajectory using Stack/Recursion
7. Frequency Degree Analysis:
   - In-degree of resources (target hotspots)
   - Out-degree of IPs (proxy hubs / multi-account scanners)
"""

import collections
import json
import sqlite3
import os
from typing import Dict, List, Set, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'sentinel.db')

class Node:
    """Represents a vertex in the Access Pattern Graph."""
    def __init__(self, node_id: str, node_type: str, label: str, metadata: Optional[Dict[str, Any]] = None):
        self.id = node_id         # Unique key, e.g. "APP:APP_001", "IP:192.0.2.10", "USER:john123"
        self.type = node_type     # 'APPLICATION', 'IP', 'USER', 'SESSION', 'RESOURCE'
        self.label = label       # Display name
        self.metadata = metadata or {}
        self.in_degree = 0
        self.out_degree = 0
        self.is_suspicious = bool(self.metadata.get('risk_score', 0) >= 50 or self.metadata.get('is_attack', False))

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.type,
            'label': self.label,
            'in_degree': self.in_degree,
            'out_degree': self.out_degree,
            'is_suspicious': self.is_suspicious,
            'metadata': self.metadata
        }

class Edge:
    """Represents a directed weighted edge in the Access Pattern Graph."""
    def __init__(self, source_id: str, target_id: str, weight: int = 1, relationship: str = 'CONNECTS_TO', is_suspicious: bool = False):
        self.source = source_id
        self.target = target_id
        self.weight = weight
        self.relationship = relationship
        self.is_suspicious = is_suspicious

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source': self.source,
            'target': self.target,
            'weight': self.weight,
            'relationship': self.relationship,
            'is_suspicious': self.is_suspicious
        }

class AccessPatternGraph:
    """
    ADSA Graph Engine managing Adjacency List representation,
    BFS / DFS graph traversals, and cybersecurity blast radius calculations.
    """
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        # Adjacency List: node_id -> { target_id: Edge }
        self.adj_list: Dict[str, Dict[str, Edge]] = collections.defaultdict(dict)
        # Reverse Adjacency List
        self.rev_adj_list: Dict[str, Dict[str, Edge]] = collections.defaultdict(dict)

    def add_node(self, node_id: str, node_type: str, label: str, metadata: Optional[Dict[str, Any]] = None) -> Node:
        if node_id not in self.nodes:
            self.nodes[node_id] = Node(node_id, node_type, label, metadata)
        else:
            if metadata:
                self.nodes[node_id].metadata.update(metadata)
                if metadata.get('risk_score', 0) >= 50 or metadata.get('is_attack', False):
                    self.nodes[node_id].is_suspicious = True
        return self.nodes[node_id]

    def add_edge(self, src: str, dst: str, weight_increment: int = 1, rel: str = 'CONNECTS_TO', is_suspicious: bool = False):
        if src not in self.nodes or dst not in self.nodes:
            return

        if dst in self.adj_list[src]:
            self.adj_list[src][dst].weight += weight_increment
            if is_suspicious:
                self.adj_list[src][dst].is_suspicious = True
        else:
            edge = Edge(src, dst, weight_increment, rel, is_suspicious)
            self.adj_list[src][dst] = edge
            self.rev_adj_list[dst][src] = edge
            self.nodes[src].out_degree += 1
            self.nodes[dst].in_degree += 1

    # -------------------------------------------------------------------------
    # ADSA Algorithm 1: Breadth-First Search (BFS)
    # Time Complexity: O(V + E) | Space Complexity: O(V)
    # -------------------------------------------------------------------------
    def bfs(self, start_node_id: str, max_depth: int = 4) -> Dict[str, Any]:
        if start_node_id not in self.nodes:
            return {'visited_order': [], 'paths': {}, 'depth_levels': {}}

        visited: Set[str] = {start_node_id}
        queue = collections.deque([(start_node_id, 0)])
        visited_order: List[str] = []
        depth_levels: Dict[str, int] = {start_node_id: 0}
        parent_map: Dict[str, Optional[str]] = {start_node_id: None}

        while queue:
            curr, depth = queue.popleft()
            visited_order.append(curr)

            if depth < max_depth:
                for neighbor in self.adj_list.get(curr, {}).keys():
                    if neighbor not in visited:
                        visited.add(neighbor)
                        parent_map[neighbor] = curr
                        depth_levels[neighbor] = depth + 1
                        queue.append((neighbor, depth + 1))

        # Reconstruct shortest paths
        paths = {}
        for target in visited_order:
            path = []
            curr_node = target
            while curr_node is not None:
                path.append(curr_node)
                curr_node = parent_map[curr_node]
            paths[target] = list(reversed(path))

        return {
            'algorithm': 'BFS (Breadth-First Search)',
            'start_node': start_node_id,
            'visited_count': len(visited_order),
            'visited_order': visited_order,
            'depth_levels': depth_levels,
            'paths': paths
        }

    # -------------------------------------------------------------------------
    # ADSA Algorithm 2: Depth-First Search (DFS)
    # Time Complexity: O(V + E) | Space Complexity: O(V)
    # -------------------------------------------------------------------------
    def dfs(self, start_node_id: str, max_depth: int = 4) -> Dict[str, Any]:
        if start_node_id not in self.nodes:
            return {'visited_order': [], 'traversal_edges': []}

        visited: Set[str] = set()
        visited_order: List[str] = []
        traversal_edges: List[Dict[str, str]] = []

        def _dfs_visit(node: str, depth: int):
            if depth > max_depth or node in visited:
                return
            visited.add(node)
            visited_order.append(node)

            for neighbor in self.adj_list.get(node, {}).keys():
                if neighbor not in visited:
                    traversal_edges.append({'from': node, 'to': neighbor})
                    _dfs_visit(neighbor, depth + 1)

        _dfs_visit(start_node_id, 0)

        return {
            'algorithm': 'DFS (Depth-First Search)',
            'start_node': start_node_id,
            'visited_count': len(visited_order),
            'visited_order': visited_order,
            'traversal_edges': traversal_edges
        }

    # -------------------------------------------------------------------------
    # ADSA Analysis: Blast Radius
    # -------------------------------------------------------------------------
    def calculate_blast_radius(self, node_id: str) -> Dict[str, Any]:
        """Calculates all downstream applications, IPs, users, sessions, and resources."""
        bfs_res = self.bfs(node_id, max_depth=4)
        touched_apps = []
        touched_ips = []
        touched_users = []
        touched_sessions = []
        touched_resources = []

        for nid in bfs_res['visited_order']:
            node = self.nodes.get(nid)
            if not node:
                continue
            if node.type == 'APPLICATION':
                touched_apps.append(node.to_dict())
            elif node.type == 'IP':
                touched_ips.append(node.to_dict())
            elif node.type == 'USER':
                touched_users.append(node.to_dict())
            elif node.type == 'SESSION':
                touched_sessions.append(node.to_dict())
            elif node.type == 'RESOURCE':
                touched_resources.append(node.to_dict())

        return {
            'source_node': self.nodes.get(node_id, Node(node_id, 'UNKNOWN', node_id)).to_dict(),
            'total_compromised_nodes': len(bfs_res['visited_order']),
            'apps_impacted': touched_apps,
            'ips_involved': touched_ips,
            'users_targeted': touched_users,
            'sessions_affected': touched_sessions,
            'resources_exposed': touched_resources
        }

    def get_high_degree_nodes(self, limit: int = 5) -> Dict[str, Any]:
        sorted_by_in = sorted(self.nodes.values(), key=lambda n: n.in_degree, reverse=True)[:limit]
        sorted_by_out = sorted(self.nodes.values(), key=lambda n: n.out_degree, reverse=True)[:limit]
        return {
            'top_incoming_targets': [n.to_dict() for n in sorted_by_in if n.in_degree > 0],
            'top_outgoing_sources': [n.to_dict() for n in sorted_by_out if n.out_degree > 0]
        }

    def to_graph_data(self) -> Dict[str, Any]:
        edges = []
        for src, targets in self.adj_list.items():
            for dst, edge in targets.items():
                edges.append(edge.to_dict())

        return {
            'nodes': [n.to_dict() for n in self.nodes.values()],
            'edges': edges,
            'stats': {
                'total_nodes': len(self.nodes),
                'total_edges': len(edges)
            }
        }

def build_graph_from_db(limit_logs: int = 350) -> AccessPatternGraph:
    """
    Constructs the 5-tier ADSA Access Pattern Graph directly from sentinel.db:
    APPLICATION -> SOURCE IP -> USERNAME -> SESSION -> RESOURCE
    """
    graph = AccessPatternGraph()
    if not os.path.exists(DB_PATH):
        return graph

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. Applications
    for a in cursor.execute("SELECT application_id, name, app_type, environment FROM applications"):
        graph.add_node(f"APP:{a['application_id']}", 'APPLICATION', a['name'], {
            'type': a['app_type'], 'env': a['environment']
        })

    # 2. Sessions (Active & Historical)
    sessions_map = {}
    for s in cursor.execute("SELECT session_id, application_id, username_identifier, source_ip, duration_seconds, is_active FROM sessions LIMIT 40"):
        sid = f"SES:{s['session_id']}"
        sessions_map[s['session_id']] = sid
        graph.add_node(sid, 'SESSION', f"Session #{s['session_id'][-5:]}", {
            'duration': s['duration_seconds'], 'active': bool(s['is_active'])
        })

    # 3. Authentication Events
    events = cursor.execute(f"""
        SELECT event_id, application_id, username_identifier, authentication_result,
               source_ip, device_type, resource, session_id, risk_level, risk_score
        FROM authentication_events
        ORDER BY event_id DESC
        LIMIT {limit_logs}
    """).fetchall()

    for ev in events:
        app_nid = f"APP:{ev['application_id']}"
        ip_nid = f"IP:{ev['source_ip']}"
        user_nid = f"USER:{ev['username_identifier']}"
        res_nid = f"RES:{ev['resource']}"
        is_susp = bool(ev['risk_score'] >= 50 or ev['risk_level'] in ('HIGH', 'CRITICAL'))

        # Add IP Node
        graph.add_node(ip_nid, 'IP', ev['source_ip'], {
            'device': ev['device_type'],
            'risk_score': ev['risk_score'],
            'is_attack': is_susp
        })

        # Add User Node
        graph.add_node(user_nid, 'USER', ev['username_identifier'], {
            'result': ev['authentication_result'],
            'risk_score': ev['risk_score'],
            'is_attack': is_susp
        })

        # Add Resource Node
        graph.add_node(res_nid, 'RESOURCE', ev['resource'], {
            'is_restricted': ('admin' in ev['resource'] or 'root' in ev['resource'])
        })

        # Tier 1: APPLICATION -> SOURCE IP
        graph.add_edge(app_nid, ip_nid, 1, 'ROUTES_ORIGIN', is_susp)

        # Tier 2: SOURCE IP -> USERNAME
        graph.add_edge(ip_nid, user_nid, 1, 'PROBES_IDENTITY', is_susp)

        # Tier 3: USERNAME -> SESSION (if session established)
        if ev['session_id'] and ev['session_id'] in sessions_map:
            sess_nid = sessions_map[ev['session_id']]
            graph.add_edge(user_nid, sess_nid, 1, 'AUTHENTICATED_SESSION', is_susp)
            # Tier 4: SESSION -> RESOURCE
            graph.add_edge(sess_nid, res_nid, 1, 'ACCESSES_RESOURCE', is_susp)
        else:
            # Direct probe without session
            graph.add_edge(user_nid, res_nid, 1, 'DIRECT_AUTH_PROBE', is_susp)

    conn.close()
    return graph

if __name__ == '__main__':
    print("=== Testing 5-Tier ADSA Access Graph ===")
    g = build_graph_from_db(limit_logs=200)
    data = g.to_graph_data()
    print(f"Total Nodes: {data['stats']['total_nodes']}, Total Edges: {data['stats']['total_edges']}")
    bfs = g.bfs('APP:APP_001', max_depth=3)
    print(f"BFS from APP:APP_001 visited: {bfs['visited_count']} nodes")
    print(f"Sequence: {bfs['visited_order'][:6]}")
    blast = g.calculate_blast_radius('IP:192.0.2.10')
    print(f"Blast Radius of 192.0.2.10: {blast['total_compromised_nodes']} nodes, Targeted Users: {[u['label'] for u in blast['users_targeted']]}")
