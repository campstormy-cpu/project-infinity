"""Small typed directed multigraph. Standard library only, so Thunder can be dropped into any project."""
from __future__ import annotations

import json
from collections import deque


class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: set[tuple[str, str, str]] = set()
        self._out: dict[str, set[tuple[str, str]]] = {}
        self._in: dict[str, set[tuple[str, str]]] = {}

    # -- construction
    def add_node(self, nid: str, kind: str, **attrs) -> None:
        cur = self.nodes.setdefault(nid, {"kind": kind})
        cur.update(attrs)

    def add_edge(self, src: str, dst: str, kind: str) -> None:
        if src == dst:
            return
        self.edges.add((src, dst, kind))
        self._out.setdefault(src, set()).add((dst, kind))
        self._in.setdefault(dst, set()).add((src, kind))

    # -- queries
    def out(self, n: str, kinds=None):
        return [d for d, k in self._out.get(n, ()) if kinds is None or k in kinds]

    def inc(self, n: str, kinds=None):
        return [s for s, k in self._in.get(n, ()) if kinds is None or k in kinds]

    def reachable(self, start, kinds=None, reverse: bool = False) -> set[str]:
        """All nodes reachable from `start` (a node or iterable of nodes), excluding the starts themselves
        unless they sit on a cycle."""
        starts = [start] if isinstance(start, str) else list(start)
        step = self.inc if reverse else self.out
        seen: set[str] = set()
        dq = deque(starts)
        while dq:
            n = dq.popleft()
            for m in step(n, kinds):
                if m not in seen:
                    seen.add(m)
                    dq.append(m)
        return seen

    def path(self, a: str, b: str, kinds=None) -> list[str] | None:
        """Shortest path a -> b (BFS), or None."""
        if a == b:
            return [a]
        prev = {a: None}
        dq = deque([a])
        while dq:
            n = dq.popleft()
            for m in sorted(self.out(n, kinds)):
                if m not in prev:
                    prev[m] = n
                    if m == b:
                        p = [m]
                        while prev[p[-1]] is not None:
                            p.append(prev[p[-1]])
                        return p[::-1]
                    dq.append(m)
        return None

    def cycles(self, kinds=None) -> list[list[str]]:
        """Strongly connected components with more than one node (iterative Tarjan)."""
        index, low, onstack, stack, out = {}, {}, set(), [], []
        counter = [0]
        for root in sorted(self.nodes):
            if root in index:
                continue
            work = [(root, iter(sorted(self.out(root, kinds))))]
            index[root] = low[root] = counter[0]; counter[0] += 1
            stack.append(root); onstack.add(root)
            while work:
                v, it = work[-1]
                adv = False
                for w in it:
                    if w not in index:
                        index[w] = low[w] = counter[0]; counter[0] += 1
                        stack.append(w); onstack.add(w)
                        work.append((w, iter(sorted(self.out(w, kinds)))))
                        adv = True
                        break
                    if w in onstack:
                        low[v] = min(low[v], index[w])
                if adv:
                    continue
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[v])
                if low[v] == index[v]:
                    comp = []
                    while True:
                        w = stack.pop(); onstack.discard(w); comp.append(w)
                        if w == v:
                            break
                    if len(comp) > 1:
                        out.append(sorted(comp))
        return out

    # -- (de)serialisation and diff
    def to_json(self) -> dict:
        return {"nodes": {k: self.nodes[k] for k in sorted(self.nodes)},
                "edges": sorted([list(e) for e in self.edges])}

    @staticmethod
    def from_json(d: dict) -> "Graph":
        g = Graph()
        for k, v in d["nodes"].items():
            g.nodes[k] = dict(v)
        for s, t, k in d["edges"]:
            g.add_edge(s, t, k)
        return g

    def dumps(self) -> str:
        return json.dumps(self.to_json(), indent=1, sort_keys=True) + "\n"

    def to_dot(self, kinds=None) -> str:
        lines = ["digraph thunder {", "  rankdir=LR;"]
        for s, t, k in sorted(self.edges):
            if kinds is None or k in kinds:
                lines.append(f'  "{s}" -> "{t}" [label="{k}"];')
        return "\n".join(lines + ["}"]) + "\n"


def diff(old: Graph, new: Graph) -> dict:
    return {
        "nodes_added": sorted(set(new.nodes) - set(old.nodes)),
        "nodes_removed": sorted(set(old.nodes) - set(new.nodes)),
        "edges_added": sorted(new.edges - old.edges),
        "edges_removed": sorted(old.edges - new.edges),
    }
