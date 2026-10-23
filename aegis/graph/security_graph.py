"""Security graph (PHASES P9.2, P9.5) — endpoint ↔ function ↔ sink ↔ finding ↔ library/crypto.

Node keys (SYSTEM_DESIGN §4.3)::

    endpoint      GET /api/accounts/{param}
    function      app/routes/accounts.py::get_account
    sink          app/routes/accounts.py:27::db.execute
    finding       F-0012
    library       pkg:pypi/requests@2.19.0
    crypto_asset  algo:MD5@app/auth.py:14

Edges: ``HANDLED_BY`` (endpoint → function, ``score``/``signals``/``origin``),
``FLOWS_TO`` (function → sink, ``evidence_id``), ``ON`` (finding → endpoint |
function), ``USES`` (function → library | crypto_asset, ``evidence_id``).

NetworkX is the default engine behind a small :class:`GraphBackend` protocol, so
a Neo4j implementation can replace it without touching callers (SD §4.3).
Deterministic: no LLM, no randomness; serialization is sorted so a saved graph
reloads identical.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Protocol

import networkx as nx

__all__ = [
    "NODE_TYPES",
    "EDGE_KINDS",
    "GraphBackend",
    "NetworkXBackend",
    "SecurityGraph",
    "graph_path",
]

NODE_TYPES = ("endpoint", "function", "sink", "finding", "library", "crypto_asset")
EDGE_KINDS = ("HANDLED_BY", "FLOWS_TO", "ON", "USES")
_SCAN_ID = re.compile(r"^S-\d{4,}$")


def graph_path(data_dir: str | Path, scan_id: str) -> Path:
    """``<data_dir>/graphs/<scan_id>.json`` — the id is validated (no path traversal)."""
    if not _SCAN_ID.match(scan_id):
        raise ValueError(f"invalid scan id: {scan_id!r}")
    return Path(data_dir) / "graphs" / f"{scan_id}.json"


class GraphBackend(Protocol):
    def add_node(self, key: str, node_type: str, **attrs: Any) -> None: ...
    def add_edge(self, src: str, dst: str, kind: str, **attrs: Any) -> None: ...
    def node(self, key: str) -> dict[str, Any] | None: ...
    def nodes(self, type: str | None = None) -> list[tuple[str, dict[str, Any]]]: ...
    def edges(self, kind: str | None = None) -> list[tuple[str, str, str, dict[str, Any]]]: ...
    def successors(self, key: str, kind: str | None = None) -> list[str]: ...
    def predecessors(self, key: str, kind: str | None = None) -> list[str]: ...
    def to_node_link(self) -> dict[str, Any]: ...


class NetworkXBackend:
    """``networkx.MultiDiGraph`` keyed by edge kind (re-adding an edge updates it)."""

    def __init__(self, graph: nx.MultiDiGraph | None = None):
        self._g = graph if graph is not None else nx.MultiDiGraph()

    def add_node(self, key: str, node_type: str, **attrs: Any) -> None:
        if key in self._g:
            self._g.nodes[key].update(attrs)
        else:
            self._g.add_node(key, type=node_type, **attrs)

    def add_edge(self, src: str, dst: str, kind: str, **attrs: Any) -> None:
        if self._g.has_edge(src, dst, key=kind):
            self._g.edges[src, dst, kind].update(attrs)
        else:
            self._g.add_edge(src, dst, key=kind, **attrs)

    def node(self, key: str) -> dict[str, Any] | None:
        return dict(self._g.nodes[key]) if key in self._g else None

    def nodes(self, type: str | None = None) -> list[tuple[str, dict[str, Any]]]:
        items = [(k, dict(a)) for k, a in self._g.nodes(data=True) if type is None or a.get("type") == type]
        return sorted(items, key=lambda kv: kv[0])

    def edges(self, kind: str | None = None) -> list[tuple[str, str, str, dict[str, Any]]]:
        items = [
            (s, d, k, dict(a))
            for s, d, k, a in self._g.edges(keys=True, data=True)
            if kind is None or k == kind
        ]
        return sorted(items, key=lambda e: (e[0], e[1], e[2]))

    def successors(self, key: str, kind: str | None = None) -> list[str]:
        if key not in self._g:
            return []
        found = {d for _, d, k in self._g.out_edges(key, keys=True) if kind is None or k == kind}
        return sorted(found)

    def predecessors(self, key: str, kind: str | None = None) -> list[str]:
        if key not in self._g:
            return []
        found = {s for s, _, k in self._g.in_edges(key, keys=True) if kind is None or k == kind}
        return sorted(found)

    def to_node_link(self) -> dict[str, Any]:
        return {
            "directed": True,
            "multigraph": True,
            "nodes": [{"id": k, **a} for k, a in self.nodes()],
            "edges": [{"source": s, "target": d, "kind": k, **a} for s, d, k, a in self.edges()],
        }

    @classmethod
    def from_node_link(cls, data: dict[str, Any]) -> "NetworkXBackend":
        backend = cls()
        for node in data.get("nodes", []):
            attrs = {k: v for k, v in node.items() if k != "id"}
            backend._g.add_node(node["id"], **attrs)
        for edge in data.get("edges", []):
            attrs = {k: v for k, v in edge.items() if k not in ("source", "target", "kind")}
            backend._g.add_edge(edge["source"], edge["target"], key=edge["kind"], **attrs)
        return backend


class SecurityGraph:
    def __init__(self, backend: GraphBackend | None = None):
        self.backend: GraphBackend = backend or NetworkXBackend()

    # --- nodes ------------------------------------------------------------ #
    def add_endpoint(self, key: str, **attrs: Any) -> str:
        self.backend.add_node(key, "endpoint", label=key, **attrs)
        return key

    def add_function(self, qualname: str, *, name: str, file: str, line: int | None = None, **attrs: Any) -> str:
        self.backend.add_node(qualname, "function", label=name, file=file, line=line, **attrs)
        return qualname

    def add_sink(self, file: str, line: int, name: str) -> str:
        key = f"{file}:{line}::{name}"
        self.backend.add_node(key, "sink", label=name, file=file, line=line)
        return key

    def add_finding(self, finding_id: str, **attrs: Any) -> str:
        self.backend.add_node(finding_id, "finding", label=finding_id, **attrs)
        return finding_id

    def add_library(self, purl: str, **attrs: Any) -> str:
        self.backend.add_node(purl, "library", label=purl, **attrs)
        return purl

    def add_crypto_asset(self, algo: str, file: str, line: int | None, **attrs: Any) -> str:
        key = f"algo:{algo}@{file}:{line}"
        self.backend.add_node(key, "crypto_asset", label=f"{algo}", file=file, line=line, **attrs)
        return key

    # --- edges ------------------------------------------------------------ #
    def handled_by(self, endpoint: str, function: str, *, score: float, signals: dict[str, Any], origin: str) -> None:
        self.backend.add_edge(endpoint, function, "HANDLED_BY", score=score, signals=signals, origin=origin)

    def flows_to(self, function: str, sink: str, evidence_id: str) -> None:
        self.backend.add_edge(function, sink, "FLOWS_TO", evidence_id=evidence_id)

    def on(self, finding_id: str, target: str) -> None:
        self.backend.add_edge(finding_id, target, "ON")

    def uses(self, function: str, target: str, evidence_id: str) -> None:
        self.backend.add_edge(function, target, "USES", evidence_id=evidence_id)

    # --- queries ---------------------------------------------------------- #
    def _label(self, key: str) -> str:
        node = self.backend.node(key) or {}
        return str(node.get("label", key))

    def _type(self, key: str) -> str | None:
        return (self.backend.node(key) or {}).get("type")

    def attack_paths(self) -> list[list[str]]:
        """Chains ``[endpoint, function, sink, finding]`` (labels), one per sink.

        A finding is attached to an endpoint and/or a function. Endpoint and
        function are paired through ``HANDLED_BY`` from whichever side the
        finding is on, then ``FLOWS_TO`` gives the sinks. Without a sink the
        chain is ``[endpoint, function, finding]``; a function with no endpoint
        yields ``[function, sink…, finding]``.
        """
        paths: list[list[str]] = []
        for finding_id, _ in self.backend.nodes("finding"):
            pairs: set[tuple[str | None, str]] = set()
            for target in self.backend.successors(finding_id, "ON"):
                kind = self._type(target)
                if kind == "endpoint":
                    for function in self.backend.successors(target, "HANDLED_BY"):
                        pairs.add((target, function))
                elif kind == "function":
                    endpoints = self.backend.predecessors(target, "HANDLED_BY")
                    for endpoint in endpoints or [None]:
                        pairs.add((endpoint, target))
            for endpoint, function in sorted(pairs, key=lambda p: (p[0] or "", p[1])):
                head = ([self._label(endpoint)] if endpoint else []) + [self._label(function)]
                sinks = self.backend.successors(function, "FLOWS_TO")
                if sinks:
                    for sink in sinks:
                        paths.append([*head, self._label(sink), finding_id])
                else:
                    paths.append([*head, finding_id])
        return paths

    def to_api(self) -> dict[str, Any]:
        """Cytoscape-style ``{nodes, edges}`` for ``GET /api/graph``."""
        nodes = [{"data": {"id": k, **a}} for k, a in self.backend.nodes()]
        edges = [
            {"data": {"id": f"{s}|{k}|{d}", "source": s, "target": d, "kind": k, **a}}
            for s, d, k, a in self.backend.edges()
        ]
        return {"nodes": nodes, "edges": edges}

    # --- persistence ------------------------------------------------------ #
    def to_node_link(self) -> dict[str, Any]:
        return self.backend.to_node_link()

    @classmethod
    def from_node_link(cls, data: dict[str, Any]) -> "SecurityGraph":
        return cls(NetworkXBackend.from_node_link(data))

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_node_link(), indent=2, sort_keys=True), encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path) -> "SecurityGraph":
        return cls.from_node_link(json.loads(Path(path).read_text(encoding="utf-8")))
