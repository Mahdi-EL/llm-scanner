import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import math
from collections import defaultdict
from datetime import datetime


# ── Graph Node ────────────────────────────────────────────────
class GraphNode:
    """
    Represents a node in the attack graph.
    Can be an attack category or a finding.
    """

    def __init__(self, node_id, label, node_type, severity=None):
        self.node_id   = node_id
        self.label     = label
        self.node_type = node_type  # "category" or "finding"
        self.severity  = severity
        self.x         = 0.0
        self.y         = 0.0
        self.size      = 30
        self.color     = self._get_color()

    def _get_color(self):
        severity_colors = {
            "CRITICAL": "#C0392B",
            "HIGH"    : "#E67E22",
            "MEDIUM"  : "#F1C40F",
            "LOW"     : "#27AE60",
            "SAFE"    : "#2ECC71"
        }
        if self.node_type == "category":
            return "#2E75B6"
        return severity_colors.get(self.severity, "#888888")


# ── Graph Edge ────────────────────────────────────────────────
class GraphEdge:
    """Represents a connection between two nodes."""

    def __init__(self, source, target, weight=1.0, label=""):
        self.source = source
        self.target = target
        self.weight = weight
        self.label  = label


# ── Attack Graph Builder ──────────────────────────────────────
class AttackGraphBuilder:
    """
    Builds a graph from scan results showing
    how attacks relate to findings.
    """

    def __init__(self, scan_data):
        self.scan_data = scan_data
        self.nodes     = {}
        self.edges     = []

    def build(self):
        """Builds the attack graph from scan results."""
        results = self.scan_data.get("results", [])

        # Group by category
        by_category = defaultdict(list)
        for r in results:
            by_category[r["category"]].append(r)

        # Create category nodes
        for category in by_category:
            node_id = f"cat_{category}"
            label   = category.replace("_", " ").title()
            node    = GraphNode(node_id, label, "category")

            # Size based on number of findings
            count      = len(by_category[category])
            node.size  = 20 + (count * 2)

            self.nodes[node_id] = node

        # Create finding nodes for critical/high
        for r in results:
            if r["severity"] not in ("CRITICAL", "HIGH"):
                continue

            node_id = f"finding_{r['category']}_{len(self.nodes)}"
            label   = r["severity"]
            node    = GraphNode(
                node_id, label, "finding", r["severity"]
            )
            node.size = 40 if r["severity"] == "CRITICAL" else 30

            self.nodes[node_id] = node

            # Edge from category to finding
            cat_node_id = f"cat_{r['category']}"
            if cat_node_id in self.nodes:
                edge = GraphEdge(
                    source=cat_node_id,
                    target=node_id,
                    weight=r["score"] / 10,
                    label =f"Score {r['score']}/10"
                )
                self.edges.append(edge)

        # Add edges between related categories
        category_list = list(by_category.keys())
        chain_pairs   = [
            ("direct_override",   "extraction"),
            ("social_engineering","extraction"),
            ("prompt_chaining",   "direct_override"),
            ("encoding_attacks",  "direct_override"),
            ("indirect_injection","extraction"),
        ]

        for source_cat, target_cat in chain_pairs:
            source_id = f"cat_{source_cat}"
            target_id = f"cat_{target_cat}"
            if source_id in self.nodes and target_id in self.nodes:
                edge = GraphEdge(
                    source=source_id,
                    target=target_id,
                    weight=0.5,
                    label ="leads to"
                )
                self.edges.append(edge)

        self._layout_nodes()
        return self.nodes, self.edges

    def _layout_nodes(self):
        """
        Positions nodes in a circular layout.
        Categories on outer ring, findings in center.
        """
        category_nodes = [
            n for n in self.nodes.values()
            if n.node_type == "category"
        ]
        finding_nodes = [
            n for n in self.nodes.values()
            if n.node_type == "finding"
        ]

        # Position category nodes in circle
        total_cats = len(category_nodes)
        radius     = 300

        for i, node in enumerate(category_nodes):
            angle  = (2 * math.pi * i) / max(total_cats, 1)
            node.x = 400 + radius * math.cos(angle)
            node.y = 400 + radius * math.sin(angle)

        # Position finding nodes closer to center
        total_findings = len(finding_nodes)
        inner_radius   = 150

        for i, node in enumerate(finding_nodes):
            angle  = (2 * math.pi * i) / max(total_findings, 1)
            node.x = 400 + inner_radius * math.cos(angle)
            node.y = 400 + inner_radius * math.sin(angle)


# ── SVG Generator ─────────────────────────────────────────────
class SVGGraphGenerator:
    """
    Generates an SVG visualization of the attack graph.
    """

    WIDTH  = 800
    HEIGHT = 800

    def generate(self, nodes, edges, title="Attack Graph"):
        """Generates SVG string from graph data."""

        svg_parts = [f"""<svg width="{self.WIDTH}" height="{self.HEIGHT}"
    xmlns="http://www.w3.org/2000/svg"
    style="background:#0f1117;font-family:Segoe UI,sans-serif">

  <!-- Title -->
  <text x="{self.WIDTH//2}" y="30"
    text-anchor="middle"
    fill="#ffffff" font-size="18" font-weight="bold">
    🔐 {title}
  </text>

  <!-- Defs -->
  <defs>
    <marker id="arrow" markerWidth="10" markerHeight="7"
      refX="10" refY="3.5" orient="auto">
      <polygon points="0 0, 10 3.5, 0 7" fill="#444444"/>
    </marker>
    <filter id="glow">
      <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
      <feMerge>
        <feMergeNode in="coloredBlur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>
"""]

        # Draw edges first (behind nodes)
        for edge in edges:
            source = nodes.get(edge.source)
            target = nodes.get(edge.target)

            if not source or not target:
                continue

            # Line opacity based on weight
            opacity = 0.3 + (edge.weight * 0.5)
            color   = "#C0392B" if edge.weight > 0.6 else "#444444"

            svg_parts.append(f"""  <line
    x1="{source.x:.0f}" y1="{source.y:.0f}"
    x2="{target.x:.0f}" y2="{target.y:.0f}"
    stroke="{color}" stroke-width="{1 + edge.weight * 2:.1f}"
    stroke-opacity="{opacity:.1f}"
    marker-end="url(#arrow)"/>
""")

            # Edge label at midpoint
            if edge.label and edge.weight > 0.5:
                mid_x = (source.x + target.x) / 2
                mid_y = (source.y + target.y) / 2
                svg_parts.append(f"""  <text x="{mid_x:.0f}" y="{mid_y:.0f}"
    text-anchor="middle" fill="#888888"
    font-size="9" opacity="0.8">
    {edge.label}
  </text>
""")

        # Draw nodes
        for node in nodes.values():

            # Glow for critical nodes
            glow_filter = 'filter="url(#glow)"' \
                          if node.severity == "CRITICAL" else ""

            # Node circle
            svg_parts.append(f"""  <circle
    cx="{node.x:.0f}" cy="{node.y:.0f}"
    r="{node.size}"
    fill="{node.color}" fill-opacity="0.85"
    stroke="{node.color}" stroke-width="2"
    {glow_filter}/>
""")

            # Node label
            label_lines = node.label.split()
            if len(label_lines) <= 2:
                svg_parts.append(f"""  <text
    x="{node.x:.0f}" y="{node.y + 4:.0f}"
    text-anchor="middle"
    fill="#ffffff" font-size="10" font-weight="bold">
    {node.label[:15]}
  </text>
""")
            else:
                # Multi-line label
                for i, line in enumerate(label_lines[:2]):
                    y_offset = node.y - 6 + (i * 14)
                    svg_parts.append(f"""  <text
    x="{node.x:.0f}" y="{y_offset:.0f}"
    text-anchor="middle"
    fill="#ffffff" font-size="9" font-weight="bold">
    {line}
  </text>
""")

        # Legend
        legend_items = [
            ("#2E75B6", "Attack Category"),
            ("#C0392B", "Critical Finding"),
            ("#E67E22", "High Finding"),
        ]

        for i, (color, label) in enumerate(legend_items):
            ly = self.HEIGHT - 80 + (i * 22)
            svg_parts.append(f"""  <circle cx="30" cy="{ly}"
    r="8" fill="{color}" fill-opacity="0.85"/>
  <text x="45" y="{ly+4}"
    fill="#888888" font-size="11">
    {label}
  </text>
""")

        svg_parts.append("</svg>")
        return "".join(svg_parts)


# ── HTML Graph ────────────────────────────────────────────────
class HTMLGraphGenerator:
    """
    Generates an interactive HTML attack graph
    using SVG with hover effects.
    """

    def generate(self, nodes, edges, scan_data, target_name):
        """Generates interactive HTML attack graph."""

        summary  = scan_data.get("summary", {})
        svg_gen  = SVGGraphGenerator()
        svg      = svg_gen.generate(nodes, edges, f"Attack Graph — {target_name}")

        # Build node info for JavaScript
        node_info = {}
        for nid, node in nodes.items():
            node_info[nid] = {
                "label"   : node.label,
                "type"    : node.node_type,
                "severity": node.severity,
                "color"   : node.color
            }

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Attack Graph — {target_name}</title>
    <style>
        body {{
            background: #0f1117;
            color: white;
            font-family: 'Segoe UI', sans-serif;
            margin: 0;
            padding: 20px;
        }}
        h1 {{ color: white; font-size: 24px; margin-bottom: 8px; }}
        .subtitle {{ color: #888; margin-bottom: 20px; font-size: 14px; }}
        .stats {{
            display: flex;
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat {{
            background: #1a1d27;
            border: 1px solid #2a2d3a;
            border-radius: 8px;
            padding: 12px 20px;
            text-align: center;
        }}
        .stat-num {{
            font-size: 28px;
            font-weight: 700;
        }}
        .stat-label {{
            color: #888;
            font-size: 12px;
        }}
        .graph-container {{
            background: #1a1d27;
            border: 1px solid #2a2d3a;
            border-radius: 12px;
            padding: 20px;
            display: inline-block;
        }}
        .footer {{
            margin-top: 20px;
            color: #555;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <h1>🔐 Attack Graph</h1>
    <p class="subtitle">Target : {target_name} — {scan_data.get('scan_date', '')}</p>

    <div class="stats">
        <div class="stat">
            <div class="stat-num" style="color:#C0392B">
                {summary.get('critical', 0)}
            </div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color:#E67E22">
                {summary.get('high', 0)}
            </div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color:#2ECC71">
                {summary.get('security_score', 0)}%
            </div>
            <div class="stat-label">Security Score</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color:#2E75B6">
                {len(nodes)}
            </div>
            <div class="stat-label">Graph Nodes</div>
        </div>
    </div>

    <div class="graph-container">
        {svg}
    </div>

    <div class="footer">
        Generated by LLM Scanner —
        github.com/Mahdi-EL/llm-scanner
    </div>
</body>
</html>"""
        return html


# ── Main Function ─────────────────────────────────────────────
def generate_attack_graph(
    json_path,
    output_dir ="results",
    target_name="AI Application"
):
    """
    Generates attack graph visualizations from scan results.
    Creates both SVG and HTML files.
    """
    with open(json_path, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    os.makedirs(output_dir, exist_ok=True)

    # Build graph
    builder      = AttackGraphBuilder(scan_data)
    nodes, edges = builder.build()

    print(f"  Graph built : {len(nodes)} nodes, {len(edges)} edges")

    base = os.path.basename(json_path).replace(".json", "")

    # Generate SVG
    svg_gen  = SVGGraphGenerator()
    svg      = svg_gen.generate(nodes, edges, f"Attack Graph — {target_name}")
    svg_path = os.path.join(output_dir, f"{base}_graph.svg")

    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"  SVG graph : {svg_path}")

    # Generate HTML
    html_gen  = HTMLGraphGenerator()
    html      = html_gen.generate(nodes, edges, scan_data, target_name)
    html_path = os.path.join(output_dir, f"{base}_graph.html")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  HTML graph : {html_path}")

    return svg_path, html_path


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Attack Graph Generator"
    )
    parser.add_argument(
        "--input",  required=True,
        help="Path to scan results JSON"
    )
    parser.add_argument(
        "--target", default="AI Application"
    )
    parser.add_argument(
        "--output", default="results"
    )

    args = parser.parse_args()

    svg_path, html_path = generate_attack_graph(
        json_path  =args.input,
        output_dir =args.output,
        target_name=args.target
    )

    print(f"\nOpen the graph :")
    print(f"  {html_path}")
    