import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
from datetime import datetime
from database import DB_PATH
import sqlite3


# ── Knowledge Graph ───────────────────────────────────────────
class AISecurityKnowledgeGraph:
    """
    Builds a knowledge graph of AI security relationships.
    Connects: attacks → categories → defenses → vulnerabilities
    Enables graph-based security reasoning.
    """

    def __init__(self):
        self._ensure_tables()
        self._seed_graph()

    def _ensure_tables(self):
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS kg_nodes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id    TEXT UNIQUE NOT NULL,
                node_type  TEXT NOT NULL,
                label      TEXT NOT NULL,
                properties TEXT,
                created_at TEXT NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS kg_edges (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                edge_id     TEXT UNIQUE NOT NULL,
                source_id   TEXT NOT NULL,
                target_id   TEXT NOT NULL,
                relation    TEXT NOT NULL,
                weight      REAL DEFAULT 1.0,
                properties  TEXT,
                created_at  TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    def _seed_graph(self):
        """Seeds the knowledge graph with core security knowledge."""
        # Attack categories
        categories = [
            ("cat_direct_override",     "category", "Direct Override"),
            ("cat_extraction",          "category", "Extraction"),
            ("cat_social_engineering",  "category", "Social Engineering"),
            ("cat_roleplay",            "category", "Roleplay"),
            ("cat_encoding",            "category", "Encoding Attacks"),
            ("cat_prompt_chaining",     "category", "Prompt Chaining"),
            ("cat_few_shot",            "category", "Few-Shot Poisoning"),
            ("cat_context_window",      "category", "Context Window Attacks"),
            ("cat_indirect_injection",  "category", "Indirect Injection"),
            ("cat_boundary_testing",    "category", "Boundary Testing"),
        ]

        # Attack techniques
        techniques = [
            ("tech_dan",          "technique", "DAN Jailbreak"),
            ("tech_skeleton_key", "technique", "Skeleton Key Attack"),
            ("tech_crescendo",    "technique", "Crescendo Attack"),
            ("tech_base64",       "technique", "Base64 Encoding"),
            ("tech_grandma",      "technique", "Grandma Exploit"),
            ("tech_developer",    "technique", "Developer Mode Claim"),
            ("tech_researcher",   "technique", "Research Claim"),
            ("tech_many_shot",    "technique", "Many-Shot Jailbreaking"),
        ]

        # Defenses
        defenses = [
            ("def_anti_override",  "defense", "Anti-Override Rules"),
            ("def_confidentiality","defense", "Confidentiality Rules"),
            ("def_role_enforcement","defense","Role Enforcement"),
            ("def_input_validation","defense","Input Validation"),
            ("def_output_filtering","defense","Output Filtering"),
            ("def_rate_limiting",  "defense", "Rate Limiting"),
            ("def_monitoring",     "defense", "Security Monitoring"),
        ]

        # Vulnerabilities
        vulnerabilities = [
            ("vuln_prompt_injection", "vulnerability", "Prompt Injection",     "CRITICAL"),
            ("vuln_data_leakage",     "vulnerability", "Data Leakage",         "HIGH"),
            ("vuln_jailbreak",        "vulnerability", "Jailbreak Success",     "CRITICAL"),
            ("vuln_role_confusion",   "vulnerability", "Role Confusion",        "HIGH"),
            ("vuln_filter_bypass",    "vulnerability", "Safety Filter Bypass",  "HIGH"),
        ]

        # Add all nodes
        for nodes in [categories, techniques, defenses]:
            for node_id, node_type, label in nodes:
                self.add_node(node_id, node_type, label)

        for node_id, node_type, label, *extra in vulnerabilities:
            props = {"severity": extra[0]} if extra else {}
            self.add_node(node_id, node_type, label, props)

        # Add relationships
        edges = [
            # Techniques → Categories
            ("tech_dan",          "cat_roleplay",           "belongs_to",   1.0),
            ("tech_skeleton_key", "cat_direct_override",    "belongs_to",   1.0),
            ("tech_crescendo",    "cat_prompt_chaining",    "belongs_to",   1.0),
            ("tech_base64",       "cat_encoding",           "belongs_to",   1.0),
            ("tech_grandma",      "cat_social_engineering", "belongs_to",   0.8),
            ("tech_developer",    "cat_social_engineering", "belongs_to",   0.9),
            ("tech_researcher",   "cat_social_engineering", "belongs_to",   0.9),
            ("tech_many_shot",    "cat_few_shot",           "belongs_to",   1.0),

            # Categories → Vulnerabilities
            ("cat_direct_override",    "vuln_prompt_injection", "exploits",  0.9),
            ("cat_extraction",         "vuln_data_leakage",     "exploits",  0.9),
            ("cat_roleplay",           "vuln_jailbreak",        "exploits",  0.8),
            ("cat_social_engineering", "vuln_role_confusion",   "exploits",  0.7),
            ("cat_encoding",           "vuln_filter_bypass",    "exploits",  0.8),

            # Defenses → Vulnerabilities (mitigates)
            ("def_anti_override",   "vuln_prompt_injection",  "mitigates",  0.8),
            ("def_confidentiality", "vuln_data_leakage",      "mitigates",  0.9),
            ("def_role_enforcement","vuln_role_confusion",    "mitigates",  0.8),
            ("def_input_validation","vuln_filter_bypass",     "mitigates",  0.7),
            ("def_output_filtering","vuln_data_leakage",      "mitigates",  0.8),
        ]

        for src, tgt, rel, weight in edges:
            self.add_edge(src, tgt, rel, weight)

    def add_node(self, node_id, node_type, label, properties=None):
        """Adds a node to the graph."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        try:
            c.execute("""
                INSERT OR IGNORE INTO kg_nodes (
                    node_id, node_type, label, properties, created_at
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                node_id, node_type, label,
                json.dumps(properties or {}),
                datetime.now().isoformat()
            ))
            conn.commit()
        finally:
            conn.close()

    def add_edge(self, source_id, target_id, relation, weight=1.0, properties=None):
        """Adds an edge to the graph."""
        import secrets

        edge_id = f"e_{secrets.token_hex(6)}"
        conn    = sqlite3.connect(DB_PATH)
        c       = conn.cursor()

        try:
            # Check if edge already exists
            c.execute("""
                SELECT id FROM kg_edges
                WHERE source_id=? AND target_id=? AND relation=?
            """, (source_id, target_id, relation))

            if not c.fetchone():
                c.execute("""
                    INSERT INTO kg_edges (
                        edge_id, source_id, target_id, relation,
                        weight, properties, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    edge_id, source_id, target_id, relation,
                    weight, json.dumps(properties or {}),
                    datetime.now().isoformat()
                ))
                conn.commit()
        finally:
            conn.close()

    def get_node(self, node_id):
        """Gets a node by ID."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute(
            "SELECT * FROM kg_nodes WHERE node_id = ?",
            (node_id,)
        )
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_neighbors(self, node_id, relation=None):
        """Gets all neighbors of a node."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        if relation:
            c.execute("""
                SELECT n.*, e.relation, e.weight
                FROM kg_edges e
                JOIN kg_nodes n ON e.target_id = n.node_id
                WHERE e.source_id = ? AND e.relation = ?
                ORDER BY e.weight DESC
            """, (node_id, relation))
        else:
            c.execute("""
                SELECT n.*, e.relation, e.weight
                FROM kg_edges e
                JOIN kg_nodes n ON e.target_id = n.node_id
                WHERE e.source_id = ?
                ORDER BY e.weight DESC
            """, (node_id,))

        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def get_defenses_for_attack(self, attack_category):
        """
        Graph traversal: attack → vulnerability → defense
        Returns recommended defenses for an attack category.
        """
        cat_id = f"cat_{attack_category.replace('-','_')}"

        # Get vulnerabilities this category exploits
        vulnerabilities = self.get_neighbors(cat_id, "exploits")

        defenses = []
        seen     = set()

        for vuln in vulnerabilities:
            # Get defenses for this vulnerability (reverse traversal)
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c    = conn.cursor()

            c.execute("""
                SELECT n.*, e.weight
                FROM kg_edges e
                JOIN kg_nodes n ON e.source_id = n.node_id
                WHERE e.target_id = ? AND e.relation = 'mitigates'
                ORDER BY e.weight DESC
            """, (vuln["node_id"],))

            for row in c.fetchall():
                defense = dict(row)
                if defense["node_id"] not in seen:
                    defense["for_vulnerability"] = vuln["label"]
                    defenses.append(defense)
                    seen.add(defense["node_id"])

            conn.close()

        return defenses

    def get_attack_path(self, technique_id, target_vuln=None):
        """Gets the attack path from technique to vulnerability."""
        tech = self.get_node(technique_id)
        if not tech:
            return []

        # Technique → Category → Vulnerability
        categories    = self.get_neighbors(technique_id, "belongs_to")
        path          = []

        for cat in categories:
            vulns = self.get_neighbors(cat["node_id"], "exploits")
            for vuln in vulns:
                if target_vuln and target_vuln not in vuln["node_id"]:
                    continue
                path.append({
                    "step1": {"type": "technique", "label": tech["label"]},
                    "step2": {"type": "category",  "label": cat["label"]},
                    "step3": {"type": "vuln",      "label": vuln["label"]},
                    "path" : f"{tech['label']} → {cat['label']} → {vuln['label']}"
                })

        return path

    def find_related_attacks(self, category):
        """Finds attacks related to the same vulnerability."""
        cat_id = f"cat_{category.replace('-','_')}"

        # Get vulnerabilities
        vulns = self.get_neighbors(cat_id, "exploits")
        related_cats = set()

        for vuln in vulns:
            # Get other categories that exploit same vuln
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()

            c.execute("""
                SELECT source_id FROM kg_edges
                WHERE target_id = ? AND relation = 'exploits'
                AND source_id != ?
            """, (vuln["node_id"], cat_id))

            for row in c.fetchall():
                related_cats.add(row[0])

            conn.close()

        return [
            cat_id.replace("cat_","").replace("_"," ")
            for cat_id in related_cats
        ]

    def get_graph_stats(self):
        """Gets knowledge graph statistics."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("SELECT COUNT(*) FROM kg_nodes")
        total_nodes = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM kg_edges")
        total_edges = c.fetchone()[0]

        c.execute("""
            SELECT node_type, COUNT(*) as count
            FROM kg_nodes GROUP BY node_type
        """)
        by_type = {r[0]: r[1] for r in c.fetchall()}

        c.execute("""
            SELECT relation, COUNT(*) as count
            FROM kg_edges GROUP BY relation
        """)
        by_relation = {r[0]: r[1] for r in c.fetchall()}

        conn.close()

        return {
            "total_nodes"  : total_nodes,
            "total_edges"  : total_edges,
            "by_type"      : by_type,
            "by_relation"  : by_relation
        }

    def generate_html_visualization(
        self,
        output_path="results/knowledge_graph.html"
    ):
        """Generates interactive HTML graph visualization."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("SELECT * FROM kg_nodes LIMIT 50")
        nodes = [dict(r) for r in c.fetchall()]

        c.execute("SELECT * FROM kg_edges LIMIT 100")
        edges = [dict(r) for r in c.fetchall()]

        conn.close()

        nodes_js = json.dumps([{
            "id"   : n["node_id"],
            "label": n["label"],
            "type" : n["node_type"]
        } for n in nodes])

        edges_js = json.dumps([{
            "source": e["source_id"],
            "target": e["target_id"],
            "label" : e["relation"],
            "weight": e["weight"]
        } for e in edges])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI Security Knowledge Graph</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0f1117;
            color: white;
        }}
        .header {{
            padding: 20px 24px;
            background: #1F3864;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{ font-size: 20px; }}
        .stats {{
            display: flex;
            gap: 24px;
            font-size: 13px;
            color: #aaa;
        }}
        .stats span b {{ color: white; }}
        canvas {{
            display: block;
            width: 100%;
            height: calc(100vh - 80px);
        }}
        .legend {{
            position: absolute;
            bottom: 20px;
            left: 20px;
            background: #1a1d27;
            border: 1px solid #2a2d3a;
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 12px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 6px;
        }}
        .dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🕸️ AI Security Knowledge Graph</h1>
        <div class="stats">
            <span>Nodes: <b>{len(nodes)}</b></span>
            <span>Edges: <b>{len(edges)}</b></span>
            <span>LLM Scanner v2.0.0</span>
        </div>
    </div>

    <canvas id="graph"></canvas>

    <div class="legend">
        <div class="legend-item">
            <div class="dot" style="background:#C0392B"></div>
            <span>Vulnerability</span>
        </div>
        <div class="legend-item">
            <div class="dot" style="background:#E67E22"></div>
            <span>Attack Category</span>
        </div>
        <div class="legend-item">
            <div class="dot" style="background:#9B59B6"></div>
            <span>Technique</span>
        </div>
        <div class="legend-item">
            <div class="dot" style="background:#27AE60"></div>
            <span>Defense</span>
        </div>
    </div>

    <script>
        const nodes = {nodes_js};
        const edges = {edges_js};

        const canvas = document.getElementById('graph');
        const ctx    = canvas.getContext('2d');

        canvas.width  = window.innerWidth;
        canvas.height = window.innerHeight - 80;

        // Assign colors
        const colors = {{
            'vulnerability': '#C0392B',
            'category'     : '#E67E22',
            'technique'    : '#9B59B6',
            'defense'      : '#27AE60',
            'default'      : '#2E75B6'
        }};

        // Simple force-directed layout (basic)
        const nodeMap = {{}};
        nodes.forEach((n, i) => {{
            const angle = (i / nodes.length) * Math.PI * 2;
            const r = Math.min(canvas.width, canvas.height) * 0.35;
            n.x = canvas.width / 2 + r * Math.cos(angle);
            n.y = canvas.height / 2 + r * Math.sin(angle);
            n.vx = 0; n.vy = 0;
            nodeMap[n.id] = n;
        }});

        // Simple force simulation
        for (let iter = 0; iter < 100; iter++) {{
            // Repulsion
            nodes.forEach(a => {{
                nodes.forEach(b => {{
                    if (a === b) return;
                    const dx = a.x - b.x, dy = a.y - b.y;
                    const d  = Math.sqrt(dx*dx + dy*dy) || 1;
                    const f  = 2000 / (d * d);
                    a.vx += f * dx/d; a.vy += f * dy/d;
                }});
            }});

            // Attraction
            edges.forEach(e => {{
                const a = nodeMap[e.source], b = nodeMap[e.target];
                if (!a || !b) return;
                const dx = b.x - a.x, dy = b.y - a.y;
                const d  = Math.sqrt(dx*dx + dy*dy) || 1;
                const f  = d / 300;
                a.vx += f * dx/d; a.vy += f * dy/d;
                b.vx -= f * dx/d; b.vy -= f * dy/d;
            }});

            // Apply + dampen + boundary
            nodes.forEach(n => {{
                n.x = Math.max(60, Math.min(canvas.width-60,  n.x + n.vx*0.1));
                n.y = Math.max(60, Math.min(canvas.height-60, n.y + n.vy*0.1));
                n.vx *= 0.8; n.vy *= 0.8;
            }});
        }}

        function draw() {{
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#0f1117';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            // Draw edges
            edges.forEach(e => {{
                const a = nodeMap[e.source], b = nodeMap[e.target];
                if (!a || !b) return;
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.lineTo(b.x, b.y);
                ctx.strokeStyle = 'rgba(255,255,255,0.1)';
                ctx.lineWidth = e.weight * 1.5;
                ctx.stroke();
            }});

            // Draw nodes
            nodes.forEach(n => {{
                const color = colors[n.type] || colors.default;
                const r     = n.type === 'vulnerability' ? 18 :
                              n.type === 'category' ? 14 : 10;

                ctx.beginPath();
                ctx.arc(n.x, n.y, r, 0, Math.PI*2);
                ctx.fillStyle = color + '33';
                ctx.fill();
                ctx.strokeStyle = color;
                ctx.lineWidth = 2;
                ctx.stroke();

                // Label
                ctx.fillStyle = 'white';
                ctx.font = '10px Segoe UI';
                ctx.textAlign = 'center';
                const label = n.label.length > 15
                    ? n.label.substring(0,12) + '...'
                    : n.label;
                ctx.fillText(label, n.x, n.y + r + 14);
            }});
        }}

        draw();

        window.addEventListener('resize', () => {{
            canvas.width  = window.innerWidth;
            canvas.height = window.innerHeight - 80;
            draw();
        }});
    </script>
</body>
</html>"""

        os.makedirs("results", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  Knowledge graph: {output_path}")
        return output_path

    def print_graph_summary(self):
        """Prints knowledge graph summary."""
        stats = self.get_graph_stats()

        print(f"\n  {'='*60}")
        print(f"  🕸️  AI SECURITY KNOWLEDGE GRAPH")
        print(f"  {'='*60}")
        print(f"  Total Nodes : {stats['total_nodes']}")
        print(f"  Total Edges : {stats['total_edges']}")
        print(f"\n  Nodes by Type:")
        for ntype, count in stats["by_type"].items():
            print(f"    {ntype:<20} : {count}")
        print(f"\n  Edges by Relation:")
        for rel, count in stats["by_relation"].items():
            print(f"    {rel:<20} : {count}")
        print(f"  {'='*60}\n")

    def query_graph(self, question):
        """
        Natural language graph query using AI.
        """
        from groq import Groq
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))

        stats = self.get_graph_stats()

        prompt = f"""You are a security knowledge graph expert.

GRAPH STRUCTURE:
- {stats['total_nodes']} nodes: vulnerabilities, categories, techniques, defenses
- {stats['total_edges']} edges: belongs_to, exploits, mitigates

USER QUESTION: {question}

Answer using graph reasoning. Reference specific nodes and relationships.
Be concise (2-3 sentences max)."""

        response = client.chat.completions.create(
            model    ="llama-3.3-70b-versatile",
            messages =[{"role": "user", "content": prompt}],
            max_tokens=200
        )

        return response.choices[0].message.content.strip()


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Security Knowledge Graph"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("stats")

    p_html = subparsers.add_parser("html")
    p_html.add_argument(
        "--output", default="results/knowledge_graph.html"
    )

    p_defend = subparsers.add_parser("defenses")
    p_defend.add_argument("category")

    p_path = subparsers.add_parser("path")
    p_path.add_argument("technique")

    p_query = subparsers.add_parser("query")
    p_query.add_argument("question")

    p_related = subparsers.add_parser("related")
    p_related.add_argument("category")

    args = parser.parse_args()
    kg   = AISecurityKnowledgeGraph()

    if args.command == "stats":
        kg.print_graph_summary()
    elif args.command == "html":
        kg.generate_html_visualization(args.output)
    elif args.command == "defenses":
        defenses = kg.get_defenses_for_attack(args.category)
        print(f"\n  Defenses for {args.category}:")
        for d in defenses:
            print(f"  → {d['label']} (for: {d.get('for_vulnerability','')})")
    elif args.command == "path":
        paths = kg.get_attack_path(f"tech_{args.technique}")
        for p in paths:
            print(f"  {p['path']}")
    elif args.command == "query":
        answer = kg.query_graph(args.question)
        print(f"\n  {answer}\n")
    elif args.command == "related":
        related = kg.find_related_attacks(args.category)
        print(f"\n  Related attacks: {', '.join(related)}")
    else:
        kg.print_graph_summary()