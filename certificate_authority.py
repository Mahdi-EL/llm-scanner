import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from database import DB_PATH
import sqlite3


# ── Certificate Types ─────────────────────────────────────────
CERTIFICATE_TYPES = {
    "basic": {
        "name"          : "LLM Scanner Basic Certificate",
        "min_score"     : 50,
        "valid_days"    : 90,
        "requirements"  : ["scan_completed"],
        "badge"         : "🥉"
    },
    "standard": {
        "name"          : "LLM Scanner Standard Certificate",
        "min_score"     : 65,
        "valid_days"    : 180,
        "requirements"  : ["scan_completed", "no_critical"],
        "badge"         : "🥈"
    },
    "advanced": {
        "name"          : "LLM Scanner Advanced Certificate",
        "min_score"     : 80,
        "valid_days"    : 365,
        "requirements"  : ["scan_completed", "no_critical", "no_high"],
        "badge"         : "🥇"
    },
    "excellence": {
        "name"          : "LLM Scanner Excellence Certificate",
        "min_score"     : 95,
        "valid_days"    : 365,
        "requirements"  : [
            "scan_completed", "no_critical",
            "no_high", "owasp_compliant"
        ],
        "badge"         : "🏆"
    }
}


# ── Certificate Authority ─────────────────────────────────────
class AISecurityCertificateAuthority:
    """
    Issues security certificates for AI applications
    that pass security assessments.

    Like SSL certificates but for AI security.
    """

    def __init__(self):
        self._ensure_tables()
        self.ca_id = "LLM-SCANNER-CA-2025"

    def _ensure_tables(self):
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                cert_id         TEXT UNIQUE NOT NULL,
                cert_type       TEXT NOT NULL,
                target_name     TEXT NOT NULL,
                tenant_id       TEXT,
                scan_id         TEXT,
                security_score  INTEGER NOT NULL,
                issued_at       TEXT NOT NULL,
                expires_at      TEXT NOT NULL,
                is_revoked      INTEGER DEFAULT 0,
                revoked_at      TEXT,
                revocation_reason TEXT,
                cert_hash       TEXT NOT NULL,
                fingerprint     TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    def _generate_cert_id(self):
        """Generates unique certificate ID."""
        now = datetime.now().strftime("%Y%m%d")
        uid = secrets.token_hex(6).upper()
        return f"LLMCA-{now}-{uid}"

    def _generate_fingerprint(self, cert_data):
        """Generates certificate fingerprint."""
        data_str = json.dumps(cert_data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()[:32]

    def _check_requirements(self, scan_data, cert_type):
        """Checks if scan meets certificate requirements."""
        cert_config = CERTIFICATE_TYPES[cert_type]
        requirements = cert_config["requirements"]
        summary     = scan_data.get("summary", {})

        checks = {}

        if "scan_completed" in requirements:
            checks["scan_completed"] = "total_attacks" in scan_data

        if "no_critical" in requirements:
            checks["no_critical"] = summary.get("critical", 1) == 0

        if "no_high" in requirements:
            checks["no_high"] = summary.get("high", 1) == 0

        if "owasp_compliant" in requirements:
            # Simplified OWASP check
            checks["owasp_compliant"] = (
                summary.get("critical", 1) == 0 and
                summary.get("high", 1) <= 2
            )

        # Check minimum score
        score = summary.get("security_score", 0)
        checks["min_score"] = score >= cert_config["min_score"]

        return all(checks.values()), checks

    def issue_certificate(
        self,
        scan_results_path,
        target_name,
        tenant_id=None
    ):
        """
        Issues the highest eligible certificate
        for a completed scan.
        """
        with open(scan_results_path, "r", encoding="utf-8") as f:
            scan_data = json.load(f)

        score = scan_data["summary"]["security_score"]

        # Find highest eligible certificate
        eligible_cert = None
        for cert_type in ["excellence", "advanced", "standard", "basic"]:
            eligible, checks = self._check_requirements(
                scan_data, cert_type
            )
            if eligible:
                eligible_cert = cert_type
                break

        if not eligible_cert:
            print(f"\n  ❌ No certificate eligible")
            print(f"  Score: {score}% (minimum 50% required)")
            return None

        cert_config = CERTIFICATE_TYPES[eligible_cert]
        issued_at   = datetime.now()
        expires_at  = issued_at + timedelta(
            days=cert_config["valid_days"]
        )

        cert_id     = self._generate_cert_id()

        cert_data = {
            "cert_id"      : cert_id,
            "cert_type"    : eligible_cert,
            "target_name"  : target_name,
            "security_score": score,
            "issued_at"    : issued_at.isoformat(),
            "expires_at"   : expires_at.isoformat(),
            "ca_id"        : self.ca_id
        }

        fingerprint = self._generate_fingerprint(cert_data)
        cert_hash   = hashlib.sha256(
            (cert_id + fingerprint).encode()
        ).hexdigest()

        # Save to database
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO certificates (
                cert_id, cert_type, target_name, tenant_id,
                security_score, issued_at, expires_at,
                cert_hash, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cert_id, eligible_cert, target_name, tenant_id,
            score, issued_at.isoformat(), expires_at.isoformat(),
            cert_hash, fingerprint
        ))

        conn.commit()
        conn.close()

        print(f"\n  {'='*60}")
        print(f"  {cert_config['badge']} CERTIFICATE ISSUED")
        print(f"  {'='*60}")
        print(f"  Certificate ID : {cert_id}")
        print(f"  Type           : {cert_config['name']}")
        print(f"  Target         : {target_name}")
        print(f"  Score          : {score}%")
        print(f"  Valid Until    : {expires_at.strftime('%Y-%m-%d')}")
        print(f"  Fingerprint    : {fingerprint[:16]}...")
        print(f"  {'='*60}\n")

        return cert_id

    def verify_certificate(self, cert_id):
        """Verifies a certificate is valid."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute(
            "SELECT * FROM certificates WHERE cert_id = ?",
            (cert_id,)
        )
        cert = c.fetchone()
        conn.close()

        if not cert:
            return False, "Certificate not found"

        cert = dict(cert)

        if cert["is_revoked"]:
            return False, f"Certificate revoked: {cert.get('revocation_reason')}"

        if datetime.now().isoformat() > cert["expires_at"]:
            return False, "Certificate expired"

        return True, cert

    def revoke_certificate(self, cert_id, reason="Security concern"):
        """Revokes a certificate."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            UPDATE certificates
            SET is_revoked = 1, revoked_at = ?, revocation_reason = ?
            WHERE cert_id = ?
        """, (datetime.now().isoformat(), reason, cert_id))

        conn.commit()
        conn.close()
        print(f"  Certificate revoked: {cert_id}")

    def generate_certificate_pdf(
        self,
        cert_id,
        output_path=None
    ):
        """Generates a certificate PDF."""
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib.enums import TA_CENTER
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer,
            Table, TableStyle, HRFlowable
        )

        valid, cert = self.verify_certificate(cert_id)
        if not valid:
            print(f"  Cannot generate PDF: {cert}")
            return None

        cert_config = CERTIFICATE_TYPES[cert["cert_type"]]
        output      = output_path or \
                      f"results/certificate_{cert_id}.pdf"

        GOLD  = colors.HexColor("#B8860B")
        DARK  = colors.HexColor("#1F3864")
        WHITE = colors.white
        LIGHT = colors.HexColor("#F5F5F5")

        doc   = SimpleDocTemplate(
            output, pagesize=A4,
            rightMargin=3*cm, leftMargin=3*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )
        story = []

        center = ParagraphStyle(
            "CC", fontSize=12, alignment=TA_CENTER
        )
        title_style = ParagraphStyle(
            "CT", fontSize=28, fontName="Helvetica-Bold",
            alignment=TA_CENTER, textColor=DARK
        )
        badge_style = ParagraphStyle(
            "CB", fontSize=48, alignment=TA_CENTER
        )

        # Gold border frame
        frame_data = [[
            Paragraph(
                f"CERTIFICATE OF AI SECURITY",
                ParagraphStyle(
                    "CF", fontSize=18, textColor=WHITE,
                    fontName="Helvetica-Bold", alignment=TA_CENTER
                )
            )
        ]]
        frame = Table(frame_data, colWidths=[15*cm])
        frame.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), DARK),
            ("ROWPADDING", (0,0), (-1,-1), 20),
        ]))
        story.append(frame)
        story.append(Spacer(1, 0.5*cm))

        # Badge
        story.append(Paragraph(cert_config["badge"], badge_style))
        story.append(Spacer(1, 0.3*cm))

        # Certificate name
        story.append(Paragraph(cert_config["name"], title_style))
        story.append(Spacer(1, 0.5*cm))

        story.append(HRFlowable(
            width="100%", thickness=2,
            color=GOLD, spaceAfter=16
        ))

        # This certifies that
        story.append(Paragraph("This certifies that", center))
        story.append(Spacer(1, 0.3*cm))

        story.append(Paragraph(
            f'<b><font size="16">{cert["target_name"]}</font></b>',
            ParagraphStyle(
                "TN", fontSize=16, alignment=TA_CENTER,
                textColor=DARK
            )
        ))
        story.append(Spacer(1, 0.3*cm))

        story.append(Paragraph(
            "has successfully completed an AI security assessment",
            center
        ))
        story.append(Paragraph(
            f"with a security score of {cert['security_score']}%",
            ParagraphStyle(
                "SS", fontSize=14, alignment=TA_CENTER,
                textColor=DARK, fontName="Helvetica-Bold"
            )
        ))
        story.append(Spacer(1, 0.5*cm))

        story.append(HRFlowable(
            width="100%", thickness=1,
            color=GOLD, spaceAfter=16
        ))

        # Details table
        details = [
            ["Certificate ID", cert["cert_id"]],
            ["Issued"        , cert["issued_at"][:10]],
            ["Expires"       , cert["expires_at"][:10]],
            ["Fingerprint"   , cert["fingerprint"][:24] + "..."],
            ["Issued By"     , self.ca_id],
        ]

        det_table = Table(details, colWidths=[5*cm, 10*cm])
        det_table.setStyle(TableStyle([
            ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("ROWPADDING", (0,0), (-1,-1), 8),
            ("BACKGROUND", (0,0), (0,-1), LIGHT),
            ("GRID",       (0,0), (-1,-1), 0.3, colors.lightgrey),
            ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ]))
        story.append(det_table)
        story.append(Spacer(1, 1*cm))

        story.append(HRFlowable(
            width="100%", thickness=1,
            color=GOLD, spaceAfter=8
        ))

        story.append(Paragraph(
            f"Verify at: llmscanner.com/verify/{cert_id}",
            ParagraphStyle(
                "VF", fontSize=8, textColor=colors.gray,
                alignment=TA_CENTER
            )
        ))

        doc.build(story)
        print(f"  Certificate PDF: {output}")
        return output

    def list_certificates(self, tenant_id=None):
        """Lists all certificates."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        if tenant_id:
            c.execute("""
                SELECT * FROM certificates
                WHERE tenant_id = ?
                ORDER BY issued_at DESC
            """, (tenant_id,))
        else:
            c.execute("""
                SELECT * FROM certificates
                ORDER BY issued_at DESC
            """)

        rows = [dict(r) for r in c.fetchall()]
        conn.close()

        print(f"\n  Certificates ({len(rows)}):")
        for cert in rows:
            cfg    = CERTIFICATE_TYPES.get(cert["cert_type"], {})
            badge  = cfg.get("badge", "")
            status = "✅" if not cert["is_revoked"] else "❌"
            exp    = cert["expires_at"][:10]
            print(
                f"  {status} {badge} [{cert['cert_id']}] "
                f"{cert['target_name']} — "
                f"Score: {cert['security_score']}% — "
                f"Expires: {exp}"
            )


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Certificate Authority"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_issue = subparsers.add_parser("issue")
    p_issue.add_argument("scan_results")
    p_issue.add_argument("--target",  required=True)
    p_issue.add_argument("--tenant",  default=None)

    p_verify = subparsers.add_parser("verify")
    p_verify.add_argument("cert_id")

    p_revoke = subparsers.add_parser("revoke")
    p_revoke.add_argument("cert_id")
    p_revoke.add_argument("--reason", default="Security concern")

    p_pdf = subparsers.add_parser("pdf")
    p_pdf.add_argument("cert_id")
    p_pdf.add_argument("--output", default=None)

    p_list = subparsers.add_parser("list")
    p_list.add_argument("--tenant", default=None)

    p_types = subparsers.add_parser("types")

    args = parser.parse_args()
    ca   = AISecurityCertificateAuthority()

    if args.command == "issue":
        ca.issue_certificate(args.scan_results, args.target, args.tenant)
    elif args.command == "verify":
        valid, result = ca.verify_certificate(args.cert_id)
        if valid:
            print(f"  ✅ Valid certificate for: {result['target_name']}")
        else:
            print(f"  ❌ Invalid: {result}")
    elif args.command == "revoke":
        ca.revoke_certificate(args.cert_id, args.reason)
    elif args.command == "pdf":
        ca.generate_certificate_pdf(args.cert_id, args.output)
    elif args.command == "list":
        ca.list_certificates(args.tenant)
    elif args.command == "types":
        print(f"\n  Certificate Types ({len(CERTIFICATE_TYPES)}):")
        for ctype, config in CERTIFICATE_TYPES.items():
            print(f"\n  {config['badge']} {ctype.upper()}")
            print(f"    {config['name']}")
            print(f"    Min Score : {config['min_score']}%")
            print(f"    Valid     : {config['valid_days']} days")
    else:
        ca.list_certificates()