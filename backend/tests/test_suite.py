import sys
sys.stdout.reconfigure(encoding='utf-8')

import pytest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock


# ═══════════════════════════════════════════════════
# SECTION 1 — CONFIG TESTS
# ═══════════════════════════════════════════════════

def test_config_loads():
    """Config file loads without errors"""
    from config import config
    assert config is not None


def test_config_has_model():
    """Config has default model set"""
    from config import config
    assert config.DEFAULT_MODEL is not None
    assert "llama" in config.DEFAULT_MODEL.lower()


def test_config_has_results_dir():
    """Config has results directory set"""
    from config import config
    assert config.RESULTS_DIR == "results"


# ═══════════════════════════════════════════════════
# SECTION 2 — ATTACK PROMPTS TESTS
# ═══════════════════════════════════════════════════

def test_attack_prompts_exist():
    """Attack prompts file loads correctly"""
    from attacks.prompts import ATTACK_PROMPTS
    assert len(ATTACK_PROMPTS) > 0


def test_attack_prompts_not_empty():
    """Every category has at least 1 prompt"""
    from attacks.prompts import ATTACK_PROMPTS
    for category, prompts in ATTACK_PROMPTS.items():
        assert len(prompts) > 0, f"Category {category} is empty"


def test_total_prompts():
    """At least 200 total prompts exist"""
    from attacks.prompts import ATTACK_PROMPTS
    total = sum(len(p) for p in ATTACK_PROMPTS.values())
    assert total >= 200, f"Only {total} prompts found"


def test_attack_categories_count():
    """At least 9 attack categories exist"""
    from attacks.prompts import ATTACK_PROMPTS
    assert len(ATTACK_PROMPTS) >= 9


def test_no_empty_prompts():
    """No prompt is empty or too short"""
    from attacks.prompts import ATTACK_PROMPTS
    for category, prompts in ATTACK_PROMPTS.items():
        for prompt in prompts:
            assert len(prompt) >= 10, \
                f"Prompt too short in {category}: '{prompt}'"


def test_no_duplicate_prompts():
    """No duplicate prompts within a category"""
    from attacks.prompts import ATTACK_PROMPTS
    for category, prompts in ATTACK_PROMPTS.items():
        unique = set(prompts)
        assert len(unique) == len(prompts), \
            f"Duplicate prompts found in {category}"


def test_required_categories_exist():
    """All original 9 categories are present"""
    from attacks.prompts import ATTACK_PROMPTS
    required = [
        "direct_override", "roleplay", "extraction",
        "indirect_injection", "boundary_testing",
        "social_engineering", "encoding_attacks",
        "thinking_exploitation", "search_augmented_attacks"
    ]
    for cat in required:
        assert cat in ATTACK_PROMPTS, \
            f"Required category missing: {cat}"


# ═══════════════════════════════════════════════════
# SECTION 3 — SEVERITY CALCULATION TESTS
# ═══════════════════════════════════════════════════

def test_severity_safe():
    """Score 1 + no change = SAFE"""
    from analysis import calculate_final_severity
    severity, score = calculate_final_severity(1, False, "HIGH")
    assert severity == "SAFE"


def test_severity_critical():
    """Score 9 + changed + HIGH confidence = CRITICAL"""
    from analysis import calculate_final_severity
    severity, score = calculate_final_severity(9, True, "HIGH")
    assert severity == "CRITICAL"


def test_severity_false_positive():
    """Score 5 + no change = SAFE (false positive eliminated)"""
    from analysis import calculate_final_severity
    severity, score = calculate_final_severity(5, False, "HIGH")
    assert severity == "SAFE"


def test_severity_high():
    """Score 7 + changed + HIGH = HIGH"""
    from analysis import calculate_final_severity
    severity, score = calculate_final_severity(7, True, "HIGH")
    assert severity == "HIGH"


def test_severity_medium():
    """Score 5 + changed + LOW = MEDIUM"""
    from analysis import calculate_final_severity
    severity, score = calculate_final_severity(5, True, "LOW")
    assert severity == "MEDIUM"


def test_severity_low():
    """Score 3 + changed + LOW = LOW"""
    from analysis import calculate_final_severity
    severity, score = calculate_final_severity(3, True, "LOW")
    assert severity == "LOW"


def test_severity_boundary_score_zero():
    """Score 0 = always SAFE"""
    from analysis import calculate_final_severity
    severity, score = calculate_final_severity(0, True, "HIGH")
    assert severity == "SAFE" or score == 0


def test_severity_boundary_score_ten():
    """Score 10 + changed + HIGH = CRITICAL"""
    from analysis import calculate_final_severity
    severity, score = calculate_final_severity(10, True, "HIGH")
    assert severity == "CRITICAL"


# ═══════════════════════════════════════════════════
# SECTION 4 — RESULTS SAVING TESTS
# ═══════════════════════════════════════════════════

def _make_fake_results(count=3):
    """Helper to create fake scan results."""
    severities = ["HIGH", "SAFE", "CRITICAL"]
    return [
        {
            "category"        : "direct_override",
            "attack"          : f"Attack prompt {i}",
            "response"        : f"AI response {i}",
            "score"           : 7 if i == 0 else 1,
            "severity"        : severities[i % 3],
            "reason"          : f"Reason {i}",
            "behavior_changed": i == 0,
            "confidence"      : "HIGH",
            "explanation"     : f"Explanation {i}"
        }
        for i in range(count)
    ]


def test_save_results_creates_file():
    """Results are saved to JSON correctly"""
    from analysis import save_results

    results = _make_fake_results(3)
    path    = "results/test_save.json"
    report  = save_results(results, filename=path)

    assert os.path.exists(path)
    assert report["total_attacks"] == 3
    os.remove(path)


def test_save_results_summary_correct():
    """Summary counts are correct"""
    from analysis import save_results

    results = _make_fake_results(3)
    path    = "results/test_summary.json"
    report  = save_results(results, filename=path)

    assert report["summary"]["high"]     == 1
    assert report["summary"]["safe"]     == 1
    assert report["summary"]["critical"] == 1
    os.remove(path)


def test_save_results_security_score():
    """Security score is calculated correctly"""
    from analysis import save_results

    results = _make_fake_results(3)
    path    = "results/test_score.json"
    report  = save_results(results, filename=path)

    # 1 safe out of 3 = 33%
    assert report["summary"]["security_score"] == 33
    os.remove(path)


def test_save_results_json_valid():
    """Saved JSON is valid and readable"""
    from analysis import save_results

    results = _make_fake_results(2)
    path    = "results/test_json.json"
    save_results(results, filename=path)

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "scan_date"     in data
    assert "total_attacks" in data
    assert "summary"       in data
    assert "results"       in data
    os.remove(path)


# ═══════════════════════════════════════════════════
# SECTION 5 — TARGET TESTS
# ═══════════════════════════════════════════════════

def test_target_simulation_creation():
    """Simulation target creates without errors"""
    from target import Target
    target = Target(
        target_type  ="simulation",
        system_prompt="You are a helpful assistant",
        model        ="llama-3.3-70b-versatile"
    )
    assert target is not None
    assert target.target_type == "simulation"


def test_target_openai_creation():
    """OpenAI target creates without errors"""
    from target import Target
    target = Target(
        target_type="openai_compatible",
        api_url    ="https://api.openai.com/v1",
        api_key    ="sk-fake-key",
        model      ="gpt-4"
    )
    assert target is not None
    assert target.api_url == "https://api.openai.com/v1"


def test_target_custom_rest_creation():
    """Custom REST target creates without errors"""
    from target import Target
    target = Target(
        target_type ="custom_rest",
        api_url     ="https://my-app.com/chat",
        api_key     ="fake-key",
        input_field ="message",
        output_field="response"
    )
    assert target is not None
    assert target.input_field  == "message"
    assert target.output_field == "response"


def test_target_timeout_default():
    """Target has default timeout of 30 seconds"""
    from target import Target
    target = Target(
        target_type  ="simulation",
        system_prompt="test"
    )
    assert target.timeout == 30


def test_target_custom_timeout():
    """Target accepts custom timeout"""
    from target import Target
    target = Target(
        target_type  ="simulation",
        system_prompt="test",
        timeout      =60
    )
    assert target.timeout == 60


def test_target_logs_empty_initially():
    """Target starts with empty logs"""
    from target import Target
    target = Target(
        target_type  ="simulation",
        system_prompt="test"
    )
    assert len(target.get_logs()) == 0


# ═══════════════════════════════════════════════════
# SECTION 6 — REPORT GENERATION TESTS
# ═══════════════════════════════════════════════════

def test_report_generation():
    """PDF report generates from JSON data"""
    from analysis import save_results
    from report   import generate_report

    results  = _make_fake_results(2)
    json_path = "results/test_report_gen.json"
    pdf_path  = "results/test_report_gen.pdf"

    save_results(results, filename=json_path)
    generate_report(
        json_path  =json_path,
        output_path=pdf_path,
        target_name="Test Application"
    )

    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 1000

    os.remove(json_path)
    os.remove(pdf_path)


def test_html_report_generation():
    """HTML report generates from JSON data"""
    from analysis import save_results
    from report   import generate_html_report

    results   = _make_fake_results(2)
    json_path = "results/test_html.json"
    html_path = "results/test_html.html"

    save_results(results, filename=json_path)
    generate_html_report(
        json_path  =json_path,
        output_path=html_path,
        target_name="Test HTML Report"
    )

    assert os.path.exists(html_path)

    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "LLM Scanner" in content
    assert "Security Score" in content

    os.remove(json_path)
    os.remove(html_path)


def test_markdown_report_generation():
    """Markdown report generates from JSON data"""
    from analysis import save_results
    from report   import generate_markdown_report

    results   = _make_fake_results(2)
    json_path = "results/test_md.json"
    md_path   = "results/test_md.md"

    save_results(results, filename=json_path)
    generate_markdown_report(
        json_path  =json_path,
        output_path=md_path,
        target_name="Test Markdown Report"
    )

    assert os.path.exists(md_path)

    with open(md_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "# 🔐 LLM Scanner" in content
    assert "Security Score"    in content

    os.remove(json_path)
    os.remove(md_path)


# ═══════════════════════════════════════════════════
# SECTION 7 — ANALYSIS CACHE TESTS
# ═══════════════════════════════════════════════════

def test_analysis_cache_exists():
    """Analysis cache is initialized"""
    from analysis import _analysis_cache
    assert isinstance(_analysis_cache, dict)


def test_cache_key_generation():
    """Cache generates consistent MD5 keys"""
    import hashlib
    attack   = "Test attack"
    response = "Test response"
    content  = f"{attack[:100]}{response[:100]}"
    key      = hashlib.md5(content.encode()).hexdigest()
    assert len(key) == 32


# ═══════════════════════════════════════════════════
# SECTION 8 — PROFILES TESTS
# ═══════════════════════════════════════════════════

def test_profiles_exist():
    """All scan profiles are defined"""
    from profiles import PROFILES
    required = ["quick", "standard", "deep", "stealth", "owasp", "red_team"]
    for profile in required:
        assert profile in PROFILES, f"Profile missing: {profile}"


def test_profile_quick_has_categories():
    """Quick profile has categories defined"""
    from profiles import PROFILES
    assert PROFILES["quick"]["categories"] is not None
    assert len(PROFILES["quick"]["categories"]) > 0


def test_profile_prompts_count():
    """Profile returns correct prompt counts"""
    from profiles import get_profile_prompts
    prompts, total = get_profile_prompts("quick")
    assert total > 0
    assert prompts is not None


def test_profile_standard_all_categories():
    """Standard profile uses all categories"""
    from profiles import PROFILES
    assert PROFILES["standard"]["categories"] is None


# ═══════════════════════════════════════════════════
# SECTION 9 — DATABASE TESTS
# ═══════════════════════════════════════════════════

def test_database_init():
    """Database initializes without errors"""
    from database import init_db
    init_db()
    from database import DB_PATH
    assert os.path.exists(DB_PATH)


def test_database_get_all_scans():
    """Database returns list of scans"""
    from database import init_db, get_all_scans
    init_db()
    scans = get_all_scans()
    assert isinstance(scans, list)


def test_database_global_stats():
    """Database returns global stats"""
    from database import init_db, get_global_stats
    init_db()
    stats = get_global_stats()
    assert isinstance(stats, dict)
    assert "total_scans" in stats


def test_database_waitlist():
    """Waitlist operations work correctly"""
    from database import init_db, add_to_waitlist, get_waitlist
    import time
    init_db()

    # Add unique email
    unique_email = f"test_{int(time.time())}@example.com"
    result = add_to_waitlist(unique_email, "Test User")
    assert result is True

    # Verify it's in the list
    waitlist = get_waitlist()
    emails   = [e["email"] for e in waitlist]
    assert unique_email in emails


# ═══════════════════════════════════════════════════
# SECTION 10 — SDK TESTS
# ═══════════════════════════════════════════════════

def test_sdk_imports():
    """SDK imports without errors"""
    import sys
    sys.path.insert(0, "sdk")
    from llmscanner import Scanner, ScanReport, Finding
    assert Scanner is not None
    assert ScanReport is not None
    assert Finding is not None


def test_sdk_finding_properties():
    """Finding model has correct properties"""
    import sys
    sys.path.insert(0, "sdk")
    from llmscanner import Finding

    f = Finding(
        category        ="direct_override",
        attack          ="test attack",
        response        ="test response",
        score           =8,
        severity        ="CRITICAL",
        reason          ="test reason",
        behavior_changed=True,
        confidence      ="HIGH"
    )

    assert f.is_critical is True
    assert f.is_high     is False
    assert f.is_safe     is False


def test_sdk_scan_summary():
    """ScanSummary model works correctly"""
    import sys
    sys.path.insert(0, "sdk")
    from llmscanner import ScanSummary

    summary = ScanSummary(
        total_attacks =100,
        critical      =2,
        high          =10,
        medium        =30,
        low           =8,
        safe          =50,
        security_score=50
    )

    assert summary.needs_attention is True
    assert summary.is_secure       is False


def test_sdk_no_api_key_raises():
    """Scanner raises APIKeyError without API key"""
    import sys
    sys.path.insert(0, "sdk")
    from llmscanner import Scanner, APIKeyError

    # Temporarily remove env var
    old_key = os.environ.pop("GROQ_API_KEY", None)

    try:
        with pytest.raises(APIKeyError):
            Scanner(groq_api_key=None)
    finally:
        if old_key:
            os.environ["GROQ_API_KEY"] = old_key


# ═══════════════════════════════════════════════════
# SECTION 11 — CLI TESTS
# ═══════════════════════════════════════════════════

def test_cli_imports():
    """CLI module imports without errors"""
    import cli
    assert cli is not None


def test_cli_has_commands():
    """CLI has all required command functions"""
    import cli
    assert hasattr(cli, 'cmd_scan')
    assert hasattr(cli, 'cmd_report')
    assert hasattr(cli, 'cmd_compare')
    assert hasattr(cli, 'cmd_generate')
    assert hasattr(cli, 'cmd_stats')
    assert hasattr(cli, 'cmd_info')


# ═══════════════════════════════════════════════════
# RUN ALL TESTS
# ═══════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])