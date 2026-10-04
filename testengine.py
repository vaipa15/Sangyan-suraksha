from backend.main import analyze_text


def test_guaranteed_return_is_flagged():

    score, level, summary, findings, actions, urls = analyze_text(
        "Guaranteed 30% monthly return. Pay ₹10000 today.",
        "en",
    )

    assert score > 0

    assert level in [
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]

    rules = [
        finding.rule
        for finding in findings
    ]

    assert "Guaranteed returns" in rules


def test_otp_request_is_critical():

    score, level, summary, findings, actions, urls = analyze_text(
        "Please share your OTP to verify your account.",
        "en",
    )

    assert score >= 35

    rules = [
        finding.rule
        for finding in findings
    ]

    assert "OTP / credential request" in rules


def test_url_extraction():

    score, level, summary, findings, actions, urls = analyze_text(
        "Visit https://example.com/login now.",
        "en",
    )

    assert "https://example.com/login" in urls
