import logging
from security.audit_logger import (
    log_login_success,
    log_login_failure,
    log_logout,
    log_register,
    log_mfa_success,
    log_mfa_failure,
    log_authz_denied,
    log_authz_csrf_blocked,
    log_admin_action,
    log_rate_limited,
    log_ssrf_blocked,
    log_upload_rejected,
    log_upload_accepted,
    log_webhook_delivery_failed,
    log_webhook_ssrf_blocked,
    log_config_error,
    log_startup_warning,
)


def test_audit_logger_events(caplog):
    with caplog.at_level(logging.DEBUG, logger="security"):
        log_login_success("u123", "admin", "127.0.0.1")
        log_login_failure("bad_pass", "example.com", "u123", "127.0.0.1")
        log_logout("u123", "127.0.0.1")
        log_register("u123", "user", "127.0.0.1")
        log_mfa_success("u123")
        log_mfa_failure("u123", "expired_code")
        log_authz_denied("u123", "incident", "delete", "not owner")
        log_authz_csrf_blocked("/api/update", "http://evil.com")
        log_admin_action("admin1", "promote_user", "u123")
        log_rate_limited("127.0.0.1", "/auth/login")
        log_ssrf_blocked("169.254.169.254", "metadata ip", "127.0.0.1")
        log_upload_rejected("invalid extension", "malware.exe", 1024, "127.0.0.1")
        log_upload_accepted("clean.eml", 2048, "message/rfc822")
        log_webhook_delivery_failed("sub1", "incident.created", 1, "connection timeout")
        log_webhook_ssrf_blocked("sub1", "127.0.0.1")
        log_config_error("auth", "Missing secret key in production")
        log_startup_warning("database", "Using in-memory user repository")

    records = [r.message for r in caplog.records]
    assert any("AUTH_LOGIN_SUCCESS" in r for r in records)
    assert any("AUTH_LOGIN_FAILED" in r for r in records)
    assert any("AUTH_LOGOUT" in r for r in records)
    assert any("AUTH_REGISTER" in r for r in records)
    assert any("AUTH_MFA_SUCCESS" in r for r in records)
    assert any("AUTH_MFA_FAILED" in r for r in records)
    assert any("AUTHZ_DENIED" in r for r in records)
    assert any("AUTHZ_CSRF_BLOCKED" in r for r in records)
    assert any("ADMIN_ACTION" in r for r in records)
    assert any("RATE_LIMIT_HIT" in r for r in records)
    assert any("SSRF_BLOCKED" in r for r in records)
    assert any("UPLOAD_REJECTED" in r for r in records)
    assert any("UPLOAD_ACCEPTED" in r for r in records)
    assert any("WEBHOOK_DELIVERY_FAILED" in r for r in records)
    assert any("WEBHOOK_SSRF_BLOCKED" in r for r in records)
    assert any("CONFIG_ERROR" in r for r in records)
    assert any("STARTUP_WARNING" in r for r in records)
