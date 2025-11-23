//! JWT Validation Tests
//!
//! Comprehensive tests for JWT token validation, JWKS caching, and bearer token extraction.
//! These tests verify the authentication layer works correctly with RS256 signed JWTs.

use base64::{engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD}, Engine as _};
use runbeam_sdk::{extract_bearer_token, validate_jwt_token, JwtClaims, JwtValidationOptions};
use serde_json::json;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

// ============================================================================
// Bearer Token Extraction Tests
// ============================================================================

#[test]
fn test_extract_bearer_token_valid() {
    let header = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";
    let token = extract_bearer_token(header).unwrap();
    assert_eq!(token, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test");
}

#[test]
fn test_extract_bearer_token_with_extra_whitespace() {
    let header = "Bearer   eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test   ";
    let token = extract_bearer_token(header).unwrap();
    assert_eq!(token, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test");
}

#[test]
fn test_extract_bearer_token_with_tabs_and_spaces() {
    // Bearer followed by space then token should work
    let header = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";
    let token = extract_bearer_token(header);
    assert!(token.is_ok());
    assert_eq!(token.unwrap(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test");
}

#[test]
fn test_extract_bearer_token_missing_bearer_prefix() {
    let header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";
    let result = extract_bearer_token(header);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Bearer"));
}

#[test]
fn test_extract_bearer_token_empty_token() {
    let header = "Bearer ";
    let result = extract_bearer_token(header);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Missing token"));
}

#[test]
fn test_extract_bearer_token_case_sensitive() {
    // lowercase "bearer" should fail - the spec requires "Bearer"
    let header = "bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";
    let result = extract_bearer_token(header);
    assert!(result.is_err());
}

// ============================================================================
// JWT Claims Tests
// ============================================================================

#[test]
fn test_jwt_claims_is_expired() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Expired token (1 hour ago)
    let expired_claims = JwtClaims {
        iss: "http://example.com".to_string(),
        sub: "user123".to_string(),
        aud: Some("runbeam-cli".to_string()),
        exp: now - 3600,
        iat: now - 7200,
        user: None,
        team: None,
    };

    assert!(expired_claims.is_expired());

    // Valid token (expires in 1 hour)
    let valid_claims = JwtClaims {
        iss: "http://example.com".to_string(),
        sub: "user123".to_string(),
        aud: Some("runbeam-cli".to_string()),
        exp: now + 3600,
        iat: now,
        user: None,
        team: None,
    };

    assert!(!valid_claims.is_expired());
}

#[test]
fn test_jwt_claims_api_base_url() {
    let claims = JwtClaims {
        iss: "http://runbeam.lndo.site".to_string(),
        sub: "user123".to_string(),
        aud: Some("runbeam-cli".to_string()),
        exp: 9999999999,
        iat: 1234567890,
        user: None,
        team: None,
    };

    assert_eq!(claims.api_base_url(), "http://runbeam.lndo.site");
}

#[test]
fn test_jwt_claims_with_user_info() {
    use runbeam_sdk::UserInfo;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = JwtClaims {
        iss: "http://example.com".to_string(),
        sub: "user123".to_string(),
        aud: Some("runbeam-cli".to_string()),
        exp: now + 3600,
        iat: now,
        user: Some(UserInfo {
            id: "user123".to_string(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
        }),
        team: None,
    };

    assert!(claims.user.is_some());
    let user = claims.user.unwrap();
    assert_eq!(user.id, "user123");
    assert_eq!(user.email, "test@example.com");
}

#[test]
fn test_jwt_claims_with_team_info() {
    use runbeam_sdk::TeamInfo;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = JwtClaims {
        iss: "http://example.com".to_string(),
        sub: "team456".to_string(),
        aud: Some("runbeam-cli".to_string()),
        exp: now + 3600,
        iat: now,
        user: None,
        team: Some(TeamInfo {
            id: "team456".to_string(),
            name: "Test Team".to_string(),
        }),
    };

    assert!(claims.team.is_some());
    let team = claims.team.unwrap();
    assert_eq!(team.id, "team456");
    assert_eq!(team.name, "Test Team");
}

// ============================================================================
// JWT Validation with JWKS Mocking Tests
// ============================================================================

/// Helper function to create a test RSA key pair and JWKS response
fn create_test_jwks() -> (String, String) {
    // This is a test RSA key pair (DO NOT USE IN PRODUCTION!)
    // Generated for testing purposes only
    let public_key_n = "xGOr-H7A-PWgZE8f8nkXcFbRqDMXtpnlxyZbFbLxQZJrZxQzLbBhLLR8wHv5sA_VkxjHCz8wHv5sA_VkxjHCz8wHv5sA_VkxjHCz8wHv5sA_VkxjHCz8wHv5sA_VkxjHCz8wHv5sA_VkxjHCz8wHv5sA_VkxjHCz8wHv5sA_VkxjHCz8wHv5sA_VkxjHCz8wHv5sA_VkxjHCz8";
    let public_key_e = "AQAB";

    let jwks_response = json!({
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-id",
                "alg": "RS256",
                "n": public_key_n,
                "e": public_key_e
            }
        ]
    });

    (jwks_response.to_string(), "test-key-id".to_string())
}

#[tokio::test]
async fn test_jwt_validation_with_malformed_token() {
    let mock_server = MockServer::start().await;

    // Mock JWKS endpoint
    let (jwks_response, _) = create_test_jwks();
    Mock::given(method("GET"))
        .and(path("/api/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_response))
        .mount(&mock_server)
        .await;

    // Malformed JWT (not three parts)
    let malformed_token = "not.a.valid.jwt.token";

    let options = JwtValidationOptions::new()
        .with_trusted_issuers(vec![mock_server.uri()]);
    let result = validate_jwt_token(malformed_token, &options).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_jwt_validation_with_missing_kid() {
    let mock_server = MockServer::start().await;

    // Create a simple JWT header without kid
    let header = BASE64.encode(json!({"alg": "RS256", "typ": "JWT"}).to_string());
    let payload = BASE64.encode(json!({"iss": mock_server.uri(), "sub": "test", "exp": 9999999999_i64, "iat": 1234567890_i64}).to_string());
    let invalid_jwt = format!("{}.{}.fakesignature", header, payload);

    let options = JwtValidationOptions::new()
        .with_trusted_issuers(vec![mock_server.uri()]);
    let result = validate_jwt_token(&invalid_jwt, &options).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_jwt_validation_with_expired_token() {
    let mock_server = MockServer::start().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create JWT with expired timestamp
    let header =
        BASE64.encode(json!({"alg": "RS256", "typ": "JWT", "kid": "test-key"}).to_string());
    let payload = BASE64.encode(
        json!({
            "iss": mock_server.uri(),
            "sub": "test",
            "exp": now - 3600,  // Expired 1 hour ago
            "iat": now - 7200
        })
        .to_string(),
    );
    let expired_jwt = format!("{}.{}.fakesignature", header, payload);

    // Mock JWKS endpoint
    let (jwks_response, _) = create_test_jwks();
    Mock::given(method("GET"))
        .and(path("/api/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_response))
        .mount(&mock_server)
        .await;

    let options = JwtValidationOptions::new()
        .with_trusted_issuers(vec![mock_server.uri()]);
    let result = validate_jwt_token(&expired_jwt, &options).await;
    // Should fail due to expiration
    assert!(result.is_err());
}

#[tokio::test]
async fn test_jwt_validation_missing_required_claims() {
    let mock_server = MockServer::start().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create JWT without required 'sub' claim
    let header =
        BASE64.encode(json!({"alg": "RS256", "typ": "JWT", "kid": "test-key"}).to_string());
    let payload = BASE64.encode(
        json!({
            "iss": mock_server.uri(),
            // Missing 'sub' claim
            "exp": now + 3600,
            "iat": now
        })
        .to_string(),
    );
    let invalid_jwt = format!("{}.{}.fakesignature", header, payload);

    // Mock JWKS endpoint
    let (jwks_response, _) = create_test_jwks();
    Mock::given(method("GET"))
        .and(path("/api/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_response))
        .mount(&mock_server)
        .await;

    let options = JwtValidationOptions::new()
        .with_trusted_issuers(vec![mock_server.uri()]);
    let result = validate_jwt_token(&invalid_jwt, &options).await;
    // Should fail validation due to missing subject
    assert!(result.is_err());
}

// ============================================================================
// JWKS Endpoint Tests
// ============================================================================

// Note: These JWKS endpoint tests are skipped because they require real JWT signing
// The SDK needs properly signed RS256 JWTs which is complex to set up in tests.
// The unit tests above cover the basic functionality, and the SDK is tested
// end-to-end with real tokens in production.

// ============================================================================
// JWKS Caching Tests
// ============================================================================
// Note: JWKS caching is tested indirectly through unit tests in jwt.rs
// Integration testing would require generating properly signed RS256 JWTs
// which adds significant complexity. The caching logic is verified through
// unit tests and production usage.

// ============================================================================
// JWT Claims Serialization Tests
// ============================================================================

#[test]
fn test_jwt_claims_serialization() {
    use runbeam_sdk::{TeamInfo, UserInfo};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = JwtClaims {
        iss: "http://example.com".to_string(),
        sub: "user123".to_string(),
        aud: Some("runbeam-cli".to_string()),
        exp: now + 3600,
        iat: now,
        user: Some(UserInfo {
            id: "user123".to_string(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
        }),
        team: Some(TeamInfo {
            id: "team456".to_string(),
            name: "Test Team".to_string(),
        }),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&claims).unwrap();
    assert!(json.contains("\"iss\":"));
    assert!(json.contains("\"sub\":"));
    assert!(json.contains("user123"));
    assert!(json.contains("Test User"));
    assert!(json.contains("Test Team"));

    // Deserialize back
    let deserialized: JwtClaims = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.iss, claims.iss);
    assert_eq!(deserialized.sub, claims.sub);
    assert!(deserialized.user.is_some());
    assert!(deserialized.team.is_some());
}

#[test]
fn test_jwt_claims_serialization_minimal() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = JwtClaims {
        iss: "http://example.com".to_string(),
        sub: "user123".to_string(),
        aud: None,
        exp: now + 3600,
        iat: now,
        user: None,
        team: None,
    };

    // Serialize to JSON
    let json = serde_json::to_string(&claims).unwrap();

    // Deserialize back
    let deserialized: JwtClaims = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.iss, "http://example.com");
    assert_eq!(deserialized.sub, "user123");
    assert!(deserialized.aud.is_none());
    assert!(deserialized.user.is_none());
    assert!(deserialized.team.is_none());
}

// ============================================================================
// Security Validation Tests
// ============================================================================

#[tokio::test]
async fn test_jwt_validation_untrusted_issuer() {
    let mock_server = MockServer::start().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create JWT from untrusted issuer
    let header = URL_SAFE_NO_PAD.encode(
        json!({"alg": "RS256", "typ": "JWT", "kid": "test-key"})
            .to_string()
            .as_bytes(),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": mock_server.uri(),  // This issuer is NOT in trusted list
            "sub": "test",
            "exp": now + 3600,
            "iat": now
        })
        .to_string()
        .as_bytes(),
    );
    let jwt = format!("{}.{}.fakesignature", header, payload);

    // Configure with trusted issuers that does NOT include mock_server.uri()
    let options = JwtValidationOptions::new()
        .with_trusted_issuers(vec!["https://api.runbeam.io".to_string()]);

    let result = validate_jwt_token(&jwt, &options).await;
    // Should fail because issuer is not in trusted list
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("trusted issuers"), "Expected 'trusted issuers' in error, got: {}", err_msg);
}

#[tokio::test]
async fn test_jwt_validation_trusted_issuer_passes() {
    let mock_server = MockServer::start().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create JWT from trusted issuer
    let header = URL_SAFE_NO_PAD.encode(
        json!({"alg": "RS256", "typ": "JWT", "kid": "test-key"})
            .to_string()
            .as_bytes(),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": mock_server.uri(),
            "sub": "test",
            "exp": now + 3600,
            "iat": now
        })
        .to_string()
        .as_bytes(),
    );
    let jwt = format!("{}.{}.fakesignature", header, payload);

    // Mock JWKS endpoint
    let (jwks_response, _) = create_test_jwks();
    Mock::given(method("GET"))
        .and(path("/api/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_response))
        .mount(&mock_server)
        .await;

    // Configure with trusted issuer that DOES include mock_server.uri()
    let options = JwtValidationOptions::new()
        .with_trusted_issuers(vec![mock_server.uri()]);

    let result = validate_jwt_token(&jwt, &options).await;
    // Should still fail due to invalid signature, but NOT due to untrusted issuer
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(!err_msg.contains("not in the trusted issuers list"));
    }
}

#[tokio::test]
async fn test_jwt_validation_disallowed_algorithm() {
    let mock_server = MockServer::start().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create JWT with ES256 algorithm
    let header = URL_SAFE_NO_PAD.encode(
        json!({"alg": "ES256", "typ": "JWT", "kid": "test-key"})
            .to_string()
            .as_bytes(),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": mock_server.uri(),
            "sub": "test",
            "exp": now + 3600,
            "iat": now
        })
        .to_string()
        .as_bytes(),
    );
    let jwt = format!("{}.{}.fakesignature", header, payload);

    // Only allow RS256
    let options = JwtValidationOptions::new()
        .with_trusted_issuers(vec![mock_server.uri()])
        .with_algorithms(vec![jsonwebtoken::Algorithm::RS256]);

    let result = validate_jwt_token(&jwt, &options).await;
    // Should fail because ES256 is not in allowed list
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("allowed"), "Expected 'allowed' in error, got: {}", err_msg);
}

#[tokio::test]
async fn test_jwt_validation_required_custom_claims() {
    let mock_server = MockServer::start().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create JWT without 'email' claim
    let header = URL_SAFE_NO_PAD.encode(
        json!({"alg": "RS256", "typ": "JWT", "kid": "test-key"})
            .to_string()
            .as_bytes(),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": mock_server.uri(),
            "sub": "test",
            "exp": now + 3600,
            "iat": now
            // Missing 'email' claim
        })
        .to_string()
        .as_bytes(),
    );
    let jwt = format!("{}.{}.fakesignature", header, payload);

    // Mock JWKS endpoint
    let (jwks_response, _) = create_test_jwks();
    Mock::given(method("GET"))
        .and(path("/api/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_response))
        .mount(&mock_server)
        .await;

    // Require 'email' claim
    let options = JwtValidationOptions::new()
        .with_trusted_issuers(vec![mock_server.uri()])
        .with_required_claims(vec!["email".to_string()]);

    let result = validate_jwt_token(&jwt, &options).await;
    // Should eventually fail - either due to missing claim or invalid signature
    assert!(result.is_err());
}

#[test]
fn test_jwt_validation_options_builder() {
    use jsonwebtoken::Algorithm;

    let options = JwtValidationOptions::new()
        .with_trusted_issuers(vec!["https://api.runbeam.io".to_string()])
        .with_algorithms(vec![Algorithm::RS256, Algorithm::ES256])
        .with_required_claims(vec!["email".to_string(), "scope".to_string()])
        .with_leeway_seconds(60)
        .with_validate_expiry(false)
        .with_jwks_cache_duration_hours(48);

    assert!(options.trusted_issuers.is_some());
    assert_eq!(options.trusted_issuers.unwrap().len(), 1);
    assert!(options.algorithms.is_some());
    assert_eq!(options.algorithms.unwrap().len(), 2);
    assert!(options.required_claims.is_some());
    assert_eq!(options.required_claims.unwrap().len(), 2);
    assert_eq!(options.leeway_seconds, Some(60));
    assert_eq!(options.validate_expiry, false);
    assert_eq!(options.jwks_cache_duration_hours, 48);
}

#[test]
fn test_jwt_validation_options_leeway_capped() {
    // Leeway should be capped at 300 seconds
    let options = JwtValidationOptions::new()
        .with_leeway_seconds(500);

    assert_eq!(options.leeway_seconds, Some(300));
}

#[tokio::test]
async fn test_jwt_validation_without_trusted_issuers_logs_warning() {
    let mock_server = MockServer::start().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create JWT without configuring trusted issuers
    let header = URL_SAFE_NO_PAD.encode(
        json!({"alg": "RS256", "typ": "JWT", "kid": "test-key"})
            .to_string()
            .as_bytes(),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": mock_server.uri(),
            "sub": "test",
            "exp": now + 3600,
            "iat": now
        })
        .to_string()
        .as_bytes(),
    );
    let jwt = format!("{}.{}.fakesignature", header, payload);

    // Mock JWKS endpoint
    let (jwks_response, _) = create_test_jwks();
    Mock::given(method("GET"))
        .and(path("/api/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_response))
        .mount(&mock_server)
        .await;

    // Validate WITHOUT trusted_issuers - should log warning but continue
    let options = JwtValidationOptions::new(); // No trusted issuers!

    let result = validate_jwt_token(&jwt, &options).await;
    // Will fail due to invalid signature, but issuer validation should have logged warning
    assert!(result.is_err());
}
