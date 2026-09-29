# SENTINEL — Universal Authentication Security Integration Guide

## 1. Architectural Philosophy & Zero-Password Rule

> [!IMPORTANT]
> **Fundamental Security Principle:**
> SENTINEL strictly forbids receiving, storing, displaying, or processing passwords.
> Your website/application remains 100% responsible for verifying user and administrator passwords.
> SENTINEL receives **authentication event metadata only**.
> Any API payload containing a password field is automatically rejected with `HTTP 400 Bad Request`.

---

## 2. Five-Step Integration Workflow

```
[ Step 1: Register Application ]
               │
               ▼
[ Step 2: Generate API Credentials ]
  (Application ID, API Key, Secret)
               │
               ▼
[ Step 3: Configure Backend Storage ]
  (Store Secret in Backend Environment)
               │
               ▼
[ Step 4: Emit Auth Events via REST ]
  POST /api/v1/auth-events
               │
               ▼
[ Step 5: Real-Time Monitoring & Alerts ]
  (Inspect telemetry on SENTINEL SOC)
```

---

## 3. Registering Your Application

Navigate to the **Connect Your Application** tab in SENTINEL:
1. **Application Name**: Enter your application's public name (e.g. `Apex University Portal`).
2. **Application URL**: The base URL of your portal (e.g. `https://portal.apex.edu`).
3. **Application Type**: Select `Website`, `Web Application`, `Mobile Application`, `API`, or `Portal`.
4. **Owner Email**: Security contact email for incident dispatch.
5. **Environment**: Select `Production`, `Staging`, or `Development`.

Upon submission, SENTINEL generates:
- **Application ID**: Unique identifier (e.g., `APP_001`).
- **API Key**: Public key for identification.
- **API Secret**: Cryptographic secret (shown once). Store this securely in your backend environment variables (`.env`). **NEVER expose API secrets in frontend JavaScript.**

---

## 4. REST API Endpoint Reference

### `POST /api/v1/auth-events`

#### Request Headers
```http
POST /api/v1/auth-events HTTP/1.1
Host: localhost:8000
Content-Type: application/json
X-API-Key: sen_live_9b4a8e109f2d431c
```

#### JSON Payload Format (Event Metadata Only)
```json
{
  "application_id": "APP_001",
  "event_type": "LOGIN_ATTEMPT",
  "username_identifier": "john123",
  "authentication_result": "SUCCESS",
  "timestamp": "2026-09-19 10:42:21",
  "source_ip": "192.0.2.10",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0.0.0",
  "device_type": "Desktop",
  "resource": "/login"
}
```

#### Supported `authentication_result` Values
- `SUCCESS`: Valid credentials verified by your system.
- `FAILURE`: Invalid password or credential.
- `UNKNOWN_ACCOUNT`: Non-existent username or email identifier.
- `LOCKED_ACCOUNT`: User account is suspended or locked.
- `MFA_FAILURE`: Secondary verification factor failed.
- `MFA_SUCCESS`: Secondary verification factor verified.
- `SESSION_STARTED`: User established an active session.
- `SESSION_ENDED`: User logged out or session expired.

#### Response Format
```json
{
  "status": "PROCESSED",
  "event_id": 510,
  "application_id": "APP_001",
  "username_identifier": "john123",
  "authentication_result": "SUCCESS",
  "risk_level": "LOW",
  "risk_score": 5,
  "system_status": "SAFE",
  "explanation": "Successful authentication with no significant suspicious indicators.",
  "triggered_rules": [],
  "alert_generated": false
}
```

---

## 5. Code Integration Examples

### Node.js / Express Example
```javascript
const sendSentinelAuthEvent = async (username, result, req) => {
  try {
    await fetch('http://localhost:8000/api/v1/auth-events', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': process.env.SENTINEL_API_KEY
      },
      body: JSON.stringify({
        application_id: process.env.SENTINEL_APP_ID,
        event_type: 'LOGIN_ATTEMPT',
        username_identifier: username,
        authentication_result: result, // 'SUCCESS' | 'FAILURE' | 'UNKNOWN_ACCOUNT'
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        source_ip: req.ip || req.connection.remoteAddress,
        device_type: 'Desktop',
        user_agent: req.headers['user-agent'],
        resource: req.originalUrl || '/login'
        // STRICT RULE: NEVER INCLUDE PASSWORDS!
      })
    });
  } catch (err) {
    console.error('Sentinel telemetry error:', err);
  }
};
```

### Python / Flask Example
```python
import requests
from datetime import datetime

def notify_sentinel(username: str, result: str, request):
    payload = {
        "application_id": "APP_001",
        "event_type": "LOGIN_ATTEMPT",
        "username_identifier": username,
        "authentication_result": result,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": request.remote_addr,
        "device_type": "Desktop",
        "user_agent": request.user_agent.string,
        "resource": request.path
    }
    requests.post(
        "http://localhost:8000/api/v1/auth-events",
        json=payload,
        headers={"X-API-Key": "sen_live_9b4a8e109f2d431c"},
        timeout=2.0
    )
```

### Java / Spring Boot Example
```java
public void sendAuthEvent(String username, String result, HttpServletRequest request) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("application_id", "APP_001");
    payload.put("username_identifier", username);
    payload.put("authentication_result", result);
    payload.put("source_ip", request.getRemoteAddr());
    payload.put("user_agent", request.getHeader("User-Agent"));
    payload.put("resource", request.getRequestURI());

    restTemplate.postForEntity("http://localhost:8000/api/v1/auth-events", payload, String.class);
}
```
