# IDOR Detection Plugin Development Plan (Based on Autorize)

## 1. Project Overview
The goal is to develop a Burp Suite extension that automates the detection of Insecure Direct Object Reference (IDOR) vulnerabilities. Unlike the standard Autorize plugin which focuses on replay with stripped/modified session tokens, this plugin focuses on **parameter swapping** between two authenticated users (User A and User B).

## 2. Core Workflow
1.  **Traffic Collection**: Passively listen to HTTP traffic from User A (Attacker) and User B (Victim).
2.  **Parameter Extraction**: Parse and store parameters (Query, Body, Path) from captured requests.
3.  **Attack Generation**: Automatically generate attack vectors by swapping User A's parameters with User B's values (and vice versa) for the same API endpoints.
4.  **Replay & Analysis**: Replay the generated requests and analyze the response to determine if User A successfully accessed User B's resources.

## 3. Architecture & Database Design

### 3.1 Database (SQLite)
The plugin will use a local SQLite database (`autorize_idor.db`) stored in the plugin directory.

**Tables:**
1.  `raw_requests`: Stores original traffic.
    *   `id`: PK
    *   `user`: 'A' or 'B'
    *   `method`: GET, POST, etc.
    *   `host`: target.com
    *   `path`: /api/v1/user/123
    *   `path_template`: /api/v1/user/{id} (Normalized path)
    *   `headers`: JSON
    *   `body`: Raw text/bytes
    *   `timestamp`: Time of capture
    *   `processed`: Boolean (True if parameters have been extracted)

2.  `parameter_pool`: Stores extracted parameters.
    *   `id`: PK
    *   `request_id`: FK to raw_requests
    *   `api_signature`: method + host + path_template
    *   `param_name`: id, account_no, etc.
    *   `param_value`: 123, admin, etc.
    *   `param_location`: QUERY, BODY_JSON, PATH
    *   `user`: 'A' or 'B'

3.  `attack_queue`: Stores generated attack requests.
    *   `id`: PK
    *   `original_request_id`: FK (The base request being modified, e.g., User A's request)
    *   `target_user`: 'B' (The victim whose data we are trying to access)
    *   `payload_description`: "Swapped 'id' with User B's value"
    *   `request_data`: Full HTTP request blob
    *   `status`: PENDING, SENT, CONFIRMED (for dangerous methods)
    *   `response_data`: Full HTTP response blob
    *   `response_code`: HTTP Status Code
    *   `vulnerability_score`: 0-100 (Likelihood of IDOR)

### 3.2 Modules
*   **TrafficListener**: Hooks into Burp's `IHttpListener`. Identifies User A/B based on configured headers/cookies.
*   **ParameterExtractor**:
    *   **Path**: Regex/Heuristic to identify IDs in paths (e.g., numeric segments, UUIDs).
    *   **Query**: Standard URL parsing.
    *   **Body**: JSON parser (initial scope).
*   **AttackEngine**:
    *   Matches User A and User B requests by `api_signature`.
    *   Generates permutations:
        *   Replace single parameter.
        *   Replace all parameters.
*   **Replayer**: Executes requests. Handles "Safe" (GET) vs "Unsafe" (POST/DELETE) logic.
*   **Analyzer**: Compares the attack response with User A's original response and User B's original response.

## 4. Implementation Steps

### Phase 1: Infrastructure & Traffic Collection
*   **Goal**: Successfully record User A and User B traffic into the database.
*   **UI**: Add "User Configuration" tab in Autorize.
    *   Input: `User A Identifier` (e.g., "Cookie: sess=A").
    *   Input: `User B Identifier` (e.g., "Cookie: sess=B").
*   **Logic**:
    *   Initialize SQLite DB.
    *   Implement `IHttpListener`.
    *   Detect user identity.
    *   Store raw request.

### Phase 2: Parameter Extraction
*   **Goal**: Populate `parameter_pool`.
*   **Logic**:
    *   Implement `PathNormalizer`: Convert `/users/101` to `/users/{id}`.
    *   Implement `Extractor`:
        *   Extract `101` from path.
        *   Extract `?q=search` from query.
        *   Extract `{"role": "admin"}` from body.

### Phase 3: Attack Generation Strategy
*   **Goal**: Create intelligent attack payloads.
*   **Logic**:
    *   Trigger: Periodic task or "Generate Attacks" button.
    *   Find intersection: APIs accessed by BOTH User A and User B.
    *   For each API:
        *   Take User A's request.
        *   Find User B's values for the *same* parameters.
        *   Construct new request: User A's Session + User B's ID.

### Phase 4: Execution & Analysis
*   **Goal**: Send requests and flag vulnerabilities.
*   **Logic**:
    *   **Safe Mode**: Automatically send GET requests.
    *   **Manual Mode**: Queue POST/PUT/DELETE requests for user approval.
    *   **Detection**:
        *   If Status == 200 AND Content != Error: Potential IDOR.
        *   Compare Content-Length and Body Similarity with User B's actual response.

## 5. UI Design
*   **Configuration Tab**:
    *   User A/B Strings.
    *   Filters (Scope, File extensions).
    *   "Auto-Send Safe Requests" checkbox.
*   **IDOR Results Tab**:
    *   Table showing: API Method/Path, Parameter Swapped, Status Code, Result (Vulnerable?).
    *   Request/Response Viewer.

## 6. Next Steps
1.  Initialize the database (`db/database.py`).
2.  Implement `TrafficListener` in `authorization.py` to capture and label traffic.
