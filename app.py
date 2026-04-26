#!/usr/bin/env python3
"""OpenHands Governance Dashboard - Backend API."""

import os
import re
import json
import time
import requests
from datetime import datetime
from collections import defaultdict
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='static')
CORS(app)

API_BASE = "https://app.all-hands.dev"
API_KEY = os.environ.get("OH_API_KEY")
BACKGROUND_TRIGGERS = {"automation", "resolver", "slack"}
CACHE_TTL_SECONDS = 300
MAX_FETCH_RETRIES = 3
CACHE_FILE = "conversations_cache.json"
SEARCH_PAGE_SIZE = 100

# Cache for conversations and security analysis
_cache = {"conversations": None, "stats": None, "last_fetch": None, "security_analysis": None}

# Sensitive command patterns for governance
SENSITIVE_PATTERNS = {
    "credential_access": [
        r"password", r"secret", r"token", r"api.?key", r"credential",
        r"\.env", r"\.pem", r"\.key", r"id_rsa", r"ssh.*key"
    ],
    "system_modification": [
        r"rm\s+-rf", r"chmod\s+777", r"chown", r"sudo", r"apt.*install",
        r"pip\s+install", r"npm\s+install", r"curl.*\|.*sh", r"wget.*\|.*sh"
    ],
    "network_access": [
        r"curl\s+", r"wget\s+", r"ssh\s+", r"scp\s+", r"nc\s+", r"netcat",
        r"https?://(?!localhost)", r"ftp://"
    ],
    "data_exfiltration": [
        r"base64", r"xxd", r"upload", r"post.*data", r"send.*file"
    ],
    "destructive_operations": [
        r"drop\s+table", r"delete\s+from", r"truncate", r"format",
        r"rm\s+-r", r"rmdir", r"shred"
    ]
}

def get_headers():
    return {"Authorization": f"Bearer {API_KEY}"}


def persist_conversation_cache(convos):
    """Persist conversation cache to disk for cold-start fallback."""
    payload = {
        "conversations": convos,
        "last_fetch": datetime.now().isoformat(),
    }
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(payload, f)
    except OSError:
        pass


def load_persisted_conversation_cache():
    """Load a previously saved conversation cache from disk."""
    if not os.path.exists(CACHE_FILE):
        return

    try:
        with open(CACHE_FILE) as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    conversations = payload.get("conversations")
    last_fetch = payload.get("last_fetch")
    if isinstance(conversations, list) and last_fetch:
        _cache["conversations"] = conversations
        _cache["last_fetch"] = last_fetch


def parse_iso_datetime(value):
    """Parse ISO datetime strings from the API."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def normalize_conversation_id(value):
    """Normalize conversation IDs so app-server and agent-server forms match."""
    return (value or "").replace("-", "")


def simplify_model_name(model):
    """Return the short model identifier used in the dashboard."""
    if not model:
        return "unknown"
    return model.split("/")[-1] if "/" in model else model


def get_conversation_cost(conv):
    """Extract accumulated cost from conversation metrics."""
    metrics = conv.get("metrics") or {}
    try:
        return float(metrics.get("accumulated_cost") or 0)
    except (TypeError, ValueError):
        return 0.0


def get_token_total(conv):
    """Sum visible token counters for quick morning-review visibility."""
    usage = ((conv.get("metrics") or {}).get("accumulated_token_usage") or {})
    total = 0
    for key in [
        "prompt_tokens",
        "completion_tokens",
        "reasoning_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
    ]:
        value = usage.get(key) or 0
        if isinstance(value, (int, float)):
            total += int(value)
    return total


def get_runtime_batch_base_url(conv):
    """Return the agent-server batch-get base URL for a conversation, if available."""
    conv_url = conv.get("conversation_url")
    session_key = conv.get("session_api_key")
    if not conv_url or not session_key:
        return None
    return conv_url.rsplit("/", 1)[0]


def extract_runtime_metrics(runtime_conv):
    """Extract the richest available metrics snapshot from agent-server payloads."""
    stats_metrics = (((runtime_conv.get("stats") or {}).get("usage_to_metrics") or {}).get("agent") or {})
    if stats_metrics:
        return {
            "model_name": stats_metrics.get("model_name") or "default",
            "accumulated_cost": stats_metrics.get("accumulated_cost") or 0,
            "max_budget_per_task": stats_metrics.get("max_budget_per_task"),
            "accumulated_token_usage": stats_metrics.get("accumulated_token_usage") or {},
        }
    return runtime_conv.get("metrics")


def merge_conversation_fields(base_conv, overlay_conv):
    """Merge richer conversation fields from an overlay payload."""
    merged = dict(base_conv)

    for field in [
        "metrics",
        "execution_status",
        "sandbox_status",
        "updated_at",
        "conversation_url",
        "session_api_key",
        "parent_conversation_id",
        "sub_conversation_ids",
        "tags",
    ]:
        value = overlay_conv.get(field)
        if value is not None:
            merged[field] = value

    return merged


def enrich_conversations_from_runtime(convos):
    """Enrich active/runtime-backed conversations using agent-server batch-get."""
    enriched = []
    runtime_groups = defaultdict(list)

    for conv in convos:
        runtime_base = get_runtime_batch_base_url(conv)
        if runtime_base:
            runtime_groups[(runtime_base, conv["session_api_key"])].append(conv)
        else:
            enriched.append(conv)

    for (runtime_base, session_key), group in runtime_groups.items():
        headers = {"X-Session-API-Key": session_key}
        ids = [conv["id"] for conv in group]
        enriched_by_id = {}

        try:
            resp = requests.get(
                runtime_base,
                headers=headers,
                params=[("ids", conv_id) for conv_id in ids],
                timeout=15,
            )
            resp.raise_for_status()
            runtime_items = resp.json()

            if isinstance(runtime_items, list):
                for runtime_conv in runtime_items:
                    if not runtime_conv:
                        continue
                    enriched_by_id[normalize_conversation_id(runtime_conv.get("id"))] = runtime_conv
        except Exception:
            runtime_items = []

        for conv in group:
            runtime_conv = enriched_by_id.get(normalize_conversation_id(conv.get("id")))
            if not runtime_conv:
                enriched.append(conv)
                continue

            runtime_metrics = extract_runtime_metrics(runtime_conv)
            overlay = {}
            if runtime_metrics:
                overlay["metrics"] = runtime_metrics
            if runtime_conv.get("execution_status"):
                overlay["execution_status"] = runtime_conv.get("execution_status")
            if runtime_conv.get("updated_at"):
                overlay["updated_at"] = runtime_conv.get("updated_at")
            merged = merge_conversation_fields(conv, overlay)
            enriched.append(merged)

    return enriched


def is_background_conversation(conv):
    """Detect conversations that look like autonomous or system-triggered work."""
    trigger = (conv.get("trigger") or "").lower()
    tags = conv.get("tags") or {}
    return trigger in BACKGROUND_TRIGGERS or "automationid" in tags or "automationrunid" in tags


def derive_operation_status(conv):
    """Collapse runtime and execution state into a simpler dashboard label."""
    sandbox_status = (conv.get("sandbox_status") or "UNKNOWN").upper()
    execution_status = (conv.get("execution_status") or "").lower()

    if sandbox_status == "RUNNING":
        return "running"
    if sandbox_status == "PAUSED":
        return "paused"
    if execution_status in {"error", "failed", "cancelled", "completed", "finished"}:
        return execution_status
    if sandbox_status == "MISSING":
        return "ended"
    return "unknown"


def normalize_operation(conv):
    """Normalize a conversation into the phase-1 operations model."""
    tags = conv.get("tags") or {}
    trigger = (conv.get("trigger") or "manual").lower()
    automation_name = tags.get("automationname")
    automation_run_id = tags.get("automationrunid")
    child_ids = conv.get("sub_conversation_ids") or []

    updated_at = conv.get("updated_at") or conv.get("created_at")
    updated_dt = parse_iso_datetime(updated_at)

    return {
        "id": conv.get("id"),
        "title": conv.get("title") or f"Conversation {conv.get('id', 'unknown')}",
        "job_name": automation_name or conv.get("title") or f"Conversation {conv.get('id', 'unknown')}",
        "trigger": trigger,
        "trigger_label": trigger.replace("_", " ").title() if trigger else "Manual",
        "automation_name": automation_name,
        "automation_run_id": automation_run_id,
        "group_id": automation_run_id or conv.get("parent_conversation_id") or conv.get("id"),
        "group_name": automation_name or conv.get("title") or "Untitled job",
        "model": simplify_model_name(conv.get("llm_model")),
        "repository": conv.get("selected_repository") or "No repository",
        "branch": conv.get("selected_branch"),
        "runtime_status": conv.get("sandbox_status") or "UNKNOWN",
        "status": derive_operation_status(conv),
        "execution_status": conv.get("execution_status") or "unknown",
        "created_at": conv.get("created_at"),
        "updated_at": updated_at,
        "updated_at_epoch": updated_dt.timestamp() if updated_dt else 0,
        "created_by_user_id": conv.get("created_by_user_id"),
        "cost_usd": get_conversation_cost(conv),
        "token_total": get_token_total(conv),
        "parent_conversation_id": conv.get("parent_conversation_id"),
        "sub_conversation_ids": child_ids,
        "subagent_count": len(child_ids),
        "lineage_available": bool(conv.get("parent_conversation_id") or child_ids),
        "lineage_role": "parent" if child_ids else ("child" if conv.get("parent_conversation_id") else "standalone"),
        "sandbox_id": conv.get("sandbox_id"),
        "conversation_url": conv.get("conversation_url"),
        "tags": tags,
    }


def build_operations_overview(convos):
    """Build a morning-review oriented operations summary."""
    jobs = [normalize_operation(conv) for conv in convos if is_background_conversation(conv)]
    jobs.sort(key=lambda job: job["updated_at_epoch"], reverse=True)

    now = datetime.now().astimezone()
    recent_jobs = []
    active_jobs = []
    paused_jobs = []
    stale_active_jobs = []
    trigger_counts = defaultdict(int)
    automation_counts = defaultdict(int)

    jobs_with_parents = 0
    jobs_with_children = 0
    total_subagents_observed = 0

    for job in jobs:
        trigger_counts[job["trigger"] or "manual"] += 1
        if job["automation_name"]:
            automation_counts[job["automation_name"]] += 1

        updated_dt = parse_iso_datetime(job["updated_at"])
        if updated_dt and (now - updated_dt).total_seconds() <= 86400:
            recent_jobs.append(job)

        if job["parent_conversation_id"]:
            jobs_with_parents += 1
        if job["subagent_count"] > 0:
            jobs_with_children += 1
            total_subagents_observed += job["subagent_count"]

        runtime_status = (job["runtime_status"] or "UNKNOWN").upper()
        if runtime_status == "RUNNING":
            active_jobs.append(job)
            if updated_dt and (now - updated_dt).total_seconds() > 3600:
                stale_active_jobs.append(job)
        elif runtime_status == "PAUSED":
            paused_jobs.append(job)

    return {
        "generated_at": now.isoformat(),
        "summary": {
            "background_jobs_total": len(jobs),
            "active_background_jobs": len(active_jobs),
            "paused_background_jobs": len(paused_jobs),
            "recent_background_jobs_24h": len(recent_jobs),
            "automation_runs_24h": len({
                job["automation_run_id"] or job["id"]
                for job in recent_jobs
                if job["trigger"] == "automation"
            }),
            "stale_active_jobs": len(stale_active_jobs),
            "triggers_seen": len(trigger_counts),
            "jobs_with_lineage": len([job for job in jobs if job["lineage_available"]]),
        },
        "lineage_summary": {
            "jobs_with_parent_reference": jobs_with_parents,
            "jobs_with_child_references": jobs_with_children,
            "total_subagents_observed": total_subagents_observed,
        },
        "trigger_breakdown": dict(sorted(trigger_counts.items(), key=lambda item: (-item[1], item[0]))),
        "automation_breakdown": dict(sorted(automation_counts.items(), key=lambda item: (-item[1], item[0]))[:10]),
        "active_jobs": active_jobs[:15],
        "recent_jobs": recent_jobs[:25],
        "stale_active_jobs": stale_active_jobs[:10],
    }

def fetch_all_conversations(force_refresh=False):
    """Fetch all conversations with pagination and caching."""
    if _cache.get("conversations") is None:
        load_persisted_conversation_cache()

    cached = _cache.get("conversations")
    last_fetch = parse_iso_datetime(_cache.get("last_fetch"))
    if cached and last_fetch and not force_refresh:
        age_seconds = (datetime.now(last_fetch.tzinfo) - last_fetch).total_seconds()
        if age_seconds < CACHE_TTL_SECONDS:
            return cached
    
    headers = get_headers()
    all_convos = []
    next_page = None
    
    while True:
        url = f"{API_BASE}/api/v1/app-conversations/search?limit={SEARCH_PAGE_SIZE}"
        if next_page:
            url += f"&page_id={next_page}"

        resp = None
        for attempt in range(MAX_FETCH_RETRIES):
            resp = requests.get(url, headers=headers, timeout=20)
            if resp.status_code != 429:
                break
            if attempt < MAX_FETCH_RETRIES - 1:
                time.sleep(1.5 * (attempt + 1))

        if resp is None:
            raise RuntimeError("Failed to fetch conversations: no response received")

        if resp.status_code == 429 and cached:
            return cached

        try:
            resp.raise_for_status()
        except requests.HTTPError:
            if cached:
                return cached
            raise

        data = resp.json()
        
        all_convos.extend(data.get("items", []))
        next_page = data.get("next_page_id")
        
        if not next_page:
            break
    
    _cache["conversations"] = all_convos
    _cache["last_fetch"] = datetime.now().isoformat()
    persist_conversation_cache(all_convos)
    return all_convos

def compute_stats(convos):
    """Compute governance statistics."""
    stats = {
        "total": len(convos),
        "by_model": defaultdict(int),
        "by_status": defaultdict(int),
        "by_sandbox_status": defaultdict(int),
        "by_repository": defaultdict(int),
        "by_date": defaultdict(int),
        "by_hour": defaultdict(int),
        "by_weekday": defaultdict(int),
        "active_sandboxes": 0,
        "paused_sandboxes": 0,
    }
    
    weekdays = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    
    for conv in convos:
        # Model analysis
        model = conv.get("llm_model", "unknown")
        if model:
            model_short = model.split("/")[-1] if "/" in model else model
            stats["by_model"][model_short] += 1
        
        # Status analysis
        exec_status = conv.get("execution_status") or "unknown"
        stats["by_status"][exec_status] += 1
        
        sandbox_status = conv.get("sandbox_status") or "unknown"
        stats["by_sandbox_status"][sandbox_status] += 1
        
        if sandbox_status == "RUNNING":
            stats["active_sandboxes"] += 1
        elif sandbox_status == "PAUSED":
            stats["paused_sandboxes"] += 1
        
        # Repository analysis
        repo = conv.get("selected_repository") or "No repository"
        stats["by_repository"][repo] += 1
        
        # Time analysis
        created = conv.get("created_at", "")
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                date_key = dt.strftime("%Y-%m-%d")
                hour_key = dt.strftime("%H:00")
                weekday_key = weekdays[dt.weekday()]
                stats["by_date"][date_key] += 1
                stats["by_hour"][hour_key] += 1
                stats["by_weekday"][weekday_key] += 1
            except:
                pass
    
    # Sort and convert
    stats["by_date"] = dict(sorted(stats["by_date"].items())[-30:])
    stats["by_hour"] = dict(sorted(stats["by_hour"].items()))
    stats["by_weekday"] = {day: stats["by_weekday"].get(day, 0) for day in weekdays}
    stats["by_model"] = dict(sorted(stats["by_model"].items(), key=lambda x: -x[1]))
    stats["by_status"] = dict(stats["by_status"])
    stats["by_sandbox_status"] = dict(stats["by_sandbox_status"])
    stats["by_repository"] = dict(sorted(stats["by_repository"].items(), key=lambda x: -x[1])[:10])
    
    return stats

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/stats')
def get_stats():
    """Get aggregated governance statistics."""
    convos = fetch_all_conversations()
    stats = compute_stats(convos)
    stats["last_fetch"] = _cache.get("last_fetch")
    return jsonify(stats)

@app.route('/api/conversations')
def get_conversations():
    """Get paginated conversations list."""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    model_filter = request.args.get('model')
    repo_filter = request.args.get('repository')
    status_filter = request.args.get('status')
    trigger_filter = request.args.get('trigger')
    
    convos = fetch_all_conversations()
    
    # Apply filters
    if model_filter:
        convos = [c for c in convos if model_filter in (c.get("llm_model") or "")]
    if repo_filter:
        convos = [c for c in convos if repo_filter == (c.get("selected_repository") or "No repository")]
    if status_filter:
        convos = [c for c in convos if status_filter == (c.get("sandbox_status") or "unknown")]
    if trigger_filter:
        convos = [c for c in convos if trigger_filter == (c.get("trigger") or "manual")]
    
    # Paginate
    start = (page - 1) * per_page
    end = start + per_page
    page_items = convos[start:end]
    
    return jsonify({
        "total": len(convos),
        "page": page,
        "per_page": per_page,
        "items": page_items
    })

@app.route('/api/conversation/<conv_id>')
def get_conversation(conv_id):
    """Get a specific conversation with details."""
    convos = fetch_all_conversations()
    conv = next((c for c in convos if c["id"] == conv_id), None)
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404
    return jsonify(enrich_conversations_from_runtime([conv])[0])

@app.route('/api/conversation/<conv_id>/events')
def get_conversation_events(conv_id):
    """Fetch events for a conversation (requires active sandbox)."""
    convos = fetch_all_conversations()
    conv = next((c for c in convos if c["id"] == conv_id), None)
    
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404
    
    # Check if sandbox is active
    conv_url = conv.get("conversation_url")
    session_key = conv.get("session_api_key")
    
    if not conv_url or not session_key:
        return jsonify({
            "error": "Sandbox not active",
            "sandbox_status": conv.get("sandbox_status"),
            "message": "Events can only be fetched from active sandboxes"
        }), 400
    
    # Fetch events from agent server
    try:
        headers = {"X-Session-API-Key": session_key}
        events_url = f"{conv_url}/events/search?limit=100"
        resp = requests.get(events_url, headers=headers, timeout=10)
        resp.raise_for_status()
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/refresh')
def refresh_data():
    """Force refresh of conversation data."""
    convos = fetch_all_conversations(force_refresh=True)
    return jsonify({"success": True, "total": len(convos), "last_fetch": _cache.get("last_fetch")})

@app.route('/api/filters')
def get_filters():
    """Get available filter options."""
    convos = fetch_all_conversations()
    
    models = set()
    repos = set()
    statuses = set()
    triggers = set()
    
    for conv in convos:
        model = conv.get("llm_model", "")
        if model:
            models.add(model.split("/")[-1] if "/" in model else model)
        repos.add(conv.get("selected_repository") or "No repository")
        statuses.add(conv.get("sandbox_status") or "unknown")
        triggers.add(conv.get("trigger") or "manual")
    
    return jsonify({
        "models": sorted(list(models)),
        "repositories": sorted(list(repos)),
        "statuses": sorted(list(statuses)),
        "triggers": sorted(list(triggers))
    })


@app.route('/api/operations/overview')
def get_operations_overview():
    """Get a morning-review view of autonomous/background jobs."""
    convos = fetch_all_conversations()
    background_convos = [conv for conv in convos if is_background_conversation(conv)]
    runtime_backed = [conv for conv in background_convos if get_runtime_batch_base_url(conv)]
    enriched_runtime = enrich_conversations_from_runtime(runtime_backed) if runtime_backed else []
    enriched_by_id = {conv["id"]: conv for conv in enriched_runtime}
    merged = [enriched_by_id.get(conv["id"], conv) for conv in background_convos]
    return jsonify(build_operations_overview(merged))


def analyze_event_security(event):
    """Analyze a single event for security concerns."""
    event_str = json.dumps(event).lower()
    findings = []
    
    for category, patterns in SENSITIVE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, event_str, re.IGNORECASE):
                findings.append({
                    "category": category,
                    "pattern": pattern,
                    "event_id": event.get("id", "unknown"),
                    "timestamp": event.get("timestamp", ""),
                    "source": event.get("source", "unknown")
                })
                break  # One finding per category per event
    
    return findings


def extract_tool_calls(events):
    """Extract tool usage from events."""
    tool_usage = defaultdict(int)
    security_levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}
    sensitive_actions = []
    
    for event in events:
        event_str = json.dumps(event)
        
        # Extract tool names
        matches = re.findall(r'"tool_name":\s*"([^"]+)"', event_str)
        for m in matches:
            tool_usage[m] += 1
        
        # Extract security risk levels
        for level in ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            if f'"security_risk": "{level}"' in event_str or f'"security_risk":"{level}"' in event_str:
                security_levels[level] += 1
                if level == "HIGH":
                    sensitive_actions.append({
                        "event_id": event.get("id"),
                        "timestamp": event.get("timestamp"),
                        "risk_level": level,
                        "source": event.get("source")
                    })
        
        # Check for sensitive patterns
        findings = analyze_event_security(event)
        for finding in findings:
            finding["risk_level"] = "MEDIUM"
            sensitive_actions.append(finding)
    
    return {
        "tool_usage": dict(tool_usage),
        "security_levels": security_levels,
        "sensitive_actions": sensitive_actions[:50]  # Limit to 50
    }


@app.route('/api/security/overview')
def get_security_overview():
    """Get security and governance overview using V1 App Server API."""
    convos = fetch_all_conversations()
    
    all_tool_usage = defaultdict(int)
    all_security_levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}
    all_sensitive_actions = []
    command_types = defaultdict(int)
    conversations_analyzed = 0
    
    # Use V1 App Server API - works for all conversations
    for conv in convos[:20]:  # Analyze 20 recent conversations
        try:
            url = f"{API_BASE}/api/v1/conversation/{conv['id']}/events/search?limit=100"
            resp = requests.get(url, headers=get_headers(), timeout=20)
            
            if resp.status_code == 200 and resp.text:
                events = resp.json().get("items", [])
                
                for event in events:
                    # Track tool usage
                    tool_name = event.get("tool_name")
                    if tool_name:
                        all_tool_usage[tool_name] += 1
                    
                    # Track security risk
                    risk = event.get("security_risk")
                    if risk:
                        all_security_levels[risk] += 1
                    
                    # Get action details for sensitive command detection
                    action = event.get("action", {})
                    if isinstance(action, dict):
                        cmd = action.get("command", "")
                        if cmd:
                            # Categorize commands
                            if "ls " in cmd or cmd.startswith("ls"):
                                command_types["ls (list)"] += 1
                            if "cat " in cmd:
                                command_types["cat (read)"] += 1
                            if "curl " in cmd:
                                command_types["curl (network)"] += 1
                                all_sensitive_actions.append({
                                    "conversation_id": conv["id"],
                                    "conversation_title": conv.get("title", "Untitled"),
                                    "category": "network_access",
                                    "pattern": "curl",
                                    "risk_level": "MEDIUM",
                                    "timestamp": event.get("timestamp"),
                                    "command": cmd[:100]
                                })
                            if "pip install" in cmd:
                                command_types["pip install"] += 1
                                all_sensitive_actions.append({
                                    "conversation_id": conv["id"],
                                    "conversation_title": conv.get("title", "Untitled"),
                                    "category": "system_modification",
                                    "pattern": "pip install",
                                    "risk_level": "MEDIUM",
                                    "timestamp": event.get("timestamp"),
                                    "command": cmd[:100]
                                })
                            if "rm " in cmd:
                                command_types["rm (delete)"] += 1
                                all_sensitive_actions.append({
                                    "conversation_id": conv["id"],
                                    "conversation_title": conv.get("title", "Untitled"),
                                    "category": "destructive_operation",
                                    "pattern": "rm",
                                    "risk_level": "MEDIUM",
                                    "timestamp": event.get("timestamp"),
                                    "command": cmd[:100]
                                })
                            if ".env" in cmd:
                                all_sensitive_actions.append({
                                    "conversation_id": conv["id"],
                                    "conversation_title": conv.get("title", "Untitled"),
                                    "category": "credential_access",
                                    "pattern": ".env file",
                                    "risk_level": "HIGH",
                                    "timestamp": event.get("timestamp"),
                                    "command": cmd[:100]
                                })
                            if any(x in cmd.lower() for x in ["token", "secret", "password", "api_key"]):
                                all_sensitive_actions.append({
                                    "conversation_id": conv["id"],
                                    "conversation_title": conv.get("title", "Untitled"),
                                    "category": "credential_access",
                                    "pattern": "credential keyword",
                                    "risk_level": "HIGH",
                                    "timestamp": event.get("timestamp"),
                                    "command": cmd[:100]
                                })
                            if "git " in cmd:
                                command_types["git"] += 1
                            if "python" in cmd:
                                command_types["python"] += 1
                
                conversations_analyzed += 1
        except Exception as e:
            continue
    
    return jsonify({
        "conversations_analyzed": conversations_analyzed,
        "active_conversations": len([c for c in convos if c.get("sandbox_status") == "RUNNING"]),
        "tool_usage": dict(sorted(all_tool_usage.items(), key=lambda x: -x[1])),
        "security_levels": all_security_levels,
        "command_types": dict(sorted(command_types.items(), key=lambda x: -x[1])),
        "sensitive_actions": all_sensitive_actions[:50],
        "risk_summary": {
            "high_risk_actions": all_security_levels.get("HIGH", 0),
            "medium_risk_actions": all_security_levels.get("MEDIUM", 0),
            "low_risk_actions": all_security_levels.get("LOW", 0),
            "sensitive_patterns_detected": len(all_sensitive_actions)
        }
    })


@app.route('/api/security/conversation/<conv_id>')
def get_conversation_security(conv_id):
    """Get detailed security analysis for a specific conversation."""
    convos = fetch_all_conversations()
    conv = next((c for c in convos if c["id"] == conv_id), None)
    
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404
    
    if not conv.get("conversation_url") or not conv.get("session_api_key"):
        return jsonify({
            "error": "Sandbox not active",
            "message": "Security analysis requires an active sandbox"
        }), 400
    
    try:
        headers = {"X-Session-API-Key": conv["session_api_key"]}
        url = f"{conv['conversation_url']}/events/search?limit=500"
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        
        events = resp.json().get("items", [])
        analysis = extract_tool_calls(events)
        
        # Add conversation context
        analysis["conversation_id"] = conv_id
        analysis["conversation_title"] = conv.get("title", "Untitled")
        analysis["model"] = conv.get("llm_model", "unknown")
        analysis["repository"] = conv.get("selected_repository")
        analysis["total_events"] = len(events)
        
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/security/alerts')
def get_security_alerts():
    """Get recent security alerts and anomalies."""
    convos = fetch_all_conversations()
    
    alerts = []
    
    # Check for anomalies
    active = [c for c in convos if c.get("sandbox_status") == "RUNNING"]
    if len(active) > 10:
        alerts.append({
            "level": "WARNING",
            "type": "resource_usage",
            "message": f"High number of active sandboxes: {len(active)}",
            "timestamp": datetime.now().isoformat()
        })
    
    # Check for unusual model usage
    model_counts = defaultdict(int)
    for conv in convos[:50]:  # Recent 50
        model = conv.get("llm_model", "").split("/")[-1]
        model_counts[model] += 1
    
    # Add informational alerts
    alerts.append({
        "level": "INFO",
        "type": "model_diversity",
        "message": f"Using {len(model_counts)} different models across recent conversations",
        "timestamp": datetime.now().isoformat()
    })
    
    return jsonify({
        "alerts": alerts,
        "generated_at": datetime.now().isoformat()
    })


@app.route('/api/governance/permissions')
def get_permissions_summary():
    """Get summary of tool/permission usage patterns using V1 App Server API."""
    convos = fetch_all_conversations()
    
    permission_categories = {
        "file_system": ["file_editor", "read_file", "write_file", "list_files"],
        "terminal": ["terminal", "bash", "shell", "cmd"],
        "browser": ["browser_navigate", "browser_click", "browser_get_state", "browser_type"],
        "external_api": ["tavily", "slack", "notion", "github", "gitlab", "shttp"],
        "task_management": ["task_tracker", "finish"],
    }
    
    usage_by_category = defaultdict(int)
    tool_details = defaultdict(lambda: {"count": 0, "conversations": set()})
    analyzed = 0
    
    # Use V1 App Server API
    for conv in convos[:15]:
        try:
            url = f"{API_BASE}/api/v1/conversation/{conv['id']}/events/search?limit=100"
            resp = requests.get(url, headers=get_headers(), timeout=20)
            
            if resp.status_code == 200 and resp.text:
                events = resp.json().get("items", [])
                
                for event in events:
                    tool = event.get("tool_name")
                    if tool:
                        tool_details[tool]["count"] += 1
                        tool_details[tool]["conversations"].add(conv["id"])
                        
                        # Categorize
                        categorized = False
                        for category, patterns in permission_categories.items():
                            if any(p in tool.lower() for p in patterns):
                                usage_by_category[category] += 1
                                categorized = True
                                break
                        if not categorized:
                            usage_by_category["other"] += 1
                
                analyzed += 1
        except:
            continue
    
    # Convert sets to counts
    for tool in tool_details:
        tool_details[tool]["conversations"] = len(tool_details[tool]["conversations"])
    
    return jsonify({
        "by_category": dict(usage_by_category),
        "tool_details": dict(sorted(tool_details.items(), key=lambda x: -x[1]["count"])[:15]),
        "categories_defined": list(permission_categories.keys()),
        "conversations_analyzed": analyzed
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=12000, debug=True)
