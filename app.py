#!/usr/bin/env python3
"""OpenHands Governance Dashboard - Backend API."""

import os
import re
import json
import requests
from datetime import datetime
from collections import defaultdict
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='static')
CORS(app)

API_BASE = "https://app.all-hands.dev"
API_KEY = os.environ.get("OH_API_KEY")

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

def fetch_all_conversations(force_refresh=False):
    """Fetch all conversations with pagination and caching."""
    if not force_refresh and _cache["conversations"]:
        return _cache["conversations"]
    
    headers = get_headers()
    all_convos = []
    next_page = None
    
    while True:
        url = f"{API_BASE}/api/v1/app-conversations/search?limit=50"
        if next_page:
            url += f"&page_id={next_page}"
        
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        
        all_convos.extend(data.get("items", []))
        next_page = data.get("next_page_id")
        
        if not next_page:
            break
    
    _cache["conversations"] = all_convos
    _cache["last_fetch"] = datetime.now().isoformat()
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
    
    convos = fetch_all_conversations()
    
    # Apply filters
    if model_filter:
        convos = [c for c in convos if model_filter in (c.get("llm_model") or "")]
    if repo_filter:
        convos = [c for c in convos if repo_filter == (c.get("selected_repository") or "No repository")]
    if status_filter:
        convos = [c for c in convos if status_filter == (c.get("sandbox_status") or "unknown")]
    
    # Paginate
    start = (page - 1) * per_page
    end = start + per_page
    
    return jsonify({
        "total": len(convos),
        "page": page,
        "per_page": per_page,
        "items": convos[start:end]
    })

@app.route('/api/conversation/<conv_id>')
def get_conversation(conv_id):
    """Get a specific conversation with details."""
    convos = fetch_all_conversations()
    conv = next((c for c in convos if c["id"] == conv_id), None)
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404
    return jsonify(conv)

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
    
    for conv in convos:
        model = conv.get("llm_model", "")
        if model:
            models.add(model.split("/")[-1] if "/" in model else model)
        repos.add(conv.get("selected_repository") or "No repository")
        statuses.add(conv.get("sandbox_status") or "unknown")
    
    return jsonify({
        "models": sorted(list(models)),
        "repositories": sorted(list(repos)),
        "statuses": sorted(list(statuses))
    })


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
    """Get security and governance overview across active conversations."""
    convos = fetch_all_conversations()
    active = [c for c in convos if c.get("conversation_url") and c.get("session_api_key")]
    
    all_tool_usage = defaultdict(int)
    all_security_levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}
    all_sensitive_actions = []
    conversations_analyzed = 0
    
    for conv in active[:5]:  # Analyze up to 5 active conversations
        try:
            headers = {"X-Session-API-Key": conv["session_api_key"]}
            url = f"{conv['conversation_url']}/events/search?limit=200"
            resp = requests.get(url, headers=headers, timeout=15)
            
            if resp.status_code == 200:
                events = resp.json().get("items", [])
                analysis = extract_tool_calls(events)
                
                for tool, count in analysis["tool_usage"].items():
                    all_tool_usage[tool] += count
                
                for level, count in analysis["security_levels"].items():
                    all_security_levels[level] += count
                
                for action in analysis["sensitive_actions"]:
                    action["conversation_id"] = conv["id"]
                    action["conversation_title"] = conv.get("title", "Untitled")
                    all_sensitive_actions.append(action)
                
                conversations_analyzed += 1
        except Exception as e:
            continue
    
    return jsonify({
        "conversations_analyzed": conversations_analyzed,
        "active_conversations": len(active),
        "tool_usage": dict(sorted(all_tool_usage.items(), key=lambda x: -x[1])),
        "security_levels": all_security_levels,
        "sensitive_actions": all_sensitive_actions[:30],
        "risk_summary": {
            "high_risk_actions": all_security_levels["HIGH"],
            "medium_risk_actions": all_security_levels["MEDIUM"],
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
    """Get summary of tool/permission usage patterns."""
    convos = fetch_all_conversations()
    active = [c for c in convos if c.get("conversation_url") and c.get("session_api_key")]
    
    permission_categories = {
        "file_system": ["file_editor", "read_file", "write_file", "list_files"],
        "terminal": ["terminal", "bash", "shell", "cmd"],
        "browser": ["browser_navigate", "browser_click", "browser_get_state", "browser_type"],
        "external_api": ["tavily", "slack", "notion", "github", "gitlab"],
        "code_execution": ["python", "node", "execute"],
    }
    
    usage_by_category = defaultdict(int)
    tool_details = defaultdict(lambda: {"count": 0, "conversations": set()})
    
    for conv in active[:3]:  # Sample from 3 active
        try:
            headers = {"X-Session-API-Key": conv["session_api_key"]}
            url = f"{conv['conversation_url']}/events/search?limit=200"
            resp = requests.get(url, headers=headers, timeout=15)
            
            if resp.status_code == 200:
                events = resp.json().get("items", [])
                event_str = json.dumps(events)
                
                # Count tool usage
                matches = re.findall(r'"tool_name":\s*"([^"]+)"', event_str)
                for tool in matches:
                    tool_details[tool]["count"] += 1
                    tool_details[tool]["conversations"].add(conv["id"])
                    
                    # Categorize
                    for category, patterns in permission_categories.items():
                        if any(p in tool.lower() for p in patterns):
                            usage_by_category[category] += 1
                            break
                    else:
                        usage_by_category["other"] += 1
        except:
            continue
    
    # Convert sets to counts
    for tool in tool_details:
        tool_details[tool]["conversations"] = len(tool_details[tool]["conversations"])
    
    return jsonify({
        "by_category": dict(usage_by_category),
        "tool_details": dict(sorted(tool_details.items(), key=lambda x: -x[1]["count"])[:15]),
        "categories_defined": list(permission_categories.keys())
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=12000, debug=True)
