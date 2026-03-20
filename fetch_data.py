#!/usr/bin/env python3
"""Fetch all conversation data from OpenHands API for governance analysis."""

import os
import json
import requests
from datetime import datetime
from collections import defaultdict

API_BASE = "https://app.all-hands.dev"
API_KEY = os.environ.get("OH_API_KEY")

def fetch_all_conversations():
    """Fetch all conversations with pagination."""
    headers = {"Authorization": f"Bearer {API_KEY}"}
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
        
        print(f"Fetched {len(all_convos)} conversations...")
        
        if not next_page:
            break
    
    return all_convos

def analyze_conversations(convos):
    """Generate governance analytics from conversations."""
    stats = {
        "total": len(convos),
        "by_model": defaultdict(int),
        "by_status": defaultdict(int),
        "by_sandbox_status": defaultdict(int),
        "by_repository": defaultdict(int),
        "by_date": defaultdict(int),
        "by_hour": defaultdict(int),
        "recent": [],
        "models_list": set(),
        "repos_list": set(),
    }
    
    for conv in convos:
        # Model analysis
        model = conv.get("llm_model", "unknown")
        if model:
            model_short = model.split("/")[-1] if "/" in model else model
            stats["by_model"][model_short] += 1
            stats["models_list"].add(model_short)
        
        # Status analysis
        exec_status = conv.get("execution_status") or "unknown"
        stats["by_status"][exec_status] += 1
        
        sandbox_status = conv.get("sandbox_status") or "unknown"
        stats["by_sandbox_status"][sandbox_status] += 1
        
        # Repository analysis
        repo = conv.get("selected_repository") or "No repository"
        stats["by_repository"][repo] += 1
        stats["repos_list"].add(repo)
        
        # Time analysis
        created = conv.get("created_at", "")
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                date_key = dt.strftime("%Y-%m-%d")
                hour_key = dt.strftime("%H:00")
                stats["by_date"][date_key] += 1
                stats["by_hour"][hour_key] += 1
            except:
                pass
    
    # Sort and convert
    stats["by_date"] = dict(sorted(stats["by_date"].items())[-30:])  # Last 30 days
    stats["by_hour"] = dict(sorted(stats["by_hour"].items()))
    stats["by_model"] = dict(stats["by_model"])
    stats["by_status"] = dict(stats["by_status"])
    stats["by_sandbox_status"] = dict(stats["by_sandbox_status"])
    stats["by_repository"] = dict(sorted(stats["by_repository"].items(), key=lambda x: -x[1])[:10])
    stats["models_list"] = sorted(list(stats["models_list"]))
    stats["repos_list"] = sorted(list(stats["repos_list"]))
    
    # Recent conversations (last 20)
    stats["recent"] = convos[:20]
    
    return stats

if __name__ == "__main__":
    print("Fetching all conversations from OpenHands...")
    convos = fetch_all_conversations()
    
    print(f"\nAnalyzing {len(convos)} conversations...")
    stats = analyze_conversations(convos)
    
    # Save raw data and stats
    with open("conversations.json", "w") as f:
        json.dump(convos, f, indent=2)
    
    with open("stats.json", "w") as f:
        json.dump(stats, f, indent=2, default=list)
    
    print(f"\n=== Governance Summary ===")
    print(f"Total conversations: {stats['total']}")
    print(f"\nBy Model:")
    for model, count in stats['by_model'].items():
        print(f"  {model}: {count}")
    print(f"\nBy Execution Status:")
    for status, count in stats['by_status'].items():
        print(f"  {status}: {count}")
    print(f"\nTop Repositories:")
    for repo, count in list(stats['by_repository'].items())[:5]:
        print(f"  {repo}: {count}")
    
    print("\nData saved to conversations.json and stats.json")
