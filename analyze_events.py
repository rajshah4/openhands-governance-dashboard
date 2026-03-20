#!/usr/bin/env python3
"""Analyze events from active conversations for governance insights."""

import os
import json
import requests

API_KEY = os.environ.get("OH_API_KEY")

# Load conversations
with open("conversations.json") as f:
    convos = json.load(f)

# Find active conversations with sandbox URLs
active = [c for c in convos if c.get("conversation_url") and c.get("session_api_key")]
print(f"Found {len(active)} active conversations with accessible events")

if active:
    conv = active[0]
    print(f"\nSampling events from: {conv['title']}")
    print(f"Conversation ID: {conv['id']}")
    
    # Fetch events
    headers = {"X-Session-API-Key": conv["session_api_key"]}
    url = f"{conv['conversation_url']}/events/search?limit=20"
    
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        events = resp.json()
        
        print(f"\nFetched {len(events.get('items', []))} events")
        
        # Analyze event structure
        for i, event in enumerate(events.get('items', [])[:5]):
            print(f"\n--- Event {i+1} ---")
            print(f"Type: {event.get('type', 'unknown')}")
            print(f"Source: {event.get('source', 'unknown')}")
            if 'action' in event:
                print(f"Action: {event['action']}")
            if 'observation' in event:
                print(f"Observation: {event['observation']}")
            if 'args' in event:
                args = event['args']
                print(f"Args keys: {list(args.keys())}")
                if 'security_risk' in args:
                    print(f"  Security Risk: {args['security_risk']}")
                if 'command' in args:
                    cmd = args['command'][:100] if len(str(args.get('command', ''))) > 100 else args.get('command', '')
                    print(f"  Command: {cmd}")
            if 'extras' in event:
                extras = event['extras']
                if 'security_risk' in extras:
                    print(f"  Security Risk (extras): {extras['security_risk']}")
                    
        # Save sample for analysis
        with open("sample_events.json", "w") as f:
            json.dump(events, f, indent=2)
        print("\nSaved sample events to sample_events.json")
        
    except Exception as e:
        print(f"Error fetching events: {e}")
