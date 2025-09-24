import os
import re
import json
import cohere
from dotenv import load_dotenv
# utils/cohere_parser.py
import os, json, textwrap
# === UNIVERSAL HEURISTICS (command-agnostic) =================================

_STATE_UP = re.compile(r'\b(up|active|established|enabled|ok)\b', re.I)
_STATE_DOWN = re.compile(r'\b(down|inactive|idle|closed|disabled|shutdown)\b', re.I)
_ERR = re.compile(r'\b(error|fail|denied|invalid|timeout|unreachable|warning|crit|alarm)\b', re.I)
_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b')
_IFACE = re.compile(r'\b(?:GigabitEthernet|TenGigE|FastEthernet|Eth\d+|ge-\d/\d/\d|xe-\d/\d/\d|et-\d/\d/\d|lo|Loopback\d*)[^\s]*', re.I)
_NUMERIC_ROW = re.compile(r'^\s*[\w\-\.:/]+\s+\S+\s+.*\d+.*$')

def _classify_command(cmd: str):
    c = (cmd or '').strip().lower()
    is_show = c.startswith('show') or c.startswith('display') or c.startswith('get ') or ' brief' in c
    is_diag = any(k in c for k in ['ping', 'traceroute', 'trace ', 'mtr', 'test '])
    is_config = any(c.startswith(p) for p in ['configure', 'conf t', 'conf ', 'set ', 'delete ', 'no ', 'interface ', 'router '])
    is_verify = any(k in c for k in ['verify', 'check', 'validate', 'test', 'confirm'])
    is_execute = any(k in c for k in ['execute', 'run', 'apply', 'commit', 'save'])
    risky = any(k in c for k in ['reload','clear ','shutdown','erase','write erase','format','delete ']) and not is_show
    
    if is_show:
        purpose = "Displays current device status or configuration (read-only)."
    elif is_diag:
        purpose = "Runs a diagnostic to check connectivity or path."
    elif is_config:
        purpose = "Applies or changes configuration on the device."
    elif is_verify:
        purpose = "Verifies configuration or network connectivity."
    elif is_execute:
        purpose = "Executes or commits configuration changes."
    else:
        purpose = "Runs a management or diagnostic command on the device."
    
    return {
        "is_show": is_show, 
        "is_diag": is_diag, 
        "is_config": is_config, 
        "is_verify": is_verify,
        "is_execute": is_execute,
        "risky": risky, 
        "purpose": purpose
    }

# Fix 2: Enhanced fallback explanation with verify/execute handling
def _fallback_explain(cmd: str) -> str:
    info = _classify_command(cmd)
    c = (cmd or '').lower()
    
    # Specific command patterns
    if c.startswith('show ') and 'interface' in c:
        return "Lists interface status and key parameters."
    if c.startswith('show ') and 'route' in c:
        return "Shows the routing table (how traffic is forwarded)."
    if 'ping' in c:
        return "Sends test packets to verify reachability."
    if 'traceroute' in c or 'trace ' in c:
        return "Shows the hop-by-hop path to a destination."
    if 'verify' in c:
        return "Validates configuration or connectivity status."
    if 'execute' in c or 'commit' in c:
        return "Applies or saves configuration changes to the device."
    if 'copy run' in c or 'write mem' in c:
        return "Saves running configuration to startup configuration."
    
    return info["purpose"]

def _heur_summary_from_output(cmd: str, out_text: str) -> str:
    text = (out_text or '').strip()
    if not text:
        return "No output returned. This may mean no matches, insufficient privilege, or a transient issue."

    lines = text.splitlines()
    total_lines = len(lines)

    # quick counts
    ups = sum(1 for ln in lines if _STATE_UP.search(ln))
    downs = sum(1 for ln in lines if _STATE_DOWN.search(ln))
    errs = sum(1 for ln in lines if _ERR.search(ln))
    ips = len(_IP.findall(text))
    ifaces = len(_IFACE.findall(text))
    rows = sum(1 for ln in lines if _NUMERIC_ROW.search(ln))

    # header hint (first nontrivial text line)
    header = ""
    for ln in lines[:8]:
        if re.search(r'[A-Za-z].*[A-Za-z]', ln) and len(ln.strip()) > 3:
            header = ln.strip()
            break

    bits = []
    if header: bits.append(f"Header: {header}")
    if rows: bits.append(f"Approx rows: {rows}")
    if ups or downs: bits.append(f"States — Up/Active: {ups}, Down/Shutdown: {downs}")
    if errs: bits.append(f"Errors/Warnings observed: {errs}")
    if ips: bits.append(f"IP addresses detected: {ips}")
    if ifaces: bits.append(f"Interfaces referenced: {ifaces}")
    if not bits: bits.append(f"Lines: {total_lines}. Scan for anomalies, unexpected values, or blank sections.")
    return " | ".join(bits)

def _build_heuristic_explanations(items):
    out = []
    for it in items:
        cmd = it.get("command", "")
        otp = it.get("output", "")
        info = _classify_command(cmd)
        
        # Enhanced how-to instructions based on command type
        if info["is_show"] or info["is_diag"]:
            how = "Open PuTTY -> connect to the device -> log in -> type the command at the prompt and press Enter."
        elif info["is_verify"]:
            how = "Open PuTTY -> connect -> log in -> run this command to verify current state or connectivity."
        elif info["is_execute"]:
            how = "Open PuTTY -> connect -> log in -> execute this command to apply or save changes."
        else:
            how = "Open PuTTY -> connect -> log in -> enter configuration mode as required -> paste/apply the commands carefully."
        
        # Enhanced key points based on command type
        key_points = []
        if info["is_show"] or info["is_diag"]:
            key_points = ["Safe to run (read-only).", "Check for errors, Down links, or unexpected values."]
        elif info["is_verify"]:
            key_points = ["Verification command - safe to run.", "Use to confirm configuration or connectivity.", "Check output for any failures or warnings."]
        elif info["is_execute"]:
            key_points = ["Execution command - may change device state.", "Ensure you have proper backups before running.", "Verify changes after execution."]
        else:
            key_points = ["May change device state; review before running.", "Check for errors, Down links, or unexpected values."]
        
        if info["risky"]:
            key_points.insert(0, "⚠️ Potentially disruptive command – confirm maintenance window and backups.")
        
        out.append({
            "command": cmd,
            "what_it_does": _fallback_explain(cmd),
            "how_to_use": how,
            "what_the_output_means": _heur_summary_from_output(cmd, otp),
            "key_points": key_points,
        })
    return out

# Fix 4: Enhanced Cohere prompt for better command explanations
def explain_commands_rich(items, vendor: str | None = None):
    """
    items: list of { 'command': str, 'output': str }
    Returns list of dicts: command, what_it_does, how_to_use, what_the_output_means, key_points
    """
    # Normalize & de-dupe by (command, output)
    norm, seen = [], set()
    for it in items or []:
        cmd = (it.get("command") or "").strip()
        out_txt = it.get("output") or ""
        key = (cmd, out_txt)
        if cmd and key not in seen:
            norm.append({"command": cmd, "output": out_txt})
            seen.add(key)
    if not norm:
        return []

    api_key = os.getenv("COHERE_API_KEY")
    if not api_key:
        return _build_heuristic_explanations(norm)

    try:
        import cohere
        co = cohere.Client(api_key)
        
        # Enhanced preamble with better instruction for verify/execute commands
        preamble = (
            "You are a senior network engineer explaining commands to a non-technical reader. "
            "For EACH command, provide clear explanations focusing on:\n"
            "1. What the command does (purpose and function)\n"
            "2. How to run it step-by-step in PuTTY/terminal\n"
            "3. What the actual output means and what to look for\n"
            "4. Important safety considerations\n\n"
            "Special attention for command types:\n"
            "- SHOW commands: Explain they are read-only and safe\n"
            "- VERIFY commands: Explain they check/validate without changing anything\n"
            "- EXECUTE/COMMIT commands: Explain they apply changes and need caution\n"
            "- CONFIG commands: Explain they modify device settings\n\n"
            "Return STRICT JSON: a list of objects with keys exactly:\n"
            "command, what_it_does, how_to_use, what_the_output_means, key_points (2-5 short bullet strings).\n"
            "Keep explanations clear, concise and practical."
        )
        
        lines = []
        for it in norm:
            # Enhanced command context for better AI understanding
            cmd_type = _classify_command(it['command'])
            cmd_context = f"COMMAND TYPE: {cmd_type['purpose']}"
            lines.append(f"- {cmd_context}\nCOMMAND: {it['command']}\nOUTPUT:\n{it['output'][:24000]}\n---")
        
        user = "Explain these network device commands with their outputs:\n" + "\n".join(lines) + "\nJSON:"

        try:
            resp = co.chat(model="command", message=user, preamble=preamble)
            raw = getattr(resp, "text", "") or ""
        except Exception:
            resp = co.generate(model="command",
                               prompt=textwrap.dedent(f"{preamble}\n\n{user}"),
                               max_tokens=2000, temperature=0.2)
            raw = (resp.generations[0].text if getattr(resp, "generations", None) else "") or "[]"

        txt = raw.strip()
        if txt.startswith("```"):
            txt = txt.strip("`")
            if "\n" in txt:
                txt = txt.split("\n", 1)[1].strip()

        data = json.loads(txt)
        if isinstance(data, list):
            by_cmd = { (row.get("command") or "").strip(): row for row in data if isinstance(row, dict) }
            out = []
            for it in norm:
                cmd = it["command"]
                row = by_cmd.get(cmd, {}) or {}
                
                # Enhanced fallback with better defaults
                default_explanation = _fallback_explain(cmd)
                cmd_info = _classify_command(cmd)
                
                if cmd_info["is_verify"]:
                    default_how = "Run this verification command to check current state - it's safe and won't make changes."
                elif cmd_info["is_execute"]:
                    default_how = "Execute this command to apply changes - ensure you have backups and are in a maintenance window."
                else:
                    default_how = "Open PuTTY -> connect -> log in -> run the command."
                
                out.append({
                    "command": cmd,
                    "what_it_does": (row.get("what_it_does") or default_explanation).strip(),
                    "how_to_use": (row.get("how_to_use") or default_how).strip(),
                    "what_the_output_means": (row.get("what_the_output_means") or _heur_summary_from_output(cmd, it["output"])).strip(),
                    "key_points": row.get("key_points") or _build_heuristic_explanations([it])[0]["key_points"],
                })
            return out

        # Unexpected model shape -> heuristic
        return _build_heuristic_explanations(norm)

    except Exception:
        # Any AI/JSON failure → clean heuristic fallback
        return _build_heuristic_explanations(norm)

# Fix 5: Enhanced analyze_command_detailed for verify/execute commands
def analyze_command_detailed(command, vendor):
    """
    Analyze a single command and provide comprehensive details
    """
    cmd_lower = command.lower().strip()
    
    # Default analysis structure
    analysis = {
        'purpose': 'Configuration command',
        'category': 'General',
        'explanation': '',
        'usage_example': '',
        'prerequisites': '',
        'warnings': '',
        'verification': '',
        'related_commands': ''
    }
    
    # Verify commands
    if any(word in cmd_lower for word in ['verify', 'check', 'validate', 'test']):
        analysis.update({
            'purpose': 'Verify configuration or network connectivity',
            'category': 'Verification',
            'explanation': 'This command validates current configuration or tests network connectivity without making any changes to the device.',
            'usage_example': f"""Verification process in PuTTY/Terminal:
1. Router> enable
2. Router# {command}
3. Review output for any failures or warnings
4. Document results for troubleshooting""",
            'prerequisites': 'Appropriate privilege level (usually enable mode)',
            'warnings': 'Safe to run - this command only checks status and does not modify configuration.',
            'verification': 'Review command output for pass/fail status and error messages',
            'related_commands': 'show commands, ping, traceroute, other diagnostic commands'
        })
    
    # Execute/Commit commands
    elif any(word in cmd_lower for word in ['execute', 'commit', 'apply', 'save']):
        analysis.update({
            'purpose': 'Execute or commit configuration changes',
            'category': 'Execution',
            'explanation': 'This command applies pending changes or saves current configuration. It modifies the device state.',
            'usage_example': f"""Execution process in PuTTY/Terminal:
1. Router> enable
2. Router# configure terminal (if needed)
3. Router(config)# {command}
4. Router(config)# copy running-config startup-config
5. Verify changes with appropriate show commands""",
            'prerequisites': 'Configuration mode access and proper privileges',
            'warnings': 'CAUTION: This command makes actual changes. Ensure you have backups and are in maintenance window.',
            'verification': 'Run verification commands to confirm changes were applied correctly',
            'related_commands': 'show running-config, copy commands, rollback commands'
        })
    
    # Copy/Save commands
    elif any(phrase in cmd_lower for phrase in ['copy run', 'write mem', 'copy running-config startup-config']):
        analysis.update({
            'purpose': 'Save running configuration to startup configuration',
            'category': 'Configuration Management',
            'explanation': 'Saves the current running configuration to startup configuration so changes persist after reboot.',
            'usage_example': f"""Configuration save process:
1. Router> enable
2. Router# {command}
3. Wait for confirmation message
4. Verify with: show startup-config""",
            'prerequisites': 'Enable mode privileges',
            'warnings': 'This permanently saves current configuration. Ensure running-config is correct before saving.',
            'verification': 'show startup-config, compare with show running-config',
            'related_commands': 'show running-config, show startup-config, erase startup-config'
        })
    
    # Add the existing interface, IP, router, etc. configurations...
    # (keeping the existing code for other command types)
    
    # Default case for unknown commands
    else:
        # Enhanced categorization
        if any(word in cmd_lower for word in ['show', 'display']):
            analysis['category'] = 'Information Display'
            analysis['warnings'] = 'Safe to run - read-only command'
        elif any(word in cmd_lower for word in ['ping', 'trace', 'test']):
            analysis['category'] = 'Network Diagnostics'
            analysis['warnings'] = 'Safe diagnostic command'
        elif any(word in cmd_lower for word in ['ip', 'address', 'route']):
            analysis['category'] = 'IP/Routing'
        elif any(word in cmd_lower for word in ['interface', 'port', 'duplex', 'speed']):
            analysis['category'] = 'Interface'
        elif any(word in cmd_lower for word in ['vlan', 'trunk', 'access']):
            analysis['category'] = 'Switching'
        elif any(word in cmd_lower for word in ['security', 'password', 'secret', 'auth']):
            analysis['category'] = 'Security'
        
        analysis.update({
            'explanation': f'This appears to be a {vendor.upper()} configuration command. Refer to vendor documentation for specific details.',
            'usage_example': f"""General command application:
1. Router/Switch> enable
2. Router/Switch# configure terminal (if config command)
3. Router/Switch(config)# {command}
4. Router/Switch(config)# exit
5. Router/Switch# copy running-config startup-config""",
            'prerequisites': 'Appropriate configuration mode access',
            'warnings': 'Test configuration changes in lab environment first',
            'verification': 'show running-config, show [relevant-status-command]',
            'related_commands': 'Consult vendor documentation'
        })
    
    return analysis



# Load from .env if available
load_dotenv()

def get_client():
    api_key = os.getenv("COHERE_API_KEY")
    if not api_key:
        raise ValueError("⚠️  No Cohere API key found. Please set COHERE_API_KEY environment variable or add it to .env file.")
    return cohere.Client(api_key)

def get_show_command_keywords(prompt, device_info):
    """
    Generate show command keywords (like "interface", "bgp") using LLM training
    This mimics the "show ?" output that shows available command keywords
    """
    device_type = device_info.get("device_type", "cisco_ios").lower()
    
    # Try LLM approach for command keywords
    try:
        keywords = get_llm_command_keywords(prompt, device_type)
        if keywords:
            return keywords
    except Exception as e:
        print(f"LLM keyword generation failed: {e}")
    
    # Fallback to minimal keywords
    return get_fallback_keywords(device_type)

def get_llm_command_keywords(prompt, device_type):
    """
    Use LLM to generate show command keywords with descriptions
    """
    co = get_client()
    
    # Training examples for command keywords (not full commands)
    training_examples = {
        "cisco_ios": """
Training: Cisco IOS "show ?" command keywords:

When user types "show ?" on Cisco IOS, device responds with:
- access-lists: Access lists
- arp: ARP show commands  
- bgp: BGP show commands
- cdp: CDP information
- configuration: Contents of Non-Volatile memory
- controllers: Interface controllers status
- crypto: Encryption module
- debugging: State of each debugging option
- dhcp: Dynamic Host Configuration Protocol status
- environment: Environmental monitor
- flash: Display information about flash: file system
- history: Display the session command history
- hosts: IP domain-name, lookup style, nameservers, and host table
- interfaces: Interface status and configuration
- inventory: Show the physical inventory
- ip: IP information
- ipv6: IPv6 information
- line: TTY line information
- logging: Show the contents of logging buffers
- mac-address-table: MAC forwarding table
- memory: Memory statistics
- mpls: MPLS information
- ntp: Network time protocol
- ospf: OSPF information
- platform: Show platform information
- processes: Active process statistics
- protocols: Active network routing protocols
- route-map: route-map information
- running-config: Current operating configuration
- snmp: SNMP statistics
- spanning-tree: Spanning tree topology
- startup-config: Contents of startup configuration
- tcp: Status of TCP connections
- users: Display information about terminal lines
- version: System hardware and software status
- vlan: VTP VLAN status
- vrf: VRF information
        """,
        
        "cisco_xr": """
Training: Cisco IOS-XR "show ?" command keywords:

When user types "show ?" on Cisco XR, device responds with:
- aaa: Show AAA configuration and operational data
- access-lists: Access lists
- adjacency: Adjacency information
- alarms: Show Alarms associated with XR
- arp: ARP show commands
- bgp: BGP information
- bridge: Bridge-domain information
- bundle: Bundle information
- cef: Cisco Express Forwarding
- configuration: Show configuration
- controllers: Show controller information
- crypto: Cryptographic subsystem
- dhcp: DHCP information
- environment: Show environmental information
- ethernet: Ethernet information
- hsrp: HSRP information
- interfaces: Show interface information
- inventory: Show the physical inventory
- ipv4: IPv4 configuration commands
- ipv6: IPv6 configuration commands
- isis: IS-IS Routing Information
- l2vpn: Show L2VPN information
- ldp: Show LDP related information
- lldp: Show LLDP information
- logging: Show the contents of logging buffers
- memory: Show memory usage
- mpls: MPLS show commands
- multicast-routing: IP multicast routing information
- ntp: Show NTP information
- ospf: OSPF show commands
- platform: Show platform information
- processes: Show process information
- redundancy: Show redundancy information
- route: Show route information
- running-config: Current operating configuration
- snmp: Show SNMP information
- tcp: Show TCP information
- version: Show version information
- vrf: Show VRF information
        """,
        
        "juniper_junos": """
Training: Juniper JunOS "show ?" command keywords:

When user types "show ?" on JunOS, device responds with:
- chassis: Chassis and chassis hardware information
- class-of-service: Class-of-service (CoS) information  
- configuration: Current configuration information
- firewall: Show firewall information
- interfaces: Interface information
- isis: Show IS-IS information
- ldp: Show LDP information
- log: Contents of log files
- mpls: Show MPLS information
- ospf: Show OSPF information
- pim: Show PIM information
- route: Routing table information
- rsvp: Show RSVP information
- security: Show security information
- snmp: Show SNMP information
- system: System information
- ted: Show TED information
- version: Software information
- vrrp: Show VRRP information
        """
    }
    
    # Select training example
    examples = training_examples.get("cisco_ios", training_examples["cisco_ios"])
    if "xr" in device_type:
        examples = training_examples["cisco_xr"]
    elif "juniper" in device_type:
        examples = training_examples["juniper_junos"]
    
    enhanced_prompt = f"""
You are simulating a {device_type} device's "show ?" help output.

{examples}

Generate ONLY the command keywords with descriptions, exactly like a real device would show.

Format: keyword: description
Return only the keyword list, nothing else.

User request: "{prompt}"

Keywords:"""

    try:
        response = co.generate(
            model='command-r-plus',
            prompt=enhanced_prompt,
            temperature=0.1,
            max_tokens=600,
        )
        
        # Parse the response to extract keyword-description pairs
        return parse_keyword_response(response.generations[0].text.strip())
        
    except Exception as e:
        raise e

def parse_keyword_response(response):
    """
    Parse LLM response to extract keyword-description pairs
    """
    keywords = []
    lines = response.splitlines()
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
            
        # Remove bullet points or dashes at the start
        line = re.sub(r'^[-•*]\s*', '', line)
        
        # Look for "keyword: description" format
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                keyword = parts[0].strip().replace('_', '-')
                description = parts[1].strip()
                if keyword and description:
                    keywords.append((keyword, description))
    
    return keywords

def get_fallback_keywords(device_type):
    """
    Minimal fallback keywords for emergency cases
    """
    fallback_keywords = {
        "cisco_ios": [
            ("interfaces", "Interface status and configuration"),
            ("ip", "IP information"), 
            ("version", "System hardware and software status"),
            ("running-config", "Current operating configuration"),
            ("arp", "ARP show commands"),
            ("bgp", "BGP show commands"),
            ("ospf", "OSPF information"),
            ("cdp", "CDP information"),
            ("memory", "Memory statistics"),
            ("logging", "Show the contents of logging buffers")
        ],
        "cisco_xr": [
            ("interfaces", "Show interface information"),
            ("route", "Show route information"),
            ("version", "Show version information"),
            ("configuration", "Show configuration"),
            ("bgp", "BGP information"),
            ("ospf", "OSPF show commands"),
            ("lldp", "Show LLDP information"),
            ("platform", "Show platform information"),
            ("memory", "Show memory usage")
        ],
        "juniper_junos": [
            ("interfaces", "Interface information"),
            ("route", "Routing table information"),
            ("version", "Software information"),
            ("configuration", "Current configuration information"),
            ("system", "System information"),
            ("chassis", "Chassis and chassis hardware information"),
            ("log", "Contents of log files")
        ]
    }
    
    device_key = "cisco_ios"
    if "xr" in device_type:
        device_key = "cisco_xr"
    elif "juniper" in device_type:
        device_key = "juniper_junos"
    
    return fallback_keywords[device_key]

def get_llm_show_commands(prompt, device_type):
    """
    Use LLM with comprehensive training to generate actual show commands
    """
    co = get_client()
    
    # Training context for actual commands
    training_context = create_command_training_context(device_type)
    
    enhanced_prompt = f"""
You are a network engineering AI trained extensively on {device_type} show commands.

{training_context}

Based on your training, analyze the user request and provide the most relevant show commands.

User request: "{prompt}"

Important guidelines:
1. Return only show commands, one per line
2. Use proper {device_type} syntax
3. For "all commands" requests, provide comprehensive coverage
4. Match user intent precisely
5. No explanations or extra text

Commands:"""

    try:
        response = co.generate(
            model='command-r-plus',
            prompt=enhanced_prompt,
            temperature=0.15,
            max_tokens=800,
        )
        
        commands = extract_config_commands(response.generations[0].text.strip())
        show_commands = [cmd for cmd in commands if cmd.lower().startswith('show')]
        
        # Quality filter - ensure commands make sense
        return filter_valid_commands(show_commands, device_type)
        
    except Exception as e:
        return []

def create_command_training_context(device_type):
    """
    Create rich training context based on device type for actual commands
    """
    contexts = {
        "cisco_ios": """
Training Data - Cisco IOS Show Commands:

Interface Management:
- "check interface status" → show ip interface brief, show interfaces status
- "interface details" → show interfaces, show interfaces description  
- "port errors" → show interfaces counters errors
- "interface utilization" → show interfaces counters

Routing and Protocols:
- "routing table" → show ip route, show ip route summary
- "bgp status" → show ip bgp summary, show ip bgp neighbors
- "ospf info" → show ip ospf, show ip ospf neighbor, show ip ospf database
- "eigrp neighbors" → show ip eigrp neighbors, show ip eigrp topology

System Information:
- "system info" → show version, show inventory, show environment
- "memory usage" → show memory, show processes cpu
- "uptime" → show version | include uptime

Network Discovery:
- "neighbors" → show cdp neighbors detail, show lldp neighbors
- "arp table" → show arp, show ip arp

Security and Access:
- "access lists" → show access-lists, show ip access-lists
- "mac table" → show mac address-table, show mac address-table dynamic

VLAN and Switching:
- "vlan info" → show vlan brief, show vlan
- "spanning tree" → show spanning-tree, show spanning-tree summary

Logs and Troubleshooting:
- "logs" → show logging, show logging last 50
- "configuration" → show running-config, show startup-config

All Commands Request:
- "all show commands" → [comprehensive list of all IOS show commands]
        """,
        
        "cisco_xr": """
Training Data - Cisco IOS-XR Show Commands:

Interface Management:
- "interface status" → show interfaces brief, show ipv4 interface brief
- "interface details" → show interfaces, show interfaces description
- "interface counters" → show interfaces counters

Routing Protocols:  
- "routing table" → show route, show route summary, show route ipv4
- "bgp status" → show bgp summary, show bgp neighbors
- "ospf info" → show ospf, show ospf neighbor, show ospf database
- "isis info" → show isis, show isis neighbors, show isis database

System and Platform:
- "system info" → show version, show inventory
- "platform" → show platform, show environment
- "memory" → show memory summary, show processes cpu
- "redundancy" → show redundancy, show redundancy summary

MPLS and L2VPN:
- "mpls info" → show mpls ldp neighbor, show mpls interfaces
- "l2vpn" → show l2vpn bridge-domain, show l2vpn forwarding

Configuration Management:
- "configuration" → show running-config, show configuration
- "commit history" → show configuration commit list, show configuration history

Network Discovery:
- "neighbors" → show lldp neighbors detail, show cdp neighbors

Logs and Monitoring:
- "logs" → show logging, show logging last 50
- "alarms" → show alarms brief

All Commands Request:
- "all show commands" → [comprehensive list of all XR show commands]
        """,
        
        "juniper_junos": """
Training Data - Juniper JunOS Show Commands:

Interface Management:
- "interface status" → show interfaces terse, show interfaces extensive
- "interface details" → show interfaces detail

Routing:
- "routing table" → show route, show route summary
- "bgp status" → show bgp summary, show bgp neighbor
- "ospf info" → show ospf neighbor, show ospf database

System Information:
- "system info" → show version, show chassis hardware
- "system status" → show system uptime, show chassis environment

Configuration:
- "configuration" → show configuration, show configuration | display set
- "commit history" → show system commit

Network Services:
- "lldp neighbors" → show lldp neighbors, show lldp neighbors detail

Logs and Monitoring:
- "logs" → show log messages, show log messages | last 20

All Commands Request:
- "all show commands" → [comprehensive list of all JunOS show commands]
        """
    }
    
    # Select appropriate context
    if "xr" in device_type:
        return contexts["cisco_xr"]
    elif "juniper" in device_type or "junos" in device_type:
        return contexts["juniper_junos"]
    else:
        return contexts["cisco_ios"]

def filter_valid_commands(commands, device_type):
    """
    Filter commands to ensure they're valid for the device type
    """
    if not commands:
        return []
    
    # Device-specific validation patterns
    valid_patterns = {
        "cisco_ios": [
            r"^show\s+",
            r"^show ip\s+",
            r"^show ipv6\s+",
            r"^show interfaces?\s+",
            r"^show version",
            r"^show running-config",
            r"^show mac\s+",
            r"^show vlan\s+",
        ],
        "cisco_xr": [
            r"^show\s+",
            r"^show ipv4\s+", 
            r"^show ipv6\s+",
            r"^show interfaces?\s+",
            r"^show route\s+",
            r"^show bgp\s+",
            r"^show configuration\s+",
            r"^show platform\s+",
        ],
        "juniper_junos": [
            r"^show\s+",
            r"^show interfaces\s+",
            r"^show route\s+", 
            r"^show configuration\s+",
            r"^show chassis\s+",
            r"^show system\s+",
        ]
    }
    
    # Use appropriate patterns
    patterns = valid_patterns.get("cisco_ios", valid_patterns["cisco_ios"])
    if "xr" in device_type:
        patterns = valid_patterns["cisco_xr"]
    elif "juniper" in device_type:
        patterns = valid_patterns["juniper_junos"]
    
    filtered = []
    for cmd in commands:
        cmd = cmd.strip()
        if any(re.match(pattern, cmd, re.IGNORECASE) for pattern in patterns):
            filtered.append(cmd)
    
    return filtered[:20]  # Limit results

def get_device_show_commands(prompt, device_info):
    """
    Map natural prompt to actual device show commands.
    If user wants 'all show commands', send 'show ?' to the device.
    """
    prompt_lower = prompt.lower().strip()

    # If asking for all show commands, just send 'show ?'
    if any(phrase in prompt_lower for phrase in [
        "all show commands",
        "provide all show",
        "give all show",
        "all commands",
        "all cmds",
        "list all show",
        "available show commands",
    ]):
        return ["show ?"]

    # Otherwise try normal AI mapping
    try:
        commands = get_llm_show_commands(prompt, device_info.get("device_type", "cisco_ios").lower())
        if commands:
            return commands
    except Exception:
        pass

    # Fallback basic guess
    return get_basic_fallback_commands(prompt, device_info.get("device_type", "cisco_ios").lower())



def get_comprehensive_fallback_commands(device_type):
    """
    Comprehensive fallback command list for "all commands" requests
    """
    comprehensive_commands = {
        "cisco_ios": [
            "show version", "show running-config", "show ip interface brief",
            "show interfaces", "show ip route", "show ip bgp summary",
            "show ip ospf neighbor", "show cdp neighbors", "show arp",
            "show mac address-table", "show vlan brief", "show spanning-tree",
            "show memory", "show processes cpu", "show logging"
        ],
        "cisco_xr": [
            "show version", "show running-config", "show interfaces brief",
            "show route", "show bgp summary", "show ospf neighbor",
            "show lldp neighbors", "show platform", "show memory summary",
            "show logging", "show configuration commit list"
        ],
        "juniper_junos": [
            "show version", "show configuration", "show interfaces terse",
            "show route", "show bgp summary", "show ospf neighbor",
            "show lldp neighbors", "show chassis hardware", "show system uptime",
            "show log messages"
        ]
    }
    
    device_key = "cisco_ios"
    if "xr" in device_type:
        device_key = "cisco_xr"
    elif "juniper" in device_type:
        device_key = "juniper_junos"
    
    return comprehensive_commands.get(device_key, comprehensive_commands["cisco_ios"])

def get_basic_fallback_commands(prompt, device_type):
    """
    Basic fallback commands for specific requests
    """
    prompt_lower = prompt.lower()
    
    basic_commands = {
        "cisco_ios": {
            "interface": ["show ip interface brief", "show interfaces status"],
            "route": ["show ip route", "show ip route summary"], 
            "bgp": ["show ip bgp summary", "show ip bgp neighbors"],
            "ospf": ["show ip ospf neighbor", "show ip ospf database"],
            "version": ["show version"],
            "config": ["show running-config"],
            "memory": ["show memory", "show processes cpu"],
            "log": ["show logging"]
        },
        "cisco_xr": {
            "interface": ["show interfaces brief", "show ipv4 interface brief"],
            "route": ["show route", "show route summary"],
            "bgp": ["show bgp summary", "show bgp neighbors"], 
            "ospf": ["show ospf neighbor", "show ospf database"],
            "version": ["show version"],
            "config": ["show running-config"],
            "memory": ["show memory summary", "show processes cpu"],
            "log": ["show logging"]
        },
        "juniper_junos": {
            "interface": ["show interfaces terse", "show interfaces extensive"],
            "route": ["show route", "show route summary"],
            "bgp": ["show bgp summary", "show bgp neighbor"],
            "ospf": ["show ospf neighbor", "show ospf database"],
            "version": ["show version"],
            "config": ["show configuration"],
            "log": ["show log messages"]
        }
    }
    
    device_key = "cisco_ios"
    if "xr" in device_type:
        device_key = "cisco_xr"
    elif "juniper" in device_type:
        device_key = "juniper_junos"
    
    commands_map = basic_commands[device_key]
    
    # Simple keyword matching for fallback
    for keyword, cmds in commands_map.items():
        if keyword in prompt_lower:
            return cmds
    
    # Default fallback
    return commands_map.get("interface", []) + commands_map.get("version", [])

def get_action_from_prompt(prompt, device_type="cisco_ios"):
    """
    Generate device-specific CLI commands based on natural language prompt.
    Prefers fast local paths; uses LLM only for non-show config asks (when available).
    Returns a newline-joined string of CLI commands (no prompts/explanations).
    """
    # --- FAST PATH: handle "show"/read-only intentions without any LLM ---
    prompt_lower = (prompt or "").lower()
    show_indicators = [
        "show", "display", "get", "list", "check status",
        "what is", "tell me about", "provide information",
        "all commands", "give all"
    ]
    if any(indicator in prompt_lower for indicator in show_indicators):
        device_info = {"device_type": device_type}
        commands = get_device_show_commands(prompt, device_info)
        if isinstance(commands, list) and commands:
            # Did we get help keywords (tuples) or actual commands (strings)?
            if isinstance(commands[0], tuple):
                # Format as a help readout
                return "Help - Available commands:\n" + "\n".join(f"{k}: {d}" for k, d in commands)
            else:
                return "\n".join(commands)
        return ""  # nothing matched

    # --- CONFIG PATH: may use LLM; otherwise fall back immediately ---
    device_examples = {
        "cisco_ios": {
            "config_mode": "configure terminal",
            "interface": "interface GigabitEthernet0/1",
            "ip_config": "ip address 192.168.1.1 255.255.255.0",
            "no_shutdown": "no shutdown",
            "save": "write memory",
        },
        "cisco_xr": {
            "config_mode": "configure",
            "interface": "interface GigabitEthernet0/0/0/1",
            "ip_config": "ipv4 address 192.168.1.1 255.255.255.0",
            "no_shutdown": "no shutdown",
            "commit": "commit",
        },
        "juniper_junos": {
            "config_mode": "configure",
            "interface": "set interfaces ge-0/0/1 unit 0 family inet address 192.168.1.1/24",
            "save": "commit",
        },
    }

    # Normalize device key
    dlow = device_type.lower()
    if "xr" in dlow:
        device_key = "cisco_xr"
    elif "juniper" in dlow or "junos" in dlow:
        device_key = "juniper_junos"
    else:
        device_key = "cisco_ios"

    examples = device_examples.get(device_key, device_examples["cisco_ios"])

    # If Cohere client is unavailable, immediately use local fallback
    try:
        co = get_client()
    except Exception:
        return fallback_command_mapping(prompt, device_key, examples)

    # Build concise generation prompt
    enhanced_prompt = f"""
You are a network engineer assistant. Convert the following natural language request into the appropriate CLI configuration command(s) for a {device_type} device.

Device Type: {device_type}

Common configuration patterns for this device type:
- To enter config mode: {examples.get('config_mode', 'configure terminal')}
- To configure interface: {examples.get('interface', 'interface GigabitEthernet0/1')}
- To set IP address: {examples.get('ip_config', 'ip address 192.168.1.1 255.255.255.0')}

Rules:
1. Generate ONLY the CLI command(s), no explanations
2. Use commands appropriate for {device_type}
3. One command per line
4. Do not include device prompts like Router# or Router>
5. Focus on configuration commands, not show commands

User request: {prompt}

CLI Command(s):""".strip()

    try:
        resp = co.generate(
            model="command-r-plus",
            prompt=enhanced_prompt,
            temperature=0.1,
            max_tokens=200,
        )
        raw = (resp.generations[0].text if getattr(resp, "generations", None) else "") or ""
        # Clean to strict CLI-only lines you already support
        cmds = extract_config_commands(raw)
        if not cmds:
            # As a safety net, still produce something reasonable
            return fallback_command_mapping(prompt, device_key, examples)
        return "\n".join(cmds)
    except Exception:
        # Any LLM hiccup -> deterministic fallback
        return fallback_command_mapping(prompt, device_key, examples)


def fallback_command_mapping(prompt, device_key, examples):
    """
    Fallback function that maps common phrases to commands without AI
    """
    prompt_lower = prompt.lower()
    
    # Common show command mappings
    if any(phrase in prompt_lower for phrase in ["ports are up", "interface status", "interfaces up", "which ports"]):
        return "show interfaces" if device_key == "cisco_xr" else "show ip interface brief"
    elif any(phrase in prompt_lower for phrase in ["running config", "configuration", "config"]):
        return "show running-config"
    elif "version" in prompt_lower:
        return "show version"
    elif any(phrase in prompt_lower for phrase in ["routes", "routing table", "route table"]):
        return "show route" if device_key == "cisco_xr" else "show ip route"
    elif "arp" in prompt_lower:
        return "show arp"
    elif any(phrase in prompt_lower for phrase in ["mac", "mac table", "mac address"]):
        if device_key == "cisco_xr":
            return "show l2vpn forwarding"
        elif device_key == "juniper_junos":
            return "show ethernet-switching table"
        else:
            return "show mac address-table"
    else:
        # Default to interface status for port-related queries
        return "show interfaces" if device_key == "cisco_xr" else "show ip interface brief"

def extract_config_commands(response):
    """
    Clean and extract commands from AI response
    """
    if not response:
        return []
    
    lines = response.splitlines()
    commands = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Skip common prefixes/suffixes that might be added by AI
        if line.startswith(('Router#', 'Router>', 'Switch#', 'Switch>', 'Device#', 'Device>')):
            line = line.split('#', 1)[-1].split('>', 1)[-1].strip()
        
        # Skip obvious non-commands
        if line.startswith(('Note:', 'Explanation:', 'Output:', 'Result:', 'CLI Commands:', 'Show Commands:', 'Keywords:', 'Commands:', 'Help')):
            continue
        
        # Skip lines that start with Help or Available
        if line.lower().startswith(('help', 'available')):
            continue
            
        # Skip empty or very short lines
        if len(line) < 3:
            continue
        
        # Skip numbered lists
        if line.startswith(tuple(f"{i}." for i in range(1, 10))):
            line = line.split('.', 1)[-1].strip()
        
        # Skip bullet points
        line = re.sub(r'^[-•*]\s*', '', line)
            
        commands.append(line)
    
    return commands
def explain_commands_with_usage(commands, vendor="cisco"):
    """
    Enhanced explanation function that includes usage and implementation details
    for network configuration commands with practical PuTTY/terminal examples
    """
    try:
        # Enhanced explanations with usage examples for common commands
        enhanced_explanations = []
        
        for i, command in enumerate(commands):
            if not command or command.strip() == "":
                continue
                
            explanation = f"Command {i+1}: {command}\n"
            explanation += "=" * (len(f"Command {i+1}: {command}")) + "\n\n"
            
            # Get detailed explanation and usage
            cmd_analysis = analyze_command_detailed(command.strip(), vendor)
            
            explanation += f"Purpose: {cmd_analysis['purpose']}\n"
            explanation += f"Category: {cmd_analysis['category']}\n"
            
            if cmd_analysis['explanation']:
                explanation += f"Detailed Explanation: {cmd_analysis['explanation']}\n"
            
            if cmd_analysis['usage_example']:
                explanation += f"\nPuTTY/Terminal Implementation:\n{cmd_analysis['usage_example']}\n"
            
            if cmd_analysis['prerequisites']:
                explanation += f"Prerequisites: {cmd_analysis['prerequisites']}\n"
            
            if cmd_analysis['warnings']:
                explanation += f"⚠️  Warnings: {cmd_analysis['warnings']}\n"
            
            if cmd_analysis['verification']:
                explanation += f"Verification Commands: {cmd_analysis['verification']}\n"
            
            if cmd_analysis['related_commands']:
                explanation += f"Related Commands: {cmd_analysis['related_commands']}\n"
            
            explanation += "\n" + "─" * 80 + "\n\n"
            enhanced_explanations.append(explanation)
        
        return "\n".join(enhanced_explanations)
        
    except Exception as e:
        return f"Enhanced explanations unavailable: {str(e)}\n\nBasic command list:\n" + "\n".join(f"{i+1}. {cmd}" for i, cmd in enumerate(commands))

def analyze_command_detailed(command, vendor):
    """
    Analyze a single command and provide comprehensive details
    """
    cmd_lower = command.lower().strip()
    
    # Default analysis structure
    analysis = {
        'purpose': 'Configuration command',
        'category': 'General',
        'explanation': '',
        'usage_example': '',
        'prerequisites': '',
        'warnings': '',
        'verification': '',
        'related_commands': ''
    }
    
    # Interface configuration commands
    if cmd_lower.startswith('interface '):
        interface_name = command.split()[-1] if len(command.split()) > 1 else "unknown"
        analysis.update({
            'purpose': f'Enter interface configuration mode for {interface_name}',
            'category': 'Interface Configuration',
            'explanation': f'This command enters the configuration mode for interface {interface_name}, allowing you to configure interface-specific parameters like IP addresses, descriptions, and operational settings.',
            'usage_example': f"""Step-by-step in PuTTY/Terminal:
1. Router> enable
2. Router# configure terminal
3. Router(config)# {command}
4. Router(config-if)# ip address [IP] [subnet-mask]
5. Router(config-if)# no shutdown
6. Router(config-if)# exit
7. Router(config)# copy running-config startup-config""",
            'prerequisites': 'Must be in global configuration mode (config)#',
            'warnings': 'Changes to interfaces can disrupt network connectivity. Plan changes carefully.',
            'verification': f'show interface {interface_name}, show ip interface brief',
            'related_commands': 'ip address, no shutdown, description, duplex, speed'
        })
    
    # IP address configuration
    elif 'ip address' in cmd_lower:
        analysis.update({
            'purpose': 'Configure IP address and subnet mask on an interface',
            'category': 'IP Configuration',
            'explanation': 'Assigns an IP address and subnet mask to the interface. This is essential for Layer 3 connectivity and routing.',
            'usage_example': f"""Applied under interface configuration:
1. Router(config)# interface [interface-name]
2. Router(config-if)# {command}
3. Router(config-if)# no shutdown
4. Router(config-if)# exit""",
            'prerequisites': 'Must be in interface configuration mode (config-if)#',
            'warnings': 'Ensure no IP conflicts exist in the network. Verify subnet mask is correct.',
            'verification': 'show ip interface brief, show interface [interface], ping [IP]',
            'related_commands': 'interface, no shutdown, ip route'
        })
    
    # Router configuration (routing protocols)
    elif cmd_lower.startswith('router '):
        protocol = command.split()[-1] if len(command.split()) > 1 else "unknown"
        analysis.update({
            'purpose': f'Enter routing protocol configuration mode for {protocol}',
            'category': 'Routing Protocol',
            'explanation': f'Enables and configures the {protocol} routing protocol. This allows the router to exchange routing information with other routers.',
            'usage_example': f"""Routing protocol configuration:
1. Router(config)# {command}
2. Router(config-router)# network [network-address] [wildcard-mask]
3. Router(config-router)# router-id [router-id]
4. Router(config-router)# exit""",
            'prerequisites': 'Must be in global configuration mode (config)#',
            'warnings': 'Incorrect routing configuration can cause routing loops or connectivity issues.',
            'verification': f'show ip {protocol}, show ip route, show ip protocols',
            'related_commands': 'network, router-id, redistribute, default-information'
        })
    
    # Access Control Lists
    elif 'access-list' in cmd_lower or 'ip access-list' in cmd_lower:
        analysis.update({
            'purpose': 'Configure Access Control List for traffic filtering',
            'category': 'Security/ACL',
            'explanation': 'Creates or modifies an Access Control List to permit or deny traffic based on various criteria like source/destination IP, ports, protocols.',
            'usage_example': f"""ACL configuration and application:
1. Router(config)# {command}
2. Router(config)# interface [interface-name]
3. Router(config-if)# ip access-group [acl-name/number] [in|out]
4. Router(config-if)# exit""",
            'prerequisites': 'Must be in global configuration mode (config)#',
            'warnings': 'Incorrect ACL rules can block legitimate traffic. Test thoroughly before deployment.',
            'verification': 'show access-lists, show ip access-lists, show ip interface [interface]',
            'related_commands': 'ip access-group, permit, deny, remark'
        })
    
    # VLAN configuration
    elif cmd_lower.startswith('vlan ') or 'switchport' in cmd_lower:
        analysis.update({
            'purpose': 'Configure VLAN settings',
            'category': 'Switching/VLAN',
            'explanation': 'Configures Virtual LAN settings for network segmentation and broadcast domain control.',
            'usage_example': f"""VLAN configuration:
1. Switch(config)# {command}
2. Switch(config-vlan)# name [vlan-name]
3. Switch(config-vlan)# exit
4. Switch(config)# interface [interface]
5. Switch(config-if)# switchport access vlan [vlan-id]""",
            'prerequisites': 'Must be in global configuration mode (config)#',
            'warnings': 'Ensure VLAN is allowed on trunk ports and exists on all necessary switches.',
            'verification': 'show vlan brief, show interfaces switchport, show vlan id [vlan-id]',
            'related_commands': 'switchport access, switchport mode, vlan name'
        })
    
    # Hostname configuration
    elif cmd_lower.startswith('hostname '):
        hostname = command.split()[-1] if len(command.split()) > 1 else "unknown"
        analysis.update({
            'purpose': f'Set device hostname to {hostname}',
            'category': 'System Configuration',
            'explanation': f'Changes the device hostname which appears in the command prompt and is used for device identification.',
            'usage_example': f"""Hostname configuration:
1. Router> enable
2. Router# configure terminal
3. Router(config)# {command}
4. {hostname}(config)# copy running-config startup-config""",
            'prerequisites': 'Must be in global configuration mode (config)#',
            'warnings': 'Hostname change takes effect immediately and changes the prompt.',
            'verification': 'show running-config | include hostname',
            'related_commands': 'banner motd, banner login, ip domain-name'
        })
    
    # Enable secret/password
    elif 'enable secret' in cmd_lower or 'enable password' in cmd_lower:
        analysis.update({
            'purpose': 'Configure privileged mode password',
            'category': 'Security',
            'explanation': 'Sets the password required to enter privileged EXEC mode (enable mode). Enable secret is encrypted, enable password is not.',
            'usage_example': f"""Password configuration:
1. Router(config)# {command}
2. Router(config)# service password-encryption (optional)
3. Router(config)# copy running-config startup-config""",
            'prerequisites': 'Must be in global configuration mode (config)#',
            'warnings': 'Use strong passwords. Enable secret overrides enable password if both are set.',
            'verification': 'show running-config | include enable',
            'related_commands': 'username, line vty, service password-encryption'
        })
    
    # No shutdown command
    elif cmd_lower == 'no shutdown':
        analysis.update({
            'purpose': 'Administratively enable the interface',
            'category': 'Interface Control',
            'explanation': 'Brings the interface to an administratively up state, allowing it to pass traffic if physically connected.',
            'usage_example': f"""Enable interface:
1. Router(config)# interface [interface-name]
2. Router(config-if)# {command}
3. Router(config-if)# exit""",
            'prerequisites': 'Must be in interface configuration mode (config-if)#',
            'warnings': 'Interface will become active immediately if physically connected.',
            'verification': 'show interfaces, show ip interface brief',
            'related_commands': 'shutdown, interface, show interfaces'
        })
    
    # Shutdown command
    elif cmd_lower == 'shutdown':
        analysis.update({
            'purpose': 'Administratively disable the interface',
            'category': 'Interface Control',
            'explanation': 'Places the interface in an administratively down state, preventing it from passing traffic.',
            'usage_example': f"""Disable interface:
1. Router(config)# interface [interface-name]
2. Router(config-if)# {command}
3. Router(config-if)# exit""",
            'prerequisites': 'Must be in interface configuration mode (config-if)#',
            'warnings': 'Interface will stop passing traffic immediately. Use with caution on production networks.',
            'verification': 'show interfaces, show ip interface brief',
            'related_commands': 'no shutdown, interface, show interfaces'
        })
    
    # Line configuration (console, vty, aux)
    elif cmd_lower.startswith('line '):
        line_type = command.split()[1] if len(command.split()) > 1 else "unknown"
        analysis.update({
            'purpose': f'Configure {line_type} line settings',
            'category': 'Remote Access',
            'explanation': f'Enters line configuration mode for {line_type} connections to configure access parameters like passwords and timeouts.',
            'usage_example': f"""Line configuration:
1. Router(config)# {command}
2. Router(config-line)# password [password]
3. Router(config-line)# login
4. Router(config-line)# exec-timeout [minutes] [seconds]
5. Router(config-line)# exit""",
            'prerequisites': 'Must be in global configuration mode (config)#',
            'warnings': 'Incorrect line configuration can lock you out of remote access.',
            'verification': 'show line, show running-config | section line',
            'related_commands': 'password, login, exec-timeout, transport input'
        })
    
    # Default route
    elif 'ip route 0.0.0.0 0.0.0.0' in cmd_lower or 'ip route 0.0.0.0/0' in cmd_lower:
        analysis.update({
            'purpose': 'Configure default route (gateway of last resort)',
            'category': 'Routing',
            'explanation': 'Sets up a default route that will be used for all destinations not explicitly defined in the routing table.',
            'usage_example': f"""Default route configuration:
1. Router(config)# {command}
2. Router(config)# exit
3. Router# show ip route""",
            'prerequisites': 'Must be in global configuration mode (config)#',
            'warnings': 'Default route affects all traffic to unknown destinations.',
            'verification': 'show ip route, ping [external-ip], traceroute [external-ip]',
            'related_commands': 'ip route, show ip route, no ip route'
        })
    
    # Static routes
    elif cmd_lower.startswith('ip route '):
        analysis.update({
            'purpose': 'Configure static route',
            'category': 'Routing',
            'explanation': 'Manually defines a route to a specific network destination. Static routes have administrative distance of 1 by default.',
            'usage_example': f"""Static route configuration:
1. Router(config)# {command}
2. Router(config)# exit
3. Router# show ip route static""",
            'prerequisites': 'Must be in global configuration mode (config)#',
            'warnings': 'Ensure next-hop address is reachable and correct.',
            'verification': 'show ip route, show ip route static, ping [destination]',
            'related_commands': 'no ip route, ip route summary, show ip route'
        })
    
    # Spanning Tree Protocol
    elif 'spanning-tree' in cmd_lower:
        analysis.update({
            'purpose': 'Configure Spanning Tree Protocol settings',
            'category': 'Switching/STP',
            'explanation': 'Configures STP parameters to prevent loops in switched networks while providing redundancy.',
            'usage_example': f"""STP configuration:
1. Switch(config)# {command}
2. Switch(config)# exit
3. Switch# show spanning-tree""",
            'prerequisites': 'Must be in global configuration mode (config)#',
            'warnings': 'STP changes can cause temporary network disruption during convergence.',
            'verification': 'show spanning-tree, show spanning-tree summary',
            'related_commands': 'spanning-tree mode, spanning-tree portfast, spanning-tree cost'
        })
    
    # Default case for unknown commands
    else:
        # Try to categorize based on common patterns
        if any(word in cmd_lower for word in ['ip', 'address', 'route']):
            analysis['category'] = 'IP/Routing'
        elif any(word in cmd_lower for word in ['interface', 'port', 'duplex', 'speed']):
            analysis['category'] = 'Interface'
        elif any(word in cmd_lower for word in ['vlan', 'trunk', 'access']):
            analysis['category'] = 'Switching'
        elif any(word in cmd_lower for word in ['security', 'password', 'secret', 'auth']):
            analysis['category'] = 'Security'
        
        analysis.update({
            'explanation': f'This appears to be a {vendor.upper()} configuration command. Refer to vendor documentation for specific details.',
            'usage_example': f"""General command application:
1. Router/Switch> enable
2. Router/Switch# configure terminal
3. Router/Switch(config)# {command}
4. Router/Switch(config)# exit
5. Router/Switch# copy running-config startup-config""",
            'prerequisites': 'Appropriate configuration mode access',
            'warnings': 'Test configuration changes in lab environment first',
            'verification': 'show running-config, show [relevant-status-command]',
            'related_commands': 'Consult vendor documentation'
        })
    
    return analysis

def get_vendor_specific_notes(vendor):
    """
    Return vendor-specific implementation notes
    """
    vendor_notes = {
        'cisco': {
            'config_mode': 'configure terminal',
            'save_config': 'copy running-config startup-config',
            'exit_config': 'exit or end',
            'show_config': 'show running-config'
        },
        'cisco_xr': {
            'config_mode': 'configure',
            'save_config': 'commit',
            'exit_config': 'exit or end',
            'show_config': 'show running-config'
        },
        'juniper': {
            'config_mode': 'configure',
            'save_config': 'commit',
            'exit_config': 'exit',
            'show_config': 'show configuration'
        },
        'arista': {
            'config_mode': 'configure terminal',
            'save_config': 'write memory',
            'exit_config': 'exit or end',
            'show_config': 'show running-config'
        }
    }
    
    return vendor_notes.get(vendor.lower(), vendor_notes['cisco'])

def get_action_from_prompt_with_device(prompt, device_info=None):
    """
    Enhanced version that takes device info dict and uses appropriate device type
    """
    device_type = "cisco_ios"  # default
    
    if device_info and "device_type" in device_info:
        device_type = device_info["device_type"]
    
    # Check if this is a show command request
    prompt_lower = prompt.lower()
    show_indicators = [
        "show", "display", "get", "list", "check status", 
        "what is", "tell me about", "provide information",
        "all commands", "give all"
    ]
    
    if any(indicator in prompt_lower for indicator in show_indicators):
        # Use the device-specific show command generator
        commands = get_device_show_commands(prompt, device_info or {"device_type": device_type})
        if isinstance(commands, list) and commands:
            if isinstance(commands[0], tuple):
                # Help keywords - format as help response
                return "Available commands:\n" + "\n".join([f"{k}: {d}" for k, d in commands])
            else:
                # Actual commands
                return "\n".join(commands)
        return ""
    
    return get_action_from_prompt(prompt, device_type)
# -------------------------------------------------------------------
# Backward compatibility wrapper for flask_code2.py
def explain_commands(commands, vendor="cisco"):
    """
    Compatibility wrapper so flask_code2.py can import `explain_commands`.
    Internally uses explain_commands_with_usage.
    """
    return explain_commands_with_usage(commands, vendor)
