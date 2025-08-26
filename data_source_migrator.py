#!/usr/bin/env python3
"""
Nobl9 Data Source Migrator v1.0

Created by: Jeremy Cooper (Nobl9)
Support: Community-supported script (not officially supported by Nobl9)

This script lists existing data sources in Nobl9 and shows how many SLOs each supports.
Users can then select data sources and view SLOs grouped by project and service.

IMPORTANT: This script is NOT officially supported by Nobl9. It is a community-contributed 
tool created by Jeremy Cooper, a Nobl9 employee, for internal and community use.
Use at your own risk - this is not production-tested by Nobl9.
"""

import base64
import copy
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Constants for better maintainability
DEFAULT_PROJECT = 'Unknown'
DEFAULT_SERVICE = 'Unknown'
DEFAULT_NAME = 'Unknown'
DEFAULT_KIND = 'Unknown'
DEFAULT_SLO_COUNT = 0

# Display constants
SEPARATOR_LENGTH = 80
SUBSECTION_LENGTH = 60
INDENT_SIZE = 2

# File naming constants
LOG_DIR_NAME = "data_source_logs"
OUTPUT_DIR_NAME = "slo_yaml_files"
LOG_FILE_PREFIX = "data_source_migrator_"

try:
    import toml
    import requests
    import yaml
    from colorama import Fore, Style, init
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Please install required packages: "
          "pip install colorama toml requests PyYAML")
    sys.exit(1)

# Initialize colorama for cross-platform colored output
init(autoreset=True)


class Colors:
    """Color constants using colorama."""
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL


def print_colored(text: str, color: str, end: str = "\n") -> None:
    """Print colored text to terminal."""
    print(f"{color}{text}{Colors.RESET}", end=end)


def setup_logging() -> Path:
    """Setup logging to a local file with cross-platform path handling."""
    # Use absolute path for better cross-platform compatibility
    current_dir = Path.cwd()
    log_dir = current_dir / LOG_DIR_NAME
    log_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"{LOG_FILE_PREFIX}{timestamp}.log"
    return log_file


def log_message(log_file: Path, message: str, level: str = "INFO") -> None:
    """Log message to file with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {level}: {message}\n"
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except Exception as e:
        print_colored(f"Warning: Could not write to log file: {e}", 
                      Colors.YELLOW)
    
    if level == "ERROR":
        print_colored(message, Colors.RED)
    elif level == "WARNING":
        print_colored(message, Colors.YELLOW)
    elif level == "SUCCESS":
        print_colored(message, Colors.GREEN)
    # INFO messages are only logged to file, not printed to console


def check_dependencies() -> None:
    """Check if required dependencies are installed with cross-platform support."""
    try:
        # Try to run sloctl version
        result = subprocess.run(
            ["sloctl", "version"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        print(f"{Colors.GREEN}✓ sloctl found: "
              f"{result.stdout.strip()}{Colors.RESET}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Colors.RED}Error: sloctl is not installed or not in PATH."
              f"{Colors.RESET}")
        print(f"{Colors.YELLOW}Please install sloctl from: "
              f"https://docs.nobl9.com/sloctl/{Colors.RESET}")
        
        # Platform-specific installation hints
        if os.name == 'nt':  # Windows
            print(f"{Colors.CYAN}Windows installation tips:{Colors.RESET}")
            print(f"  1. Download from: "
                  f"https://github.com/nobl9/sloctl/releases")
            print(f"  2. Extract to a folder (e.g., C:\\sloctl)")
            print(f"  3. Add the folder to your PATH environment variable")
            print(f"  4. Or run from the extracted folder directly")
        else:  # Unix-like systems
            print(f"{Colors.CYAN}Unix/Linux/macOS installation tips:{Colors.RESET}")
            print(f"  1. Use package manager: "
                  f"brew install nobl9/tap/sloctl (macOS)")
            print(f"  2. Or download from: "
                  f"https://github.com/nobl9/sloctl/releases")
        
        sys.exit(1)


def load_toml_config() -> Dict[str, Any]:
    """Load and parse TOML configuration with enhanced error handling 
    and cross-platform support."""
    # Try multiple possible config locations for cross-platform compatibility
    possible_config_paths = [
        # Unix/Linux/macOS
        os.path.expanduser("~/.config/nobl9/config.toml"),
        # Windows
        os.path.join(
            os.path.expanduser("~"), 
            "AppData", 
            "Roaming", 
            "nobl9", 
            "config.toml"
        ),
        os.path.join(
            os.path.expanduser("~"), 
            "AppData", 
            "Local", 
            "nobl9", 
            "config.toml"
        ),
        # Environment variable override
        os.getenv("NOBL9_CONFIG_PATH"),
        # Current directory
        "./config.toml",
        # Windows ProgramData
        os.path.join(
            os.environ.get("PROGRAMDATA", "C:\\ProgramData"), 
            "nobl9", 
            "config.toml"
        )
    ]
    
    config_path = None
    for path in possible_config_paths:
        if path and os.path.isfile(path):
            config_path = path
            break
    
    if not config_path:
        print(f"{Colors.RED}Config not found. "
              f"Tried the following locations:{Colors.RESET}")
        for path in possible_config_paths:
            if path:
                print(f"  - {path}")
        print(f"\n{Colors.YELLOW}Please ensure your Nobl9 config file exists in "
              f"one of these locations.{Colors.RESET}")
        print(f"{Colors.CYAN}You can also set NOBL9_CONFIG_PATH environment variable "
              f"to specify a custom location.{Colors.RESET}")
        sys.exit(1)
    
    try:
        config = toml.load(config_path)
        print(f"{Colors.GREEN}✓ Loaded config from: {config_path}{Colors.RESET}")
        return config
    except Exception as e:
        print(f"{Colors.RED}Error loading TOML config from {config_path}: {e}{Colors.RESET}")
        sys.exit(1)


def load_contexts_from_toml() -> List[Dict[str, Any]]:
    """Load contexts from TOML config with custom instance detection."""
    config = load_toml_config()
    contexts = []
    raw_contexts = config.get("contexts", {})
    
    for context_name, context_data in raw_contexts.items():
        if isinstance(context_data, dict):
            is_custom_instance = "url" in context_data
            base_url = context_data.get("url", "https://app.nobl9.com")
            client_id = (
                context_data.get("clientId") or 
                context_data.get("client_id", "")
            )
            client_secret = (
                context_data.get("clientSecret") or 
                context_data.get("client_secret", "")
            )
            org = (
                context_data.get("organization") or 
                context_data.get("org", "")
            )
            access_token = context_data.get("accessToken", "")
            
            contexts.append({
                "name": context_name,
                "client_id": client_id,
                "client_secret": client_secret,
                "org": org,
                "access_token": access_token,
                "is_custom_instance": is_custom_instance,
                "base_url": base_url
            })
    return contexts


def decode_jwt_payload(token: str) -> Optional[str]:
    """Decode JWT token to extract organization info."""
    try:
        payload_b64 = token.split('.')[1]
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload_json = base64.b64decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)
        return payload.get('m2mProfile', {}).get('organization', None)
    except Exception:
        return None


def get_token_from_credentials(credentials: Dict[str, Any], 
                              log_file: Path) -> Tuple[str, str, bool, str]:
    """Get access token using credentials with custom instance support."""
    client_id = credentials["client_id"]
    client_secret = credentials["client_secret"]
    org = credentials["org"]
    is_custom_instance = credentials.get("is_custom_instance", False)
    base_url = credentials.get("base_url", "https://app.nobl9.com")
    
    if not client_id or not client_secret:
        log_message(log_file, 
                   "ERROR: Missing client_id or client_secret in context.", 
                   "ERROR")
        sys.exit(1)
    
    if not org and credentials.get("access_token"):
        org = decode_jwt_payload(credentials["access_token"])
    if not org:
        org = os.getenv("SLOCTL_ORGANIZATION")
    if not org:
        log_message(log_file, 
                   "ERROR: Missing organization in context. Please check your TOML configuration.", 
                   "ERROR")
        sys.exit(1)
    
    auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    headers = {
        "Accept": "application/json; version=v1alpha",
        "Organization": org,
        "Authorization": f"Basic {auth}"
    }
    token_url = f"{base_url}/api/accessToken"
    log_message(log_file, f"Authenticating with {token_url}", "INFO")
    
    resp = requests.post(token_url, headers=headers)
    if resp.status_code != 200:
        log_message(log_file, 
                   f"Failed to retrieve token. Status: {resp.status_code}", 
                   "ERROR")
        try:
            error_data = resp.json()
            if isinstance(error_data, dict):
                error_msg = error_data.get("message", "Unknown error")
            else:
                error_msg = str(error_data)
            log_message(log_file, f"Error: {error_msg}", "ERROR")
        except Exception:
            log_message(log_file, f"Response: {resp.text}", "ERROR")
        sys.exit(1)
    
    try:
        token_data = resp.json()
        if "access_token" not in token_data:
            log_message(log_file, 
                       f"No access_token in response: {token_data}", 
                       "ERROR")
            sys.exit(1)
    except json.JSONDecodeError:
        log_message(log_file, f"Invalid JSON response: {resp.text}", "ERROR")
        sys.exit(1)
    
    log_message(log_file, "✓ Access token acquired", "SUCCESS")
    if is_custom_instance:
        log_message(log_file, f"Instance: {base_url}", "INFO")
    
    return token_data["access_token"], org, is_custom_instance, base_url


def enhanced_choose_context() -> Tuple[str, Dict[str, Any]]:
    """Enhanced context selection with custom instance support."""
    contexts = load_contexts_from_toml()
    if not contexts:
        print(f"{Colors.RED}No contexts found in TOML config.{Colors.RESET}")
        sys.exit(1)
    
    print(f"{Colors.CYAN}Available contexts:{Colors.RESET}")
    for i, context in enumerate(contexts, 1):
        instance_info = (
            f" (Custom: {context['base_url']})" 
            if context['is_custom_instance'] else ""
        )
        print(f"  [{i}] {context['name']}{instance_info}")
    
    while True:
        try:
            choice = input(
                f"\n{Colors.CYAN}Select context [1-{len(contexts)}]: "
                f"{Colors.RESET}"
            ).strip()
            if not choice:
                print(f"{Colors.RED}Please enter a valid choice.{Colors.RESET}")
                continue
            
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(contexts):
                selected_context = contexts[choice_idx]
                result = subprocess.run(
                    ["sloctl", "config", "use-context", selected_context["name"]],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    print(f"{Colors.YELLOW}Warning: Could not set sloctl context: "
                          f"{result.stderr}{Colors.RESET}")
                return selected_context["name"], selected_context
            else:
                print(f"{Colors.RED}Invalid choice. Please enter a number between "
                      f"1 and {len(contexts)}.{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}Invalid input. Please enter a number.{Colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Exiting...{Colors.RESET}")
            sys.exit(0)


def get_current_sloctl_context() -> Optional[str]:
    """Get the current sloctl context name."""
    try:
        result = subprocess.run(
            ["sloctl", "config", "current-context"],
            capture_output=True, text=True, check=True
        )
        context_name = result.stdout.strip()
        
        # Check if we got a valid context name
        if context_name and len(context_name) < 100:
            return context_name
        else:
            return None
            
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def restore_sloctl_context(original_context: str) -> None:
    """Restore the original sloctl context."""
    try:
        result = subprocess.run(
            ["sloctl", "config", "use-context", original_context],
            capture_output=True, text=True, check=True
        )
        print(f"{Colors.GREEN}✓ Restored sloctl context to: {original_context}{Colors.RESET}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Colors.YELLOW}Warning: Could not restore sloctl context to: {original_context}{Colors.RESET}")
        print(f"{Colors.YELLOW}Please manually restore your context: sloctl config use-context {original_context}{Colors.RESET}")


def fetch_all_data_sources() -> List[Dict[str, Any]]:
    """Fetch all available data sources using sloctl get agents -A and sloctl get directs -A."""
    print(f"{Colors.CYAN}Fetching all available data sources...{Colors.RESET}")
    all_data_sources = []
    
    # Define data source types to fetch
    ds_types = [
        ("agents", "Agent"),
        ("directs", "Direct")
    ]
    
    for ds_type, kind in ds_types:
        try:
            print(f"{Colors.CYAN}Fetching {ds_type}...{Colors.RESET}")
            result = subprocess.run(
                ["sloctl", "get", ds_type, "-A", "-o", "json"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse JSON response
            try:
                items = json.loads(result.stdout)
                # Handle both single item and list responses
                if isinstance(items, dict):
                    items = [items]
                elif not isinstance(items, list):
                    items = []
            except json.JSONDecodeError as e:
                print(f"{Colors.YELLOW}Note: No {ds_type} data sources found or empty response.{Colors.RESET}")
                print(f"{Colors.CYAN}This is normal if you don't have {ds_type} configured in your Nobl9 instance.{Colors.RESET}")
                print(f"{Colors.CYAN}The script will continue with other data source types.{Colors.RESET}")
                items = []
            
            # Process items more efficiently
            for item in items:
                if isinstance(item, dict) and 'metadata' in item:
                    metadata = item['metadata']
                    all_data_sources.append({
                        'metadata': {
                            'name': metadata.get('name', DEFAULT_NAME),
                            'displayName': (
                                metadata.get('displayName', metadata.get('name', DEFAULT_NAME))
                            ),
                            'project': metadata.get('project', DEFAULT_PROJECT),
                            'kind': kind
                        },
                        'slo_count': DEFAULT_SLO_COUNT
                    })
            
            print(f"{Colors.GREEN}Retrieved {len(items)} {ds_type}{Colors.RESET}")
            
        except subprocess.CalledProcessError as e:
            print(f"{Colors.YELLOW}Note: Could not fetch {ds_type} data sources.{Colors.RESET}")
            print(f"{Colors.CYAN}This might be due to permissions or {ds_type} not being configured.{Colors.RESET}")
            print(f"{Colors.CYAN}Error details: {e}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}Note: Unexpected error while processing {ds_type}.{Colors.RESET}")
            print(f"{Colors.CYAN}Error details: {e}{Colors.RESET}")
    
    print(f"{Colors.CYAN}Before deduplication: {len(all_data_sources)} data sources{Colors.RESET}")
    
    # Remove duplicates more efficiently using dict comprehension
    unique_data_sources = {}
    for data_source in all_data_sources:
        key = (data_source['metadata']['name'], data_source['metadata']['project'])
        if key not in unique_data_sources:
            unique_data_sources[key] = data_source
    
    result_list = list(unique_data_sources.values())
    print(f"{Colors.GREEN}Total unique data sources: {len(result_list)}{Colors.RESET}")
    
    return result_list


def fetch_slo_data_yaml() -> str:
    """Fetch SLO data from Nobl9 using sloctl in YAML format."""
    print(f"{Colors.CYAN}Fetching SLO data from Nobl9...{Colors.RESET}")
    try:
        result = subprocess.run(
            ["sloctl", "get", "slos", "-A", "-o", "yaml"], 
            capture_output=True, text=True, check=True
        )
        yaml_content = result.stdout
        print(f"{Colors.GREEN}Retrieved SLO data in YAML format{Colors.RESET}")
        return yaml_content
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}Failed to fetch SLO data: {e}{Colors.RESET}")
        print(f"{Colors.YELLOW}Please check your Nobl9 configuration.{Colors.RESET}")
        sys.exit(1)


def parse_yaml_slos(yaml_content: str) -> List[Dict[str, Any]]:
    """Parse YAML content and extract SLO data."""
    try:
        documents = list(yaml.safe_load_all(yaml_content))
        print(f"{Colors.GREEN}Parsed {len(documents)} documents from YAML{Colors.RESET}")
        
        # Extract SLOs from documents
        slos = []
        for doc in documents:
            if isinstance(doc, dict):
                # Single SLO document
                slos.append(doc)
            elif isinstance(doc, list):
                # List of SLOs
                slos.extend(doc)
            else:
                print(f"{Colors.YELLOW}Warning: Skipping document of type "
                      f"{type(doc)}{Colors.RESET}")
        
        print(f"{Colors.GREEN}Extracted {len(slos)} SLOs from YAML{Colors.RESET}")
        return slos
    except yaml.YAMLError as e:
        print(f"{Colors.RED}Failed to parse YAML: {e}{Colors.RESET}")
        sys.exit(1)


def extract_data_sources_from_slos(slos: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Extract unique data sources from SLO data."""
    data_sources = {}
    
    for slo in slos:
        # Extract metricSource information
        if 'spec' in slo and 'indicator' in slo['spec']:
            indicator = slo['spec']['indicator']
            if isinstance(indicator, dict) and 'metricSource' in indicator:
                metric_source = indicator['metricSource']
                if isinstance(metric_source, dict) and 'name' in metric_source:
                    data_source_name = metric_source['name']
                    data_source_kind = metric_source.get('kind', DEFAULT_KIND)
                    data_source_project = metric_source.get('project', DEFAULT_PROJECT)
                    
                    if data_source_name not in data_sources:
                        # Create data source entry with full metricSource info
                        data_sources[data_source_name] = {
                            'metadata': {
                                'name': data_source_name,
                                'displayName': data_source_name,
                                'project': data_source_project,
                                'kind': data_source_kind
                            },
                            'slo_count': DEFAULT_SLO_COUNT  # Will be updated in count_slos_per_data_source
                        }
    
    print(f"{Colors.GREEN}Found {len(data_sources)} unique data sources "
          f"with SLOs{Colors.RESET}")
    return data_sources


def count_slos_per_data_source(data_sources: List[Dict[str, Any]], 
                              slos: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count how many SLOs use each data source."""
    slo_counts = {}
    
    for slo in slos:
        data_source_name = (slo.get('spec', {})
                           .get('indicator', {})
                           .get('metricSource', {})
                           .get('name'))
        
        if data_source_name:
            slo_counts[data_source_name] = slo_counts.get(data_source_name, 0) + 1
    
    return slo_counts


def update_data_sources_with_slo_counts(
    all_data_sources: List[Dict[str, Any]], 
    slo_counts: Dict[str, int]
) -> List[Dict[str, Any]]:
    """Update all data sources with their SLO counts."""
    for data_source in all_data_sources:
        data_source_name = data_source['metadata']['name']
        data_source['slo_count'] = slo_counts.get(data_source_name, 0)
    
    return all_data_sources


def display_data_sources(data_sources: List[Dict[str, Any]], 
                        slo_counts: Dict[str, int]) -> None:
    """Display data sources with SLO counts."""
    print(f"\n{Colors.CYAN}Available Data Sources:{Colors.RESET}")
    print("=" * SEPARATOR_LENGTH)
    
    for i, data_source in enumerate(data_sources, 1):
        name = data_source.get('metadata', {}).get('name', DEFAULT_NAME)
        display_name = data_source.get('metadata', {}).get('displayName', name)
        project = data_source.get('metadata', {}).get('project', DEFAULT_PROJECT)
        kind = data_source.get('metadata', {}).get('kind', DEFAULT_KIND)
        slo_count = slo_counts.get(name, DEFAULT_SLO_COUNT)
        
        print(f"  [{i:2d}] {Colors.YELLOW}{display_name}{Colors.RESET}")
        print(f"       Name: {name}")
        print(f"       Project: {project}")
        print(f"       Kind: {kind}")
        print(f"       SLOs: {Colors.GREEN}{slo_count}{Colors.RESET}")
        print()


def select_data_sources(data_sources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Let user select one data source for migration."""
    print(f"{Colors.CYAN}Data Source Selection{Colors.RESET}")
    print("Select one data source to migrate SLOs from:")
    
    while True:
        try:
            choice = input(f"\n{Colors.CYAN}Enter your selection: {Colors.RESET}").strip()
            
            # Parse single number
            if choice.isdigit():
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(data_sources):
                    selected = [data_sources[choice_idx]]
                    selected_name = selected[0].get('metadata', {}).get('name', DEFAULT_NAME)
                    print(f"{Colors.GREEN}Selected: {selected_name}{Colors.RESET}")
                    return selected
                else:
                    print(f"{Colors.RED}Invalid selection. Please enter a number between "
                          f"1 and {len(data_sources)}.{Colors.RESET}")
            else:
                print(f"{Colors.RED}Invalid input. Please enter a single number.{Colors.RESET}")
                
        except ValueError:
            print(f"{Colors.RED}Invalid input. Please enter a number.{Colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Exiting...{Colors.RESET}")
            sys.exit(0)


def extract_service_from_slo(slo: Dict[str, Any]) -> str:
    """Extract service information from SLO with optimized lookups."""
    return (slo.get('spec', {}).get('service') or
            slo.get('metadata', {}).get('service') or
            slo.get('spec', {}).get('indicator', {}).get('service') or
            'Unknown')


def group_slos_by_project_and_service(
    slos: List[Dict[str, Any]], 
    selected_data_sources: List[Dict[str, Any]]
) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """Group SLOs by project and service for selected data sources with optimized lookups."""
    # Pre-compute selected data source names for faster lookup
    selected_ds_names = {ds.get('metadata', {}).get('name') for ds in selected_data_sources}
    grouped_slos = {}
    
    for slo in slos:
        # Extract data source name more efficiently
        slo_ds_name = (slo.get('spec', {})
                       .get('indicator', {})
                       .get('metricSource', {})
                       .get('name'))
        
        if slo_ds_name not in selected_ds_names:
            continue
        
        # Extract project and service once
        project = slo.get('metadata', {}).get('project', DEFAULT_PROJECT)
        service = extract_service_from_slo(slo)
        
        # Use dict.setdefault for cleaner and more efficient code
        grouped_slos.setdefault(project, {}).setdefault(service, []).append(slo)
    
    return grouped_slos


def display_grouped_slos(
    grouped_slos: Dict[str, Dict[str, List[Dict[str, Any]]]]
) -> None:
    """Display SLOs grouped by project and service."""
    print(f"\n{Colors.CYAN}SLOs by Project and Service:{Colors.RESET}")
    print("=" * SEPARATOR_LENGTH)
    
    total_slos = 0
    for project, services in grouped_slos.items():
        project_slos = sum(len(slos) for slos in services.values())
        total_slos += project_slos
        
        print(f"\n{Colors.YELLOW}Project: {project}{Colors.RESET} "
              f"({project_slos} SLOs)")
        print("-" * SUBSECTION_LENGTH)
        
        for service, slos in services.items():
            print(f"  {Colors.CYAN}Service: {service}{Colors.RESET} "
                  f"({len(slos)} SLOs)")
            for i, slo in enumerate(slos, 1):
                name = slo.get('metadata', {}).get('name', DEFAULT_NAME)
                display_name = slo.get('metadata', {}).get('displayName', name)
                print(f"    [{i:2d}] {display_name}")
            print()
    
    print(f"{Colors.GREEN}Total SLOs: {total_slos}{Colors.RESET}")


def select_slos_from_grouped(
    grouped_slos: Dict[str, Dict[str, List[Dict[str, Any]]]]
) -> List[Dict[str, Any]]:
    """Let user select SLOs from the grouped display."""
    print(f"\n{Colors.CYAN}SLO Selection Options:{Colors.RESET}")
    print("  [1] All SLOs")
    print("  [2] All SLOs in a specific project")
    print("  [3] All SLOs in a specific service")
    print("  [4] Individual SLOs")
    
    while True:
        try:
            choice = input(f"\n{Colors.CYAN}Select option: {Colors.RESET}").strip()
            
            if choice == '1':
                # All SLOs
                all_slos = []
                for project in grouped_slos.values():
                    for service in project.values():
                        all_slos.extend(service)
                print(f"{Colors.GREEN}Selected all {len(all_slos)} SLOs{Colors.RESET}")
                return all_slos
            
            elif choice == '2':
                # All SLOs in a project
                projects = list(grouped_slos.keys())
                print(f"\n{Colors.CYAN}Available Projects:{Colors.RESET}")
                for i, project in enumerate(projects, 1):
                    project_slos = sum(len(slos) for slos in grouped_slos[project].values())
                    print(f"  [{i}] {project} ({project_slos} SLOs)")
                
                project_choice = int(input(
                    f"\n{Colors.CYAN}Select project: {Colors.RESET}"
                )) - 1
                if 0 <= project_choice < len(projects):
                    selected_project = projects[project_choice]
                    project_slos = []
                    for service in grouped_slos[selected_project].values():
                        project_slos.extend(service)
                    print(f"{Colors.GREEN}Selected {len(project_slos)} SLOs from project "
                          f"{selected_project}{Colors.RESET}")
                    return project_slos
                else:
                    print(f"{Colors.RED}Invalid project selection.{Colors.RESET}")
            
            elif choice == '3':
                # All SLOs in a service
                all_services = []
                for project, services in grouped_slos.items():
                    for service_name, slos in services.items():
                        all_services.append((f"{project}/{service_name}", slos))
                
                print(f"\n{Colors.CYAN}Available Services:{Colors.RESET}")
                for i, (service_path, slos) in enumerate(all_services, 1):
                    print(f"  [{i}] {service_path} ({len(slos)} SLOs)")
                
                service_choice = int(input(
                    f"\n{Colors.CYAN}Select service: {Colors.RESET}"
                )) - 1
                if 0 <= service_choice < len(all_services):
                    selected_service_path, selected_slos = all_services[service_choice]
                    print(f"{Colors.GREEN}Selected {len(selected_slos)} SLOs from service "
                          f"{selected_service_path}{Colors.RESET}")
                    return selected_slos
                else:
                    print(f"{Colors.RED}Invalid service selection.{Colors.RESET}")
            
            elif choice == '4':
                # Individual SLOs
                all_slos = []
                slo_index = 1
                slo_map = {}
                
                print(f"\n{Colors.CYAN}All Available SLOs:{Colors.RESET}")
                for project, services in grouped_slos.items():
                    print(f"\n{Colors.YELLOW}Project: {project}{Colors.RESET}")
                    for service, slos in services.items():
                        print(f"  {Colors.CYAN}Service: {service}{Colors.RESET}")
                        for slo in slos:
                            name = slo.get('metadata', {}).get('name', DEFAULT_NAME)
                            display_name = slo.get('metadata', {}).get('displayName', name)
                            slo_project = slo.get('metadata', {}).get('project', DEFAULT_PROJECT)
                            slo_service = extract_service_from_slo(slo)
                            print(f"    [{slo_index:3d}] {display_name} "
                                  f"({slo_project}/{slo_service})")
                            slo_map[slo_index] = slo
                            slo_index += 1
                
                print(f"\n{Colors.CYAN}Enter SLO numbers separated by commas "
                      f"(e.g., 1,3,5):{Colors.RESET}")
                slo_choices = input(f"{Colors.CYAN}Selection: {Colors.RESET}").strip()
                
                try:
                    selected_indices = [
                        int(x.strip()) for x in slo_choices.split(',') 
                        if x.strip().isdigit()
                    ]
                    selected_slos = [
                        slo_map[idx] for idx in selected_indices 
                        if idx in slo_map
                    ]
                    print(f"{Colors.GREEN}Selected {len(selected_slos)} SLOs{Colors.RESET}")
                    return selected_slos
                except (ValueError, KeyError):
                    print(f"{Colors.RED}Invalid SLO selection.{Colors.RESET}")
            
            else:
                print(f"{Colors.RED}Invalid option. Please choose 1, 2, 3, or 4.{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Exiting...{Colors.RESET}")
            sys.exit(0)


def select_target_data_source(
    all_data_sources: List[Dict[str, Any]]
) -> Dict[str, Optional[str]]:
    """Let user select target data source for SLO migration from all available data sources."""
    if not all_data_sources:
        print(f"{Colors.RED}Error: No data sources available for selection.{Colors.RESET}")
        print(f"{Colors.YELLOW}This should not happen. Please check your Nobl9 configuration.{Colors.RESET}")
        sys.exit(1)
    
    # Sort data sources: those with SLOs first (by display name), then those without SLOs (by display name)
    data_sources_with_slos = [ds for ds in all_data_sources if ds.get('slo_count', 0) > 0]
    data_sources_without_slos = [ds for ds in all_data_sources if ds.get('slo_count', 0) == 0]
    
    # Sort each group by display name
    data_sources_with_slos.sort(key=lambda x: x.get('metadata', {}).get('displayName', '').lower())
    data_sources_without_slos.sort(key=lambda x: x.get('metadata', {}).get('displayName', '').lower())
    
    # Combine the sorted lists: WITH SLOs first, then WITHOUT SLOs
    sorted_data_sources = data_sources_with_slos + data_sources_without_slos
    
    # Debug: Show the sorting groups
    print(f"{Colors.CYAN}Data sources with SLOs ({len(data_sources_with_slos)}):{Colors.RESET}")
    for ds in data_sources_with_slos:
        display_name = ds.get('metadata', {}).get('displayName', 'Unknown')
        slo_count = ds.get('slo_count', 0)
        print(f"  - {display_name}: {slo_count} SLOs")
    
    print(f"\n{Colors.CYAN}Data sources without SLOs ({len(data_sources_without_slos)}):{Colors.RESET}")
    for ds in data_sources_without_slos:
        display_name = ds.get('metadata', {}).get('displayName', 'Unknown')
        slo_count = ds.get('slo_count', 0)
        print(f"  - {display_name}: {slo_count} SLOs")
    
    print(f"\n{Colors.CYAN}Target Data Source Selection{Colors.RESET}")
    print("Select the target data source from all available data sources:")
    print("(This includes data sources with and without SLOs)")
    
    # Display all available data sources
    for i, data_source in enumerate(sorted_data_sources, 1):
        name = data_source.get('metadata', {}).get('name', DEFAULT_NAME)
        display_name = data_source.get('metadata', {}).get('displayName', name)
        project = data_source.get('metadata', {}).get('project', DEFAULT_PROJECT)
        kind = data_source.get('metadata', {}).get('kind', DEFAULT_KIND)
        slo_count = data_source.get('slo_count', DEFAULT_SLO_COUNT)
        
        # Highlight data sources with no SLOs as potential migration targets
        if slo_count == 0:
            print(f"  [{i:2d}] {Colors.GREEN}{display_name}{Colors.RESET} "
                  f"({project}, {kind}) - {Colors.YELLOW}No SLOs{Colors.RESET}")
        else:
            print(f"  [{i:2d}] {Colors.YELLOW}{display_name}{Colors.RESET} "
                  f"({project}, {kind}) - {slo_count} SLOs")
    
    while True:
        try:
            choice = input(
                f"\n{Colors.CYAN}Select target data source "
                f"[1-{len(sorted_data_sources)}]: {Colors.RESET}"
            ).strip()
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(sorted_data_sources):
                selected_ds = sorted_data_sources[choice_idx]
                name = selected_ds.get('metadata', {}).get('name', DEFAULT_NAME)
                display_name = selected_ds.get('metadata', {}).get('displayName', name)
                project = selected_ds.get('metadata', {}).get('project', DEFAULT_PROJECT)
                kind = selected_ds.get('metadata', {}).get('kind', DEFAULT_KIND)
                slo_count = selected_ds.get('slo_count', DEFAULT_SLO_COUNT)
                
                if slo_count == 0:
                    print(f"{Colors.GREEN}Selected: {display_name} ({project}, {kind}) - "
                          f"{Colors.YELLOW}No SLOs (Good migration target){Colors.RESET}")
                else:
                    print(f"{Colors.GREEN}Selected: {display_name} ({project}, {kind}) - "
                          f"{slo_count} SLOs{Colors.RESET}")
                
                return {
                    'name': name,
                    'project': project,
                    'kind': kind
                }
            else:
                print(f"{Colors.RED}Invalid choice. Please enter a number between "
                      f"1 and {len(sorted_data_sources)}.{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}Invalid input. Please enter a number.{Colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Exiting...{Colors.RESET}")
            sys.exit(0)


def update_slo_data_source(
    slo: Dict[str, Any], 
    target_ds: Dict[str, Optional[str]]
) -> Dict[str, Any]:
    """Update SLO's metricSource with new data source information."""
    # Create a deep copy to avoid modifying the original
    updated_slo = slo.copy()
    
    # Update the metricSource in the indicator
    if 'spec' in updated_slo and 'indicator' in updated_slo['spec']:
        indicator = updated_slo['spec']['indicator']
        if isinstance(indicator, dict):
            # Update metricSource
            indicator['metricSource'] = {
                'name': target_ds['name'],
                'kind': target_ds['kind']
            }
            
            # Add project if specified, otherwise use SLO's project
            if target_ds['project']:
                indicator['metricSource']['project'] = target_ds['project']
    
    return updated_slo


def save_yaml_content(
    yaml_content: str, 
    selected_slos: List[Dict[str, Any]], 
    updated_slos: List[Dict[str, Any]], 
    log_file: Path,
    source_ds_name: str,
    target_ds_name: str
) -> None:
    """Save YAML content and selected SLOs for later use."""
    try:
        # Create output directory with cross-platform path handling
        current_dir = Path.cwd()
        output_dir = current_dir / OUTPUT_DIR_NAME
        output_dir.mkdir(exist_ok=True)
        
        # Generate timestamp for uniqueness
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create new file naming convention: timestamp_source_destination_type.yaml
        base_filename = f"{timestamp}_{source_ds_name}_{target_ds_name}"
        
        # Save full YAML content (commented out for v1.0 - focus on migration files only)
        # yaml_file = output_dir / f"{timestamp}_full_slo_snapshot.yaml"
        # with open(yaml_file, 'w', encoding='utf-8') as f:
        #     f.write(yaml_content)
        
        # Save original selected SLOs
        original_file = output_dir / f"{base_filename}_original.yaml"
        with open(original_file, 'w', encoding='utf-8') as f:
            # Add warning comment at the top
            f.write("# =============================================================================\n")
            f.write("# ORIGINAL SLOs - BACKUP FILE - DO NOT APPLY\n")
            f.write("# =============================================================================\n")
            f.write("# This file contains the ORIGINAL SLO configurations before migration.\n")
            f.write("# Keep this file as a backup in case you need to restore the original state.\n")
            f.write("# =============================================================================\n\n")
            yaml.dump_all(selected_slos, f, default_flow_style=False, allow_unicode=True)
        
        # Save updated SLOs with new data source
        updated_file = output_dir / f"{base_filename}_updated.yaml"
        with open(updated_file, 'w', encoding='utf-8') as f:
            # Add warning comment at the top
            f.write("# =============================================================================\n")
            f.write("# UPDATED SLOs - VALIDATE BEFORE APPLYING\n")
            f.write("# =============================================================================\n")
            f.write("# This file contains SLOs with UPDATED data source configurations.\n")
            f.write("# IMPORTANT: Review and validate these changes before applying!\n")
            f.write("# Test with: sloctl apply -f <filename> --dry-run\n")
            f.write("# Apply with: sloctl apply -f <filename>\n")
            f.write("# =============================================================================\n\n")
            yaml.dump_all(updated_slos, f, default_flow_style=False, allow_unicode=True)
        
        # log_message(log_file, f"Saved full YAML to: {yaml_file}", "INFO")
        log_message(log_file, f"Saved original SLOs to: {original_file}", "INFO")
        log_message(log_file, f"Saved updated SLOs to: {updated_file}", "INFO")
        print(f"{Colors.GREEN}✓ YAML files saved to: {output_dir}{Colors.RESET}")
        print(f"{Colors.CYAN}  - Original: {original_file.name}{Colors.RESET}")
        print(f"{Colors.CYAN}  - Updated: {updated_file.name}{Colors.RESET}")
        
        # Add validation reminder
        print(f"\n{Colors.YELLOW}⚠️  IMPORTANT: Validate the updated YAML files before applying them!{Colors.RESET}")
        print(f"{Colors.CYAN}   - Review the changes in: {updated_file.name}{Colors.RESET}")
        print(f"{Colors.CYAN}   - Test with: sloctl apply -f {updated_file.name} --dry-run{Colors.RESET}")
        print(f"{Colors.CYAN}   - Keep the original file as backup: {original_file.name}{Colors.RESET}")
        
    except Exception as e:
        log_message(log_file, f"Failed to save YAML files: {e}", "ERROR")
        print(f"{Colors.RED}Failed to save YAML files: {e}{Colors.RESET}")


def main() -> None:
    """Main function for Nobl9 Data Source Migrator."""
    print(f"{Colors.CYAN}Nobl9 Data Source Migrator{Colors.RESET}")
    print("=" * 50)
    
    # Save original sloctl context for restoration
    original_context = get_current_sloctl_context()
    if original_context:
        print(f"{Colors.CYAN}Current sloctl context: {original_context}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}Warning: Could not determine current sloctl context{Colors.RESET}")
    
    try:
        # Setup logging
        log_file = setup_logging()
        log_message(log_file, "Data Source Migrator started", "INFO")
        
        # Check dependencies
        check_dependencies()
        
        # Get context and authenticate
        context_name, credentials = enhanced_choose_context()
        log_message(log_file, f"Selected context: {context_name}", "INFO")
        
        token, org, is_custom_instance, custom_base_url = get_token_from_credentials(
            credentials, log_file
        )
        
        # Fetch all available data sources first
        all_data_sources = fetch_all_data_sources()
        
        # Fetch SLO data in YAML format
        yaml_content = fetch_slo_data_yaml()
        slos = parse_yaml_slos(yaml_content)
        
        if not slos:
            print(f"{Colors.YELLOW}No SLOs found.{Colors.RESET}")
            # Still allow migration to data sources with no SLOs
            if all_data_sources:
                print(f"{Colors.CYAN}However, {len(all_data_sources)} data sources are available for migration.{Colors.RESET}")
                print(f"{Colors.CYAN}Since there are no SLOs to migrate, the script will exit.{Colors.RESET}")
                print(f"{Colors.CYAN}You can use this script when you have SLOs that need data source migration.{Colors.RESET}")
            else:
                print(f"{Colors.RED}No data sources found either. Please check your Nobl9 configuration.{Colors.RESET}")
            sys.exit(0)
        
        # Extract data sources from SLOs (for source selection)
        data_sources_dict = extract_data_sources_from_slos(slos)
        source_data_sources = list(data_sources_dict.values())
        
        if not source_data_sources:
            print(f"{Colors.YELLOW}No data sources found in SLOs.{Colors.RESET}")
            # Still allow migration to data sources with no SLOs
            if all_data_sources:
                print(f"{Colors.CYAN}However, {len(all_data_sources)} data sources are available for migration.{Colors.RESET}")
                print(f"{Colors.CYAN}Since there are no SLOs to migrate, the script will exit.{Colors.RESET}")
                print(f"{Colors.CYAN}You can use this script when you have SLOs that need data source migration.{Colors.RESET}")
            else:
                print(f"{Colors.RED}No data sources found either. Please check your Nobl9 configuration.{Colors.RESET}")
            sys.exit(0)
        
        # Count SLOs per data source
        slo_counts = count_slos_per_data_source(source_data_sources, slos)
        
        # Update all data sources with SLO counts
        all_data_sources = update_data_sources_with_slo_counts(all_data_sources, slo_counts)
        
        # Ensure we have data sources available for target selection
        if not all_data_sources:
            print(f"{Colors.RED}No data sources available for target selection.{Colors.RESET}")
            print(f"{Colors.YELLOW}Please check your Nobl9 configuration and ensure data sources exist.{Colors.RESET}")
            sys.exit(1)
        
        # Display source data sources (those with SLOs)
        display_data_sources(source_data_sources, slo_counts)
        
        # Let user select source data sources
        selected_data_sources = select_data_sources(source_data_sources)
        
        # Group SLOs by project and service for selected data sources
        grouped_slos = group_slos_by_project_and_service(slos, selected_data_sources)
        
        if not grouped_slos:
            print(f"{Colors.YELLOW}No SLOs found for the selected data sources.{Colors.RESET}")
            sys.exit(0)
        
        # Display grouped SLOs
        display_grouped_slos(grouped_slos)
        
        # Let user select SLOs
        selected_slos = select_slos_from_grouped(grouped_slos)
        
        # Display final selection
        print(f"\n{Colors.GREEN}Final Selection Summary:{Colors.RESET}")
        print(f"Data Sources: {len(selected_data_sources)}")
        print(f"SLOs: {len(selected_slos)}")
        
        print(f"\n{Colors.CYAN}Selected SLOs for Data Source Migration:{Colors.RESET}")
        for i, slo in enumerate(selected_slos, 1):
            name = slo.get('metadata', {}).get('name', DEFAULT_NAME)
            display_name = slo.get('metadata', {}).get('displayName', name)
            project = slo.get('metadata', {}).get('project', DEFAULT_PROJECT)
            service = extract_service_from_slo(slo)
            print(f"  [{i:2d}] {display_name} ({project}/{service})")
        
        # Get target data source information from all available data sources
        target_ds = select_target_data_source(all_data_sources)
        
        # Create deep copies of selected SLOs for updating
        original_slos = copy.deepcopy(selected_slos)
        
        # Update SLOs with new data source
        updated_slos = []
        migration_summary = []
        
        for slo in selected_slos:
            # Get original data source info before updating
            original_ds_name = None
            original_ds_project = None
            original_ds_kind = None
            
            try:
                indicator = slo.get('spec', {}).get('indicator', {})
                if isinstance(indicator, dict):
                    metric_source = indicator.get('metricSource', {})
                    if isinstance(metric_source, dict):
                        original_ds_name = metric_source.get('name', 'Unknown')
                        original_ds_project = metric_source.get('project', 'Unknown')
                        original_ds_kind = metric_source.get('kind', 'Unknown')
            except (KeyError, TypeError):
                original_ds_name = 'Unknown'
                original_ds_project = 'Unknown'
                original_ds_kind = 'Unknown'
            
            # Update the SLO
            updated_slo = update_slo_data_source(slo, target_ds)
            updated_slos.append(updated_slo)
            
            # Log the migration details
            slo_name = slo.get('metadata', {}).get('name', 'Unknown')
            slo_display_name = slo.get('metadata', {}).get('displayName', slo_name)
            slo_project = slo.get('metadata', {}).get('project', 'Unknown')
            slo_service = extract_service_from_slo(slo)
            
            migration_info = {
                'slo_name': slo_name,
                'slo_display_name': slo_display_name,
                'slo_project': slo_project,
                'slo_service': slo_service,
                'from_ds_name': original_ds_name,
                'from_ds_project': original_ds_project,
                'from_ds_kind': original_ds_kind,
                'to_ds_name': target_ds['name'],
                'to_ds_project': target_ds['project'],
                'to_ds_kind': target_ds['kind']
            }
            
            migration_summary.append(migration_info)
            
            # Log individual migration
            log_message(
                log_file, 
                f"SLO Migration: '{slo_display_name}' ({slo_project}/{slo_service}) "
                f"FROM: {original_ds_name} ({original_ds_project}, {original_ds_kind}) "
                f"TO: {target_ds['name']} ({target_ds['project']}, {target_ds['kind']})",
                "INFO"
            )
        
        # Log migration summary
        log_message(
            log_file,
            f"Migration Summary: {len(updated_slos)} SLOs migrated from "
            f"{len(set(m['from_ds_name'] for m in migration_summary))} source data source(s) "
            f"to target data source: {target_ds['name']}",
            "INFO"
        )
        
        # Display consolidated migration summary to user
        print(f"\n{Colors.CYAN}Migration Summary:{Colors.RESET}")
        print("=" * 80)
        
        # Show migration path once
        print(f"{Colors.YELLOW}Migration Path:{Colors.RESET}")
        source_ds_name = migration_summary[0]['from_ds_name']  # All migrations are from the same source
        print(f"  FROM: {Colors.CYAN}{source_ds_name}{Colors.RESET}")
        print(f"  TO:   {Colors.GREEN}{target_ds['name']}{Colors.RESET} ({target_ds['project']}, {target_ds['kind']})")
        print()
        
        # Group SLOs by source data source for cleaner display
        source_groups = {}
        for migration in migration_summary:
            from_ds = migration['from_ds_name']
            if from_ds not in source_groups:
                source_groups[from_ds] = []
            source_groups[from_ds].append(migration)
        
        # Display SLOs grouped by source data source
        for from_ds, migrations in source_groups.items():
            print(f"{Colors.CYAN}Source: {from_ds}{Colors.RESET} ({len(migrations)} SLOs)")
            for migration in migrations:
                print(f"  • {migration['slo_display_name']} ({migration['slo_project']}/{migration['slo_service']})")
            print()
        
        print(f"\n{Colors.GREEN}✓ Updated {len(updated_slos)} SLOs to use "
              f"data source: {target_ds['name']}{Colors.RESET}")
        
        # Save YAML content for later use
        save_yaml_content(yaml_content, original_slos, updated_slos, log_file, source_ds_name, target_ds['name'])
        
        print(f"\n{Colors.GREEN}Script completed successfully!{Colors.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Script interrupted by user.{Colors.RESET}")
        raise
    except Exception as e:
        print(f"{Colors.RED}Unexpected error: {e}{Colors.RESET}")
        raise
    finally:
        # Always restore the original sloctl context
        if original_context:
            restore_sloctl_context(original_context)
        else:
            print(f"{Colors.YELLOW}No original context to restore{Colors.RESET}")


if __name__ == "__main__":
    main() 