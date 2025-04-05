import os
import yaml
import re
import argparse
import sys
import subprocess
import json
import csv
import fnmatch
from datetime import datetime, timedelta
from pathlib import Path
import shutil
from enum import Enum
from jinja2 import Template

VERSION = "1.0.0"

class Rule:
    def __init__(self, name, description, command, severity="MEDIUM", case_sensitive=False, whole_word=False, regex=False, enabled=True):
        self.name = name
        self.description = description
        self.command = command
        self.severity = severity
        self.case_sensitive = case_sensitive
        self.whole_word = whole_word
        self.regex = regex
        self.enabled = enabled

class Finding:
    def __init__(self, file_path, line_number, line_content, rule):
        self.file_path = file_path
        self.line_number = line_number
        self.line_content = line_content
        self.rule = rule
        self.timestamp = datetime.now().isoformat()

    def __str__(self):
        return (
            f"File: {self.file_path}\n"
            f"Line: {self.line_number}\n"
            f"Content: {self.line_content.strip()}\n"
            f"Rule: {self.rule.name}\n"
            f"Description: {self.rule.description}\n"
            f"Severity: {self.rule.severity}\n"
            f"Timestamp: {self.timestamp}\n"
            f"-------------------------"
        )

    def to_dict(self):
        return {
            'file_path': self.file_path,
            'line_number': self.line_number,
            'line_content': self.line_content.strip(),
            'rule_name': self.rule.name,
            'rule_description': self.rule.description,
            'severity': self.rule.severity,
            'timestamp': self.timestamp
        }

class ScannerConfig:
    def __init__(self, config_path='config.yaml'):
        self.config_path = config_path
        self._config = self.load_config()
        
    def __getattr__(self, name):
        if name in self._config:
            return self._config[name]
        raise AttributeError(f"'ScannerConfig' object has no attribute '{name}'")
        
    def __getitem__(self, key):
        return self._config[key]
        
    def load_config(self):
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                if not isinstance(config, dict):
                    raise yaml.YAMLError("Config must be a YAML dictionary")
                return config
        except FileNotFoundError:
            print(f"Warning: Config file {self.config_path} not found. Using defaults.")
            return self.get_default_config()
        except yaml.YAMLError as e:
            print(f"Error parsing config file: {e}")
            raise

    def get_default_config(self):
        return {
            'reporting': {
                'format': ['text'],
                'output_dir': 'reports',
                'severity_colors': {
                    'HIGH': 'red',
                    'MEDIUM': 'orange',
                    'LOW': 'yellow'
                }
            },
            'scanning': {
                'max_file_size': 10485760,
                'exclude_patterns': ['*.bak', '*.tmp'],
                'include_patterns': ['*.sql']
            },
            'rules': {
                'default_severity': 'MEDIUM',
                'case_sensitive': False,
                'whole_word': True
            }
        }

class ReportFormat(Enum):
    TEXT = "text"
    HTML = "html"
    JSON = "json"
    CSV = "csv"

def generate_report(findings, config, format):
    """Generate a report in the specified format."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = config.reporting.get('output_dir', 'reports')
    os.makedirs(output_dir, exist_ok=True)
    
    if format == ReportFormat.TEXT:
        return generate_text_report(findings, output_dir, timestamp)
    elif format == ReportFormat.HTML:
        return generate_html_report(findings, output_dir, timestamp)
    elif format == ReportFormat.JSON:
        return generate_json_report(findings, output_dir, timestamp)
    elif format == ReportFormat.CSV:
        return generate_csv_report(findings, output_dir, timestamp)
    else:
        raise ValueError(f"Unsupported report format: {format}")

def generate_text_report(findings, output_dir, timestamp):
    """Generate a text report."""
    report_path = os.path.join(output_dir, f"report_{timestamp}.txt")
    with open(report_path, 'w') as f:
        f.write("SQL Scanner Report\n")
        f.write("=================\n\n")
        
        for finding in findings:
            f.write(f"File: {finding.file_path}\n")
            f.write(f"Line: {finding.line_number}\n")
            f.write(f"Rule: {finding.rule.name}\n")
            f.write(f"Severity: {finding.rule.severity}\n")
            f.write(f"Description: {finding.rule.description}\n")
            f.write(f"Content: {finding.line_content.strip()}\n")
            f.write("-" * 80 + "\n")
    
    return report_path

def generate_html_report(findings, output_dir, timestamp):
    """Generate an HTML report."""
    report_path = os.path.join(output_dir, f"report_{timestamp}.html")
    
    template = Template("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SQL Scanner Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .finding { margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; }
            .high { background-color: #ffdddd; }
            .medium { background-color: #fff3cd; }
            .low { background-color: #d4edda; }
        </style>
    </head>
    <body>
        <h1>SQL Scanner Report</h1>
        <p>Generated on {{ timestamp }}</p>
        
        {% for finding in findings %}
        <div class="finding {{ finding.rule.severity.lower() }}">
            <h3>{{ finding.rule.name }}</h3>
            <p><strong>File:</strong> {{ finding.file_path }}</p>
            <p><strong>Line:</strong> {{ finding.line_number }}</p>
            <p><strong>Severity:</strong> {{ finding.rule.severity }}</p>
            <p><strong>Description:</strong> {{ finding.rule.description }}</p>
            <pre>{{ finding.line_content }}</pre>
        </div>
        {% endfor %}
    </body>
    </html>
    """)
    
    with open(report_path, 'w') as f:
        f.write(template.render(
            findings=findings,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
    
    return report_path

def generate_json_report(findings, output_dir, timestamp):
    """Generate a JSON report."""
    report_path = os.path.join(output_dir, f"report_{timestamp}.json")
    
    findings_data = []
    for finding in findings:
        findings_data.append({
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'line_content': finding.line_content,
            'rule': {
                'name': finding.rule.name,
                'description': finding.rule.description,
                'severity': finding.rule.severity
            }
        })
    
    with open(report_path, 'w') as f:
        json.dump(findings_data, f, indent=2)
    
    return report_path

def generate_csv_report(findings, output_dir, timestamp):
    """Generate a CSV report."""
    report_path = os.path.join(output_dir, f"report_{timestamp}.csv")
    
    with open(report_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'file_path', 'line_number', 'line_content',
            'rule_name', 'rule_description', 'rule_severity'
        ])
        writer.writeheader()
        
        for finding in findings:
            writer.writerow({
                'file_path': finding.file_path,
                'line_number': finding.line_number,
                'line_content': finding.line_content,
                'rule_name': finding.rule.name,
                'rule_description': finding.rule.description,
                'rule_severity': finding.rule.severity
            })
    
    return report_path

def analyze_sql_complexity(file_path):
    """Analyze SQL complexity and potential issues."""
    complexity_issues = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Check for long queries
            queries = content.split(';')
            for i, query in enumerate(queries, 1):
                if len(query.strip()) > 1000:  # Arbitrary threshold
                    complexity_issues.append({
                        'type': 'LONG_QUERY',
                        'line': i,
                        'description': f'Query exceeds 1000 characters'
                    })
                
                # Check for nested queries
                if query.lower().count('select') > 1:
                    complexity_issues.append({
                        'type': 'NESTED_QUERY',
                        'line': i,
                        'description': 'Contains nested SELECT statements'
                    })
                
                # Check for complex joins
                if query.lower().count('join') > 3:
                    complexity_issues.append({
                        'type': 'COMPLEX_JOIN',
                        'line': i,
                        'description': 'Contains more than 3 JOIN operations'
                    })
    
    except Exception as e:
        complexity_issues.append({
            'type': 'ERROR',
            'line': 0,
            'description': f'Error analyzing file: {str(e)}'
        })
    
    return complexity_issues

def detect_schema_changes(file_path):
    """Detect potential schema modification issues."""
    schema_issues = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Check for DROP operations
            if 'DROP TABLE' in content.upper():
                schema_issues.append({
                    'type': 'DROP_OPERATION',
                    'description': 'Contains DROP TABLE operation'
                })
            
            # Check for ALTER operations
            if 'ALTER TABLE' in content.upper():
                schema_issues.append({
                    'type': 'ALTER_OPERATION',
                    'description': 'Contains ALTER TABLE operation'
                })
            
            # Check for TRUNCATE operations
            if 'TRUNCATE TABLE' in content.upper():
                schema_issues.append({
                    'type': 'TRUNCATE_OPERATION',
                    'description': 'Contains TRUNCATE TABLE operation'
                })
    
    except Exception as e:
        schema_issues.append({
            'type': 'ERROR',
            'description': f'Error analyzing file: {str(e)}'
        })
    
    return schema_issues

def load_rules(rules_dir):
    rules = []
    for filename in os.listdir(rules_dir):
        if filename.endswith(".yaml"):
            with open(os.path.join(rules_dir, filename), "r") as f:
                rule_data = yaml.safe_load(f)
                # Handle both single rule and multiple rules in YAML
                if isinstance(rule_data, list):
                    for rule in rule_data:
                        rules.append(
                            Rule(
                                rule["name"],
                                rule["description"],
                                rule["command"],
                                rule.get("severity", "MEDIUM"),
                                rule.get("case_sensitive", False),
                                rule.get("whole_word", False),
                                rule.get("regex", False),
                                rule.get("enabled", True)
                            )
                        )
                else:
                    rules.append(  # Indented correctly
                        Rule(
                            rule_data["name"],
                            rule_data["description"],
                            rule_data["command"],
                            rule_data.get("severity", "MEDIUM"),
                            rule_data.get("case_sensitive", False),
                            rule_data.get("whole_word", False),
                            rule_data.get("regex", False),      # Corrected indentation
                            rule_data.get("enabled", True)       # Corrected indentation
                        )
                    )
    return rules

def scan_sql_file(file_path, rules, config):
    findings = []
    # Try different encodings
    encodings = ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']
    
    # Check file size
    file_size = os.path.getsize(file_path)
    if file_size > config['scanning']['max_file_size']:
        print(f"Warning: File {file_path} exceeds maximum size limit. Skipping.")
        return findings
    
    # Sort rules by severity (HIGH > MEDIUM > LOW)
    severity_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    sorted_rules = sorted(rules, key=lambda r: severity_order.get(r.severity, 0), reverse=True)
    
    for encoding in encodings:
        try:
            with open(file_path, "r", encoding=encoding) as f:
                for line_number, line in enumerate(f, 1):
                    # Track which parts of the line have been matched
                    matched_spans = set()
                    
                    for rule in sorted_rules:
                        # Skip disabled rules
                        if not getattr(rule, 'enabled', True):
                            continue

                        # Check if this part of the line has already been matched by a higher priority rule
                        if rule.regex:
                            # For regex patterns, check if pattern already includes case-insensitive flag
                            pattern = rule.command
                            flags = 0
                            if not rule.case_sensitive and not pattern.startswith('(?i)'):
                                flags = re.IGNORECASE
                            try:
                                regex = re.compile(pattern, flags)
                                matches = list(regex.finditer(line))
                                
                                for match in matches:
                                    span = match.span()
                                    # Check if this span overlaps with any existing matches
                                    if not any(span[0] < end and start < span[1] for start, end in matched_spans):
                                        findings.append(Finding(file_path, line_number, line, rule))
                                        matched_spans.add(span)
                            except re.error as e:
                                print(f"Warning: Invalid regex pattern in rule {rule.name}: {e}", file=sys.stderr)
                                continue
                        else:
                            search_text = line if rule.case_sensitive else line.lower()
                            command_text = rule.command if rule.case_sensitive else rule.command.lower()
                            
                            if rule.whole_word:
                                # Use word boundaries for whole word matching
                                pattern = r'\b' + re.escape(command_text) + r'\b'
                                matches = list(re.finditer(pattern, search_text, re.IGNORECASE if not rule.case_sensitive else 0))
                                for match in matches:
                                    span = match.span()
                                    # Check if this span overlaps with any existing matches
                                    if not any(span[0] < end and start < span[1] for start, end in matched_spans):
                                        findings.append(Finding(file_path, line_number, line, rule))
                                        matched_spans.add(span)
                            else:
                                start = 0
                                while True:
                                    pos = search_text.find(command_text, start)
                                    if pos == -1:
                                        break
                                    span = (pos, pos + len(command_text))
                                    # Check if this span overlaps with any existing matches
                                    if not any(span[0] < end and start < span[1] for start, end in matched_spans):
                                        findings.append(Finding(file_path, line_number, line, rule))
                                        matched_spans.add(span)
                                    start = pos + 1

            break  # If successful, break the encoding loop
        except UnicodeDecodeError:
            continue
        except Exception as e:
            print(f"Error reading file {file_path}: {str(e)}", file=sys.stderr)
            break

    return findings

def scan_sql_directory(sql_dir, rules, config):
    all_findings = []
    skipped_files = []
    
    for filename in os.listdir(sql_dir):
        # Check if file should be excluded
        if any(fnmatch.fnmatch(filename, pattern) for pattern in config['scanning']['exclude_patterns']):
            continue
            
        # Check if file should be included
        if any(fnmatch.fnmatch(filename, pattern) for pattern in config['scanning']['include_patterns']):
            file_path = os.path.join(sql_dir, filename)
            
            # Check file size
            if os.path.getsize(file_path) > config['scanning']['max_file_size']:
                skipped_files.append({
                    'file': file_path,
                    'reason': 'File size exceeds limit'
                })
                continue
                
            all_findings.extend(scan_sql_file(file_path, rules, config))

    return all_findings, skipped_files

def create_example_files(rules_dir, sql_dir):
    # Create directories if they don't exist
    os.makedirs(rules_dir, exist_ok=True)
    os.makedirs(sql_dir, exist_ok=True)

    # Create example files if they don't exist
    if not any(f.endswith(".yaml") for f in os.listdir(rules_dir)):
        with open(os.path.join(rules_dir, "sql_rules.yaml"), "w") as f:
            f.write("- name: DropTable\n"
                    "  description: \"Detects DROP TABLE commands, which can lead to irreversible data loss.\"\n"
                    "  command: \"DROP TABLE\"\n"
                    "  severity: HIGH\n"
                    "  case_sensitive: false\n"
                    "  whole_word: true\n"
                    "  enabled: true\n\n"
                    "- name: GrantAllPrivileges\n"
                    "  description: \"Detects GRANT ALL PRIVILEGES, which is overly permissive and a security risk.\"\n"
                    "  command: \"GRANT ALL PRIVILEGES\"\n"
                    "  severity: HIGH\n"
                    "  case_sensitive: false\n"
                    "  whole_word: false\n"
                    "  enabled: true\n\n"
                    "- name: TruncateTable\n"
                    "  description: \"Detects TRUNCATE TABLE commands, which delete all data quickly.\"\n"
                    "  command: \"TRUNCATE TABLE\"\n"
                    "  severity: MEDIUM\n"
                    "  case_sensitive: false\n"
                    "  whole_word: true\n"
                    "  enabled: true\n\n"
                    "- name: CommentedOutDropTable\n"
                    "  description: \"Detects commented out DROP TABLE commands, which may be accidentally uncommented\"\n"
                    "  command: \"--\\s*DROP TABLE\"\n"
                    "  severity: LOW\n"
                    "  case_sensitive: false\n"
                    "  whole_word: true\n"
                    "  regex: true\n"
                    "  enabled: true\n\n"
                    "- name: InsertUser\n"
                    "  description: \"Detects INSERT INTO user commands, adding a user to a table\"\n"
                    "  command: \"INSERT\\s+INTO\\s+user\"\n"
                    "  severity: MEDIUM\n"
                    "  case_sensitive: false\n"
                    "  whole_word: false\n"
                    "  regex: true\n"
                    "  enabled: true")

    if not any(f.endswith(".sql") for f in os.listdir(sql_dir)):
        with open(os.path.join(sql_dir, "example.sql"), "w") as f:
            f.write("CREATE TABLE my_table (id INT);\n"
                    "DROP TABLE other_table;\n"
                    "GRANT ALL PRIVILEGES ON database TO user;\n"
                    "truncate table some_table;\n"
                    "-- DROP TABLE another_table;\n"
                    "INSERT INTO user (username, password) VALUES ('testuser', 'testpass');")

def run_diagnostics():
    """Run internal diagnostics to check system state and dependencies."""
    print("\n=== SQL Scanner Diagnostics ===")
    
    # Check Python version
    print("\n1. Python Environment:")
    print(f"Python Version: {sys.version.split()[0]}")
    
    # Check required packages
    print("\n2. Dependencies:")
    try:
        import yaml
        print("✓ PyYAML is installed")
    except ImportError:
        print("✗ PyYAML is not installed")
    
    # Check directories
    print("\n3. Directory Structure:")
    for dir_name in ['rules', 'sql_scripts']:
        if os.path.exists(dir_name):
            print(f"✓ {dir_name} directory exists")
            files = [f for f in os.listdir(dir_name) if f.endswith('.yaml' if dir_name == 'rules' else '.sql')]
            print(f"  - Contains {len(files)} {'.yaml' if dir_name == 'rules' else '.sql'} files")
        else:
            print(f"✗ {dir_name} directory does not exist")
    
    # Check rule files
    print("\n4. Rule Files:")
    if os.path.exists('rules'):
        sql_rules_file = os.path.join('rules', 'sql_rules.yaml')
        security_rules_file = os.path.join('rules', 'security_rules.yaml')
        
        # Check SQL rules
        if os.path.exists(sql_rules_file):
            try:
                with open(sql_rules_file, 'r') as f:
                    rules = yaml.safe_load(f)
                    if isinstance(rules, list):
                        print(f"✓ sql_rules.yaml: Valid rule file with {len(rules)} rules")
                        # Check each rule
                        for i, rule in enumerate(rules, 1):
                            required_fields = ['name', 'description', 'command']
                            missing_fields = [field for field in required_fields if field not in rule]
                            if missing_fields:
                                print(f"  ✗ Rule {i}: Missing required fields: {', '.join(missing_fields)}")
                            else:
                                status = "✓" if rule.get('enabled', True) else "✗"
                                print(f"  {status} Rule {i}: {rule['name']} ({rule.get('severity', 'MEDIUM')}) - {'Enabled' if rule.get('enabled', True) else 'Disabled'}")
                    else:
                        print("✗ sql_rules.yaml: Invalid format - should be a list of rules")
            except Exception as e:
                print(f"✗ sql_rules.yaml: Error reading file - {str(e)}")
        else:
            print("✗ sql_rules.yaml: File not found")
            
        # Check security rules
        if os.path.exists(security_rules_file):
            try:
                with open(security_rules_file, 'r') as f:
                    rules = yaml.safe_load(f)
                    if isinstance(rules, list):
                        print(f"✓ security_rules.yaml: Valid rule file with {len(rules)} rules")
                        # Check each rule
                        for i, rule in enumerate(rules, 1):
                            required_fields = ['name', 'description', 'command']
                            missing_fields = [field for field in required_fields if field not in rule]
                            if missing_fields:
                                print(f"  ✗ Rule {i}: Missing required fields: {', '.join(missing_fields)}")
                            else:
                                status = "✓" if rule.get('enabled', True) else "✗"
                                print(f"  {status} Rule {i}: {rule['name']} ({rule.get('severity', 'MEDIUM')}) - {'Enabled' if rule.get('enabled', True) else 'Disabled'}")
                    else:
                        print("✗ security_rules.yaml: Invalid format - should be a list of rules")
            except Exception as e:
                print(f"✗ security_rules.yaml: Error reading file - {str(e)}")
        else:
            print("✗ security_rules.yaml: File not found")
    
    # Check SQL files
    print("\n5. SQL Files:")
    if os.path.exists('sql_scripts'):
        for filename in os.listdir('sql_scripts'):
            if filename.endswith('.sql'):
                try:
                    with open(os.path.join('sql_scripts', filename), 'r') as f:
                        content = f.read()
                        statements = [s.strip() for s in content.split(';') if s.strip()]
                        print(f"✓ {filename}: Valid SQL file")
                        print(f"  - {len(content.splitlines())} lines")
                        print(f"  - {len(statements)} SQL statements")
                except Exception as e:
                    print(f"✗ {filename}: Error reading file - {str(e)}")
    
    # Check configuration
    print("\n6. Configuration:")
    try:
        config = ScannerConfig()
        print("✓ Configuration loaded successfully")
        print(f"  - Report formats: {', '.join(config['reporting']['format'])}")
        print(f"  - Max file size: {config['scanning']['max_file_size']} bytes")
        print(f"  - Include patterns: {', '.join(config['scanning']['include_patterns'])}")
        print(f"  - Exclude patterns: {', '.join(config['scanning']['exclude_patterns'])}")
    except Exception as e:
        print(f"✗ Configuration error: {str(e)}")
    
    print("\n=== Diagnostics Complete ===\n")

def cleanup_reports(reports_dir, max_age_days=None, max_runs=None):
    """Clean up old report directories based on age or number of runs.
    
    Args:
        reports_dir (str): Path to reports directory
        max_age_days (int, optional): Maximum age of reports in days
        max_runs (int, optional): Maximum number of reports to keep
    """
    if not os.path.exists(reports_dir):
        print(f"Reports directory {reports_dir} does not exist")
        return

    # Get all report directories
    report_dirs = []
    for d in os.listdir(reports_dir):
        path = os.path.join(reports_dir, d)
        if os.path.isdir(path):
            try:
                # Try to parse the timestamp from directory name
                datetime.strptime(d, "%Y%m%d_%H%M%S")
                report_dirs.append((path, d))
            except ValueError:
                # Skip directories that don't match our timestamp format
                continue

    if not report_dirs:
        print("No report directories found to clean up")
        return

    # Sort by directory name (timestamp) in descending order
    report_dirs.sort(key=lambda x: x[1], reverse=True)

    to_delete = []

    # Filter by age if specified
    if max_age_days:
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        for path, name in report_dirs:
            try:
                dir_date = datetime.strptime(name, "%Y%m%d_%H%M%S")
                if dir_date < cutoff_date:
                    to_delete.append(path)
            except ValueError:
                continue

    # Filter by number of runs if specified
    if max_runs and len(report_dirs) > max_runs:
        to_delete.extend(path for path, _ in report_dirs[max_runs:])

    # Remove duplicates and sort
    to_delete = sorted(set(to_delete))

    # Delete old reports
    for path in to_delete:
        try:
            shutil.rmtree(path)
            print(f"Deleted old report: {path}")
        except Exception as e:
            print(f"Error deleting {path}: {e}")

    print(f"Cleanup complete. Deleted {len(to_delete)} report directories.")

def parse_args():
    parser = argparse.ArgumentParser(
        description='SQL Scanner - A tool to scan SQL files for potential issues',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('-s', '--sqlpath', 
                        default='sql_scripts',
                        help='Path to directory containing SQL files to scan')
    parser.add_argument('-r', '--rulespath',
                        default='rules',
                        help='Path to directory containing rule YAML files')
    parser.add_argument('-d', '--diags',
                        action='store_true',
                        help='Run internal diagnostics')
    parser.add_argument('--report-format', 
                        choices=['text', 'html', 'json', 'csv'],
                        default='text',
                        help='Output report format')
    parser.add_argument('--output-dir',
                        default='reports',
                        help='Directory for report output')
    parser.add_argument('--exclude',
                        help='Pattern to exclude files')
    parser.add_argument('--include',
                        help='Pattern to include files')
    parser.add_argument('--max-file-size',
                        type=int,
                        help='Maximum file size to scan')
    parser.add_argument('--config',
                        default='config.yaml',
                        help='Path to configuration file')
    parser.add_argument('--severity',
                        choices=['HIGH', 'MEDIUM', 'LOW'],
                        help='Only report findings with specified severity level')
    parser.add_argument('--cleanup-reports',
                        action='store_true',
                        help='Clean up old reports')
    parser.add_argument('--max-age-days',
                        type=int,
                        help='Maximum age of reports in days to keep')
    parser.add_argument('--max-runs',
                        type=int,
                        help='Maximum number of reports to keep')
    parser.add_argument('--test',
                        action='store_true',
                        help='Run the scanner with example files for testing')
    
    # If no arguments are provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
        
    return parser.parse_args()

def analyze_sql_complexity_metrics(file_path):
    """Analyze SQL complexity metrics and generate a detailed report."""
    metrics = {
        'total_lines': 0,
        'total_statements': 0,
        'complex_queries': 0,
        'nested_queries': 0,
        'joins': 0,
        'subqueries': 0,
        'functions': 0,
        'triggers': 0,
        'views': 0,
        'procedures': 0,
        'tables': set(),
        'columns': set(),
        'indexes': 0,
        'constraints': 0
    }
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Basic metrics
            metrics['total_lines'] = len(content.splitlines())
            statements = [s.strip() for s in content.split(';') if s.strip()]
            metrics['total_statements'] = len(statements)
            
            # Analyze each statement
            for statement in statements:
                stmt_lower = statement.lower()
                
                # Count complex queries (queries with multiple conditions or joins)
                if stmt_lower.count('where') > 1 or stmt_lower.count('and') > 2:
                    metrics['complex_queries'] += 1
                
                # Count nested queries
                if stmt_lower.count('select') > 1:
                    metrics['nested_queries'] += 1
                
                # Count joins
                metrics['joins'] += stmt_lower.count('join')
                
                # Count subqueries
                metrics['subqueries'] += stmt_lower.count('(select')
                
                # Count functions
                if 'create function' in stmt_lower:
                    metrics['functions'] += 1
                
                # Count triggers
                if 'create trigger' in stmt_lower:
                    metrics['triggers'] += 1
                
                # Count views
                if 'create view' in stmt_lower:
                    metrics['views'] += 1
                
                # Count procedures
                if 'create procedure' in stmt_lower:
                    metrics['procedures'] += 1
                
                # Extract table names
                if 'create table' in stmt_lower:
                    table_name = re.search(r'create\s+table\s+(\w+)', stmt_lower)
                    if table_name:
                        metrics['tables'].add(table_name.group(1))
                
                # Count columns
                if 'create table' in stmt_lower:
                    columns = re.findall(r'(\w+)\s+[a-z]+', stmt_lower)
                    metrics['columns'].update(columns)
                
                # Count indexes
                if 'create index' in stmt_lower:
                    metrics['indexes'] += 1
                
                # Count constraints
                metrics['constraints'] += (
                    stmt_lower.count('primary key') +
                    stmt_lower.count('foreign key') +
                    stmt_lower.count('unique') +
                    stmt_lower.count('check')
                )
    
    except Exception as e:
        print(f"Error analyzing file {file_path}: {str(e)}", file=sys.stderr)
    
    return metrics

def generate_complexity_report(metrics, output_file):
    """Generate a detailed complexity report in HTML format."""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SQL Complexity Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .metric {{ margin: 10px 0; padding: 10px; border: 1px solid #ccc; }}
            .metric-header {{ background-color: #f5f5f5; padding: 5px; }}
            .metric-value {{ font-weight: bold; }}
            .warning {{ background-color: #fff3e0; }}
            .critical {{ background-color: #ffebee; }}
            .summary {{ margin: 20px 0; }}
        </style>
    </head>
    <body>
        <h1>SQL Complexity Analysis Report</h1>
        <div class="summary">
            <h2>Summary</h2>
            <p>Total Lines: {total_lines}</p>
            <p>Total Statements: {total_statements}</p>
            <p>Total Tables: {total_tables}</p>
            <p>Total Columns: {total_columns}</p>
        </div>
        <div class="metrics">
            <h2>Complexity Metrics</h2>
            {metrics_html}
        </div>
    </body>
    </html>
    """
    
    # Generate metrics HTML
    metrics_html = ""
    
    # Query Complexity
    metrics_html += f"""
    <div class="metric">
        <div class="metric-header">Query Complexity</div>
        <p>Complex Queries: <span class="metric-value">{metrics['complex_queries']}</span></p>
        <p>Nested Queries: <span class="metric-value">{metrics['nested_queries']}</span></p>
        <p>Total Joins: <span class="metric-value">{metrics['joins']}</span></p>
        <p>Subqueries: <span class="metric-value">{metrics['subqueries']}</span></p>
    </div>
    """
    
    # Database Objects
    metrics_html += f"""
    <div class="metric">
        <div class="metric-header">Database Objects</div>
        <p>Functions: <span class="metric-value">{metrics['functions']}</span></p>
        <p>Triggers: <span class="metric-value">{metrics['triggers']}</span></p>
        <p>Views: <span class="metric-value">{metrics['views']}</span></p>
        <p>Stored Procedures: <span class="metric-value">{metrics['procedures']}</span></p>
    </div>
    """
    
    # Schema Elements
    metrics_html += f"""
    <div class="metric">
        <div class="metric-header">Schema Elements</div>
        <p>Tables: <span class="metric-value">{len(metrics['tables'])}</span></p>
        <p>Columns: <span class="metric-value">{len(metrics['columns'])}</span></p>
        <p>Indexes: <span class="metric-value">{metrics['indexes']}</span></p>
        <p>Constraints: <span class="metric-value">{metrics['constraints']}</span></p>
    </div>
    """
    
    # Format the HTML
    html_content = html_content.format(
        total_lines=metrics['total_lines'],
        total_statements=metrics['total_statements'],
        total_tables=len(metrics['tables']),
        total_columns=len(metrics['columns']),
        metrics_html=metrics_html
    )
    
    # Write the report
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        f.write(html_content)

def main():
    args = parse_args()
    
    # Load configuration
    config = ScannerConfig(args.config)
    
    # Override config with command line arguments if provided
    if args.exclude:
        config['scanning']['exclude_patterns'].append(args.exclude)
    if args.include:
        config['scanning']['include_patterns'].append(args.include)
    if args.max_file_size:
        config['scanning']['max_file_size'] = args.max_file_size
    
    if args.diags:
        run_diagnostics()
        return

    if args.cleanup_reports:
        cleanup_reports(args.output_dir, args.max_age_days, args.max_runs)
        return
    
    # Create example files if needed
    if args.test:
        create_example_files(args.rulespath, args.sqlpath)
    
    # Load rules and scan
    rules = load_rules(args.rulespath)
    findings, skipped_files = scan_sql_directory(args.sqlpath, rules, config)

    # Filter findings by severity if specified
    if args.severity:
        findings = [f for f in findings if f.rule.severity == args.severity]

    # Generate reports based on format
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(args.output_dir, timestamp)
    os.makedirs(report_dir, exist_ok=True)
    
    if 'text' in config['reporting']['format']:
        print(f"\nProcessed {len(findings)} SQL file(s)")
        if findings:
            print(f"Found {len(findings)} potential issues:")
            for finding in findings:
                print(finding)
        else:
            print("No issues found.")

    if 'html' in config['reporting']['format']:
        html_file = os.path.join(report_dir, 'report.html')
        generate_html_report(findings, report_dir, timestamp)
        print(f"\nHTML report generated: {html_file}")
        
        # Generate complexity report
        complexity_file = os.path.join(report_dir, 'complexity.html')
        metrics = analyze_sql_complexity_metrics(os.path.join(args.sqlpath, 'example.sql'))
        generate_complexity_report(metrics, complexity_file)
        print(f"Complexity report generated: {complexity_file}")
    
    if 'json' in config['reporting']['format']:
        json_file = os.path.join(report_dir, 'report.json')
        generate_json_report(findings, report_dir, timestamp)
        print(f"JSON report generated: {json_file}")
    
    if 'csv' in config['reporting']['format']:
        csv_file = os.path.join(report_dir, 'report.csv')
        generate_csv_report(findings, report_dir, timestamp)
        print(f"CSV report generated: {csv_file}")

if __name__ == "__main__":
    main()
