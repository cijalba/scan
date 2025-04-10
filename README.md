# SQL Scanner

A powerful tool for scanning SQL files for potential security issues, malicious code, and best practice violations.

## Author

Carlos Ijalba, 2025.

## Features

- Scans SQL files for security vulnerabilities
- Detects malicious code patterns
- Identifies potential SQL injection risks
- Analyzes SQL complexity
- Detects schema modification issues
- Generates detailed reports in multiple formats
- Configurable scanning rules
- File size and pattern-based filtering
- Report cleanup functionality
- Severity-based filtering
- Test mode for quick validation
- CI/CD pipeline integrations

## Installation

1. Clone the repository
2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```
3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Testing

The SQL Scanner includes a comprehensive test suite using pytest. Here's how to run and understand the tests:

### Running Tests

1. Basic test execution:
```bash
PYTHONPATH=$PYTHONPATH:. pytest -v
```

2. Run with detailed output:
```bash
PYTHONPATH=$PYTHONPATH:. pytest -v -s
```

3. Run specific test file:
```bash
PYTHONPATH=$PYTHONPATH:. pytest tests/test_scanner.py -v
```

4. Run specific test function:
```bash
PYTHONPATH=$PYTHONPATH:. pytest tests/test_scanner.py::TestSQLScanner::test_scan_sql_file -v
```

### Test Coverage

To check test coverage:
```bash
PYTHONPATH=$PYTHONPATH:. pytest --cov=sql_scanner tests/
```

### Test Categories

The test suite includes the following test categories:

1. **Rule Testing**
   - Rule creation and validation
   - Rule matching logic
   - Rule severity levels
   - Rule case sensitivity
   - Rule whole word matching
   - Rule regex patterns

2. **File Scanning**
   - Single file scanning
   - Directory scanning
   - File size limits
   - File pattern filtering
   - File encoding handling

3. **Finding Detection**
   - Finding creation and validation
   - Finding severity levels
   - Finding line numbers
   - Finding content matching

4. **Configuration Testing**
   - Config file loading
   - Default values
   - Custom configurations
   - Environment variables

5. **Report Generation**
   - Text report format
   - HTML report format
   - JSON report format
   - CSV report format
   - Report directory structure

6. **Integration Tests**
   - Full scan workflow
   - Report generation workflow
   - Cleanup operations
   - Error handling

### Test Data

The test suite uses sample SQL files and rules to test various scenarios:

1. **Sample SQL Files**
   - Basic SQL statements
   - Security vulnerabilities
   - Schema modifications
   - Complex queries
   - Different encodings

2. **Sample Rules**
   - Security rules
   - Best practice rules
   - Performance rules
   - Schema rules

### Test Environment

The test environment is set up using pytest fixtures:

```python
def setUp(self):
    self.temp_dir = tempfile.mkdtemp()
    self.sql_dir = os.path.join(self.temp_dir, 'sql_scripts')
    self.rules_dir = os.path.join(self.temp_dir, 'rules')
    os.makedirs(self.sql_dir)
    os.makedirs(self.rules_dir)
    
    # Create test SQL file
    self.test_sql = os.path.join(self.sql_dir, 'test.sql')
    with open(self.test_sql, 'w') as f:
        f.write("""
        CREATE TABLE users (
            id INT PRIMARY KEY,
            username VARCHAR(255),
            password VARCHAR(255)
        );
        
        -- This is a comment
        DROP TABLE users;
        
        SELECT * FROM users WHERE password = 'plaintext123';
        """)
```

### Test Cases

1. **Rule Creation Test**
```python
def test_rule_creation(self):
    rule = Rule(
        name="TestRule",
        description="Test Description",
        command="test",
        severity="HIGH",
        case_sensitive=False,
        whole_word=True
    )
    self.assertEqual(rule.name, "TestRule")
    self.assertEqual(rule.severity, "HIGH")
    self.assertFalse(rule.case_sensitive)
    self.assertTrue(rule.whole_word)
```

2. **File Scanning Test**
```python
def test_scan_sql_file(self):
    config = ScannerConfig(self.test_config)
    rules = load_rules(self.rules_dir)
    findings = scan_sql_file(self.test_sql, rules, config)
    self.assertEqual(len(findings), 2)  # Should find DROP TABLE and plain text password
    self.assertTrue(any(f.rule.name == "DropTable" for f in findings))
    self.assertTrue(any(f.rule.name == "PlainTextPassword" for f in findings))
```

3. **Directory Scanning Test**
```python
def test_scan_sql_directory(self):
    config = ScannerConfig(self.test_config)
    rules = load_rules(self.rules_dir)
    findings, _ = scan_sql_directory(self.sql_dir, rules, config)
    self.assertEqual(len(findings), 2)  # Should find DROP TABLE and plain text password
```

### Continuous Integration

The test suite is integrated into the CI/CD pipeline:

1. **GitHub Actions**
   - Runs on every push and pull request
   - Tests multiple Python versions
   - Generates coverage reports
   - Uploads test artifacts

2. **Azure DevOps**
   - Runs on every commit
   - Tests in containerized environment
   - Generates test reports
   - Publishes test results

3. **BitBucket Pipelines**
   - Runs on every push
   - Tests in isolated environment
   - Generates coverage reports
   - Stores test artifacts

### Test Maintenance

To maintain the test suite:

1. **Adding New Tests**
   - Follow the existing test structure
   - Use descriptive test names
   - Include assertions for expected behavior
   - Clean up test resources

2. **Updating Tests**
   - Update tests when functionality changes
   - Maintain backward compatibility
   - Update test data as needed
   - Keep test documentation current

3. **Test Best Practices**
   - Keep tests independent
   - Use meaningful test data
   - Clean up after tests
   - Document test assumptions
   - Handle edge cases

## Project Structure

```
sql-scanner/
├── sql_scanner.py          # Main scanner script
├── requirements.txt        # Python dependencies
├── config.yaml             # Configuration file
├── README.md               # Documentation
├── LICENSE                 # MIT license manifest
├── sql_scripts/            # Sample SQL files for testing
│   ├── example1.sql
│   ├── example2.sql
│   └── ...
├── rules/                  # Rule definitions
│   ├── sql_rules.yaml      # SQL-specific rules
│   └── security_rules.yaml # Security-focused rules
├── reports/                # Generated reports
│   ├── text/               # Text format reports
│   ├── html/               # HTML format reports
│   ├── json/               # JSON format reports
│   └── csv/                # CSV format reports
├── tests/                  # Test files
│   ├── test_scanner.py
│   └── test_data/
└── ci/                     # CI/CD integration files
    ├── azure-pipelines-aks.yml    # Azure DevOps pipeline (AKS Integration)
    ├── bitbucket-pipelines-aks.yml # BitBucket pipeline (AKS Integration)
    ├── .gitlab-ci-aks.yml         # GitLab CI/CD pipeline (AKS Integration)
    ├── Jenkinsfile-aks            # Jenkins pipeline (AKS Integration)
    ├── azure-pipelines.yml        # Azure DevOps pipeline (Generic)
    ├── bitbucket-pipelines.yml     # BitBucket pipeline (Generic)
    ├── .gitlab-ci.yml             # GitLab CI/CD pipeline (Generic)
    ├── Jenkinsfile                # Jenkins pipeline (Generic)
    └── .github/                   # GitHub Actions
        └── workflows/
            ├── aks-deploy.yml     # GitHub Actions workflow (AKS Integration)
            └── sql-scanner.yml    # GitHub Actions workflow (Generic)
```

## CI/CD Integrations

The SQL Scanner includes ready-to-use CI/CD pipeline configurations for various platforms, including specific examples for Azure Kubernetes Service (AKS) integration and more generic setups.

### Azure DevOps
- **AKS Integration:** `ci/azure-pipelines-aks.yml`
  - Features: Automated scanning, AKS deployment, configurable triggers, report collection.
- **Generic:** `ci/azure-pipelines.yml`
  - Features: Basic pipeline structure for scanning.

### BitBucket Pipelines
- **AKS Integration:** `ci/bitbucket-pipelines-aks.yml`
  - Features: Python-based, AKS deployment, testing/scanning, report collection.
- **Generic:** `ci/bitbucket-pipelines.yml`
  - Features: Basic pipeline structure for scanning.

### GitLab CI/CD
- **AKS Integration:** `ci/.gitlab-ci-aks.yml`
  - Features: Multi-stage, AKS integration, caching, report generation.
- **Generic:** `ci/.gitlab-ci.yml`
  - Features: Basic pipeline structure for scanning.

### Jenkins
- **AKS Integration:** `ci/Jenkinsfile-aks`
  - Features: Declarative syntax, environment variables, conditional stages, cleanup.
- **Generic:** `ci/Jenkinsfile`
  - Features: Basic pipeline structure for scanning.

### GitHub Actions
- **AKS Integration:** `ci/.github/workflows/aks-deploy.yml`
  - Features: Event-driven, AKS deployment, testing, report collection.
- **Generic:** `ci/.github/workflows/sql-scanner.yml`
  - Features: Basic workflow for scanning.

Each CI/CD configuration includes:
- Automated scanning of SQL files
- Integration with Azure Kubernetes Service
- Report generation and collection
- Configurable triggers and conditions
- Environment-specific security measures

## Usage

Basic usage:
```bash
python sql_scanner.py
```
This will display the help message with all available options.

### Command Line Options

- `-h, --help`: Show help message
- `-v, --version`: Show version information
- `-d, --diags`: Run internal diagnostics
- `-s, --sqlpath`: Path to SQL files directory (default: sql_scripts)
- `-r, --rulespath`: Path to rules directory (default: rules)
- `--report-format`: Output format (text, html, json, csv)
- `--output-dir`: Directory for report output (default: reports)
- `--exclude`: Pattern to exclude files
- `--include`: Pattern to include files
- `--max-file-size`: Maximum file size to scan
- `--config`: Path to configuration file (default: config.yaml)
- `--severity`: Filter findings by severity level (HIGH, MEDIUM, LOW)
- `--cleanup-reports`: Clean up old reports
- `--max-age-days`: Maximum age of reports in days to keep
- `--max-runs`: Maximum number of reports to keep
- `--test`: Run the scanner with example files for testing

### Examples

Scan with custom paths:
```bash
python sql_scanner.py -s /path/to/sql -r /path/to/rules
```

Generate HTML report:
```bash
python sql_scanner.py --report-format html
```

Exclude specific files:
```bash
python sql_scanner.py --exclude "*.bak"
```

Run diagnostics:
```bash
python sql_scanner.py -d
```

Filter by severity:
```bash
python sql_scanner.py --severity HIGH
```

Clean up old reports (older than 1 week):
```bash
python sql_scanner.py --cleanup-reports --max-age-days 7
```

Keep only the last 15 reports:
```bash
python sql_scanner.py --cleanup-reports --max-runs 15
```

Run in test mode:
```bash
python sql_scanner.py --test
```

## Configuration

The scanner can be configured using `config.yaml`:

```yaml
reporting:
  format: ["text", "html", "json", "csv"]
  output_dir: "reports"
  severity_colors:
    HIGH: "red"
    MEDIUM: "orange"
    LOW: "yellow"

scanning:
  max_file_size: 10485760  # 10MB
  exclude_patterns:
    - "*.bak"
    - "*.tmp"
  include_patterns:
    - "*.sql"
    - "*.sqlite"

rules:
  default_severity: "MEDIUM"
  case_sensitive: false
  whole_word: true
```

## Rule Files

Rules are defined in YAML files in the rules directory. Example rule:

```yaml
name: "DropTable"
description: "Detects DROP TABLE commands"
command: "DROP TABLE"
severity: "HIGH"
case_sensitive: false
whole_word: true
enabled: true
```

Each rule can be enabled or disabled using the `enabled` property.

## Report Formats

### Text Report
Basic console output with findings.

### HTML Report
Interactive web report with:
- Summary statistics
- Color-coded findings by severity
- Detailed finding information
- Timestamps

### JSON Report
Structured data format for programmatic analysis:
```json
{
  "timestamp": "2024-03-21T10:00:00",
  "total_findings": 5,
  "findings": [
    {
      "file_path": "example.sql",
      "line_number": 10,
      "line_content": "DROP TABLE users;",
      "rule_name": "DropTable",
      "rule_description": "Detects DROP TABLE commands",
      "severity": "HIGH",
      "timestamp": "2024-03-21T10:00:00"
    }
  ]
}
```

### CSV Report
Comma-separated values for spreadsheet analysis.

## Report Cleanup

The scanner includes functionality to clean up old reports:

- `--cleanup-reports`: Enable report cleanup
- `--max-age-days`: Keep only reports newer than specified days
- `--max-runs`: Keep only the specified number of most recent reports

Example:
```bash
# Keep only reports from the last 15 days
python sql_scanner.py --cleanup-reports --max-age-days 15

# Keep only the last 15 reports
python sql_scanner.py --cleanup-reports --max-runs 15

# Keep only reports from the last 15 days AND limit to 15 reports
python sql_scanner.py --cleanup-reports --max-age-days 15 --max-runs 15
```

## Security Rules

The scanner includes rules for detecting:
- SQL Injection vulnerabilities
- Privilege escalation attempts
- Data exfiltration
- Unsafe dynamic SQL
- Plain text passwords
- Sensitive data exposure
- Unsafe file operations
- Unsafe string concatenation
- Commented out code

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT license - see the LICENSE file for details. 