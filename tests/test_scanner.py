import unittest
import os
import tempfile
import shutil
import json
import csv
from pathlib import Path
from sql_scanner import (
    Rule, Finding, ScannerConfig, scan_sql_file, scan_sql_directory, 
    load_rules, generate_report, ReportFormat
)
import yaml

class TestSQLScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.sql_dir = os.path.join(self.temp_dir, 'sql_scripts')
        self.rules_dir = os.path.join(self.temp_dir, 'rules')
        self.reports_dir = os.path.join(self.temp_dir, 'reports')
        os.makedirs(self.sql_dir)
        os.makedirs(self.rules_dir)
        os.makedirs(self.reports_dir)
        
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
        
        # Create large SQL file for size testing
        self.large_sql = os.path.join(self.sql_dir, 'large.sql')
        with open(self.large_sql, 'w') as f:
            f.write("SELECT * FROM users;" * 1000000)  # ~20MB file
        
        # Create test rules file
        self.test_rules = os.path.join(self.rules_dir, 'test_rules.yaml')
        rules_data = [
            {
                "name": "DropTable",
                "description": "Detects DROP TABLE commands",
                "command": "DROP TABLE",
                "severity": "HIGH",
                "case_sensitive": False,
                "whole_word": True,
                "regex": False,
                "enabled": True
            },
            {
                "name": "PlainTextPassword",
                "description": "Detects passwords stored in plain text",
                "command": "password.*=.*['\"]",
                "severity": "HIGH",
                "case_sensitive": False,
                "whole_word": False,
                "regex": True,
                "enabled": True
            },
            {
                "name": "DisabledRule",
                "description": "This rule is disabled",
                "command": "SELECT",
                "severity": "LOW",
                "case_sensitive": False,
                "whole_word": True,
                "regex": False,
                "enabled": False
            }
        ]
        with open(self.test_rules, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        # Create test config
        self.test_config = os.path.join(self.temp_dir, 'config.yaml')
        with open(self.test_config, 'w') as f:
            f.write("""
            reporting:
              format: ["text", "html", "json", "csv"]
              output_dir: "reports"
              severity_colors:
                HIGH: "red"
                MEDIUM: "orange"
                LOW: "yellow"
            
            scanning:
              max_file_size: 10485760  # 10MB
              exclude_patterns: ["*.bak"]
              include_patterns: ["*.sql"]
            
            rules:
              default_severity: "MEDIUM"
              case_sensitive: false
              whole_word: true
            """)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

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

    def test_finding_creation(self):
        rule = Rule(
            name="TestRule",
            description="Test Description",
            command="test",
            severity="HIGH",
            case_sensitive=False,
            whole_word=True
        )
        finding = Finding(
            file_path="test.sql",
            line_number=1,
            line_content="test line",
            rule=rule
        )
        self.assertEqual(finding.file_path, "test.sql")
        self.assertEqual(finding.line_number, 1)
        self.assertEqual(finding.rule.name, "TestRule")

    def test_config_loading(self):
        config = ScannerConfig(self.test_config)
        self.assertEqual(config.reporting['format'], ["text", "html", "json", "csv"])
        self.assertEqual(config.scanning['max_file_size'], 10485760)
        self.assertEqual(config.rules['default_severity'], "MEDIUM")

    def test_scan_sql_file(self):
        config = ScannerConfig(self.test_config)
        rules = load_rules(self.rules_dir)
        
        print("\nSQL File Content:")
        with open(self.test_sql, 'r') as f:
            print(f.read())
            
        print("\nRules:")
        for rule in rules:
            print(f"Rule: {rule.name}, Command: {rule.command}, Regex: {rule.regex}, Whole Word: {rule.whole_word}")
            
        findings = scan_sql_file(self.test_sql, rules, config)
        print("\nFindings:")
        for f in findings:
            print(f"Rule: {f.rule.name}, Line: {f.line_content.strip()}")
            
        self.assertEqual(len(findings), 2)  # Should find DROP TABLE and plain text password
        self.assertTrue(any(f.rule.name == "DropTable" for f in findings))
        self.assertTrue(any(f.rule.name == "PlainTextPassword" for f in findings))

    def test_scan_sql_directory(self):
        config = ScannerConfig(self.test_config)
        rules = load_rules(self.rules_dir)
        findings, _ = scan_sql_directory(self.sql_dir, rules, config)
        self.assertEqual(len(findings), 2)  # Should find DROP TABLE and plain text password

    # Report Generation Tests
    def test_text_report_generation(self):
        config = ScannerConfig(self.test_config)
        rules = load_rules(self.rules_dir)
        findings = scan_sql_file(self.test_sql, rules, config)
        
        report_path = generate_report(findings, config, ReportFormat.TEXT)
        self.assertTrue(os.path.exists(report_path))
        
        with open(report_path, 'r') as f:
            content = f.read()
            self.assertIn("DropTable", content)
            self.assertIn("PlainTextPassword", content)
            self.assertIn("HIGH", content)

    def test_html_report_generation(self):
        config = ScannerConfig(self.test_config)
        rules = load_rules(self.rules_dir)
        findings = scan_sql_file(self.test_sql, rules, config)
        
        report_path = generate_report(findings, config, ReportFormat.HTML)
        self.assertTrue(os.path.exists(report_path))
        
        with open(report_path, 'r') as f:
            content = f.read()
            self.assertIn("<html", content)
            self.assertIn("DropTable", content)
            self.assertIn("PlainTextPassword", content)

    def test_json_report_generation(self):
        config = ScannerConfig(self.test_config)
        rules = load_rules(self.rules_dir)
        findings = scan_sql_file(self.test_sql, rules, config)
        
        report_path = generate_report(findings, config, ReportFormat.JSON)
        self.assertTrue(os.path.exists(report_path))
        
        with open(report_path, 'r') as f:
            data = json.load(f)
            self.assertIsInstance(data, list)
            self.assertEqual(len(data), 2)
            self.assertTrue(any(f['rule']['name'] == 'DropTable' for f in data))
            self.assertTrue(any(f['rule']['name'] == 'PlainTextPassword' for f in data))

    def test_csv_report_generation(self):
        config = ScannerConfig(self.test_config)
        rules = load_rules(self.rules_dir)
        findings = scan_sql_file(self.test_sql, rules, config)
        
        report_path = generate_report(findings, config, ReportFormat.CSV)
        self.assertTrue(os.path.exists(report_path))
        
        with open(report_path, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertEqual(len(rows), 2)
            self.assertTrue(any(row['rule_name'] == 'DropTable' for row in rows))
            self.assertTrue(any(row['rule_name'] == 'PlainTextPassword' for row in rows))

    # Advanced File Operations Tests
    def test_file_size_limit(self):
        config = ScannerConfig(self.test_config)
        rules = load_rules(self.rules_dir)
        
        # Should skip the large file
        findings, skipped_files = scan_sql_directory(self.sql_dir, rules, config)
        self.assertEqual(len(skipped_files), 1)
        self.assertEqual(skipped_files[0]['reason'], 'File size exceeds limit')

    def test_file_pattern_exclusion(self):
        # Create a backup file
        backup_sql = os.path.join(self.sql_dir, 'test.sql.bak')
        shutil.copy(self.test_sql, backup_sql)
        
        config = ScannerConfig(self.test_config)
        rules = load_rules(self.rules_dir)
        
        findings, _ = scan_sql_directory(self.sql_dir, rules, config)
        # Should only scan test.sql, not test.sql.bak
        self.assertEqual(len(findings), 2)

    # Error Handling Tests
    def test_invalid_file_handling(self):
        config = ScannerConfig(self.test_config)
        rules = load_rules(self.rules_dir)
        
        # Test non-existent file
        with self.assertRaises(FileNotFoundError):
            scan_sql_file('nonexistent.sql', rules, config)
        
        # Test invalid SQL file
        invalid_sql = os.path.join(self.sql_dir, 'invalid.sql')
        with open(invalid_sql, 'w') as f:
            f.write("This is not valid SQL")
        
        findings = scan_sql_file(invalid_sql, rules, config)
        self.assertEqual(len(findings), 0)

    def test_invalid_rule_handling(self):
        # Create invalid rule file
        invalid_rules = os.path.join(self.rules_dir, 'invalid_rules.yaml')
        with open(invalid_rules, 'w') as f:
            f.write("invalid: yaml: content")
        
        with self.assertRaises(yaml.YAMLError):
            load_rules(self.rules_dir)

    def test_invalid_config_handling(self):
        # Create invalid config file
        invalid_config = os.path.join(self.temp_dir, 'invalid_config.yaml')
        with open(invalid_config, 'w') as f:
            f.write("invalid: yaml: content")
        
        with self.assertRaises(yaml.YAMLError):
            ScannerConfig(invalid_config)

    # Advanced Rule Matching Tests
    def test_complex_regex_patterns(self):
        # Add complex regex rule
        complex_rules = os.path.join(self.rules_dir, 'complex_rules.yaml')
        rules_data = [{
            "name": "ComplexPattern",
            "description": "Complex regex pattern test",
            "command": r"select\s+\*\s+from\s+\w+\s+where\s+\w+\s*=\s*['\"].*['\"]",
            "severity": "HIGH",
            "case_sensitive": False,
            "whole_word": False,
            "regex": True,
            "enabled": True
        }]
        with open(complex_rules, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        # Create a single rule for testing
        rule = Rule(
            name="ComplexPattern",
            description="Complex regex pattern test",
            command=r"select\s+\*\s+from\s+\w+\s+where\s+\w+\s*=\s*['\"].*['\"]",
            severity="HIGH",
            case_sensitive=False,
            whole_word=False,
            regex=True,
            enabled=True
        )
        
        config = ScannerConfig(self.test_config)
        findings = scan_sql_file(self.test_sql, [rule], config)
        
        # Debug output
        print("\nComplex Pattern Test:")
        print("Pattern:", rule.command)
        print("Test SQL:", self.test_sql)
        with open(self.test_sql, 'r') as f:
            content = f.read()
            print("SQL Content:", content)
        print("Findings:", findings)
        for f in findings:
            print(f"Rule: {f.rule.name}, Line: {f.line_content.strip()}")
        
        self.assertTrue(any(f.rule.name == "ComplexPattern" for f in findings))

    def test_disabled_rules(self):
        config = ScannerConfig(self.test_config)
        rules = load_rules(self.rules_dir)
        findings = scan_sql_file(self.test_sql, rules, config)
        
        # DisabledRule should not match
        self.assertFalse(any(f.rule.name == "DisabledRule" for f in findings))

    def test_rule_priority(self):
        # Add overlapping rules with different severities
        priority_rules = os.path.join(self.rules_dir, 'priority_rules.yaml')
        rules_data = [
            {
                "name": "HighPriority",
                "description": "High priority rule",
                "command": "SELECT",
                "severity": "HIGH",
                "case_sensitive": False,
                "whole_word": True,
                "regex": False,
                "enabled": True
            },
            {
                "name": "LowPriority",
                "description": "Low priority rule",
                "command": "SELECT",
                "severity": "LOW",
                "case_sensitive": False,
                "whole_word": True,
                "regex": False,
                "enabled": True
            }
        ]
        with open(priority_rules, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        config = ScannerConfig(self.test_config)
        rules = load_rules(self.rules_dir)
        findings = scan_sql_file(self.test_sql, rules, config)
        
        # Should use the higher severity rule
        self.assertTrue(any(f.rule.name == "HighPriority" for f in findings))
        self.assertFalse(any(f.rule.name == "LowPriority" for f in findings))

if __name__ == '__main__':
    unittest.main() 