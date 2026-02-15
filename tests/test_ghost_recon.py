"""Tests for ghost-recon core functionality."""

import json
import tempfile
from pathlib import Path

import pytest

from ghost_recon import GhostRecon, C, VERSION


class TestSecurityScoring:
    """Tests for security posture scoring logic."""

    def setup_method(self):
        self.recon = GhostRecon('example.com', output_dir=Path(tempfile.mkdtemp()))

    def test_perfect_score_with_all_headers(self):
        host_data = {
            'host': 'example.com',
            'http': {'status': 301, 'headers': {}, 'server': 'nginx'},
            'https': {
                'status': 200,
                'headers': {
                    'Strict-Transport-Security': 'max-age=31536000',
                    'Content-Security-Policy': "default-src 'self'",
                    'X-Frame-Options': 'DENY',
                    'X-Content-Type-Options': 'nosniff',
                    'X-XSS-Protection': '1; mode=block',
                    'Referrer-Policy': 'no-referrer',
                    'Permissions-Policy': 'geolocation=()',
                    'Server': 'nginx',
                },
                'server': 'nginx',
            },
        }
        result = self.recon.calculate_security_score(host_data)
        assert result['score'] == 100
        assert result['grade'] == 'A'

    def test_no_https_penalty(self):
        host_data = {
            'host': 'example.com',
            'http': {'status': 200, 'headers': {}, 'server': 'nginx'},
            'https': None,
        }
        result = self.recon.calculate_security_score(host_data)
        assert result['score'] == 80
        assert any('No HTTPS' in d[0] for d in result['deductions'])

    def test_missing_hsts_penalty(self):
        host_data = {
            'host': 'example.com',
            'http': None,
            'https': {
                'status': 200,
                'headers': {
                    'Content-Security-Policy': "default-src 'self'",
                    'X-Frame-Options': 'DENY',
                    'X-Content-Type-Options': 'nosniff',
                    'X-XSS-Protection': '1; mode=block',
                    'Referrer-Policy': 'no-referrer',
                    'Permissions-Policy': 'geolocation=()',
                    'Server': 'nginx',
                },
                'server': 'nginx',
            },
        }
        result = self.recon.calculate_security_score(host_data)
        assert result['score'] == 85
        assert any('HSTS' in d[0] for d in result['deductions'])

    def test_server_version_disclosure_penalty(self):
        host_data = {
            'host': 'example.com',
            'http': None,
            'https': {
                'status': 200,
                'headers': {
                    'Strict-Transport-Security': 'max-age=31536000',
                    'Content-Security-Policy': "default-src 'self'",
                    'X-Frame-Options': 'DENY',
                    'X-Content-Type-Options': 'nosniff',
                    'X-XSS-Protection': '1',
                    'Referrer-Policy': 'no-referrer',
                    'Permissions-Policy': 'geolocation=()',
                    'Server': 'Apache/2.4.51',
                },
                'server': 'Apache/2.4.51',
            },
        }
        result = self.recon.calculate_security_score(host_data)
        assert result['score'] == 95
        assert any('version' in d[0].lower() for d in result['deductions'])

    def test_score_floor_zero(self):
        host_data = {
            'host': 'example.com',
            'http': {'status': 200, 'headers': {}, 'server': 'nginx'},
            'https': None,
        }
        result = self.recon.calculate_security_score(host_data)
        assert result['score'] >= 0


class TestGradeCalculation:
    """Tests for score-to-grade mapping."""

    def setup_method(self):
        self.recon = GhostRecon('example.com', output_dir=Path(tempfile.mkdtemp()))

    def test_grade_a(self):
        assert self.recon._score_to_grade(95) == 'A'
        assert self.recon._score_to_grade(90) == 'A'

    def test_grade_b(self):
        assert self.recon._score_to_grade(85) == 'B'
        assert self.recon._score_to_grade(80) == 'B'

    def test_grade_c(self):
        assert self.recon._score_to_grade(75) == 'C'

    def test_grade_d(self):
        assert self.recon._score_to_grade(65) == 'D'

    def test_grade_f(self):
        assert self.recon._score_to_grade(50) == 'F'
        assert self.recon._score_to_grade(0) == 'F'


class TestTechnologyDetection:
    """Tests for fingerprinting from HTTP headers."""

    def setup_method(self):
        self.recon = GhostRecon('example.com', output_dir=Path(tempfile.mkdtemp()))

    def test_nginx_detected(self):
        host_data = {
            'host': 'example.com',
            'http': None,
            'https': {'status': 200, 'headers': {'Server': 'nginx/1.21.0'}, 'server': 'nginx/1.21.0'},
        }
        techs = self.recon.detect_technologies(host_data)
        assert 'nginx' in techs

    def test_cloudflare_detected(self):
        host_data = {
            'host': 'example.com',
            'http': None,
            'https': {
                'status': 200,
                'headers': {'Server': 'cloudflare', 'CF-RAY': 'abc123'},
                'server': 'cloudflare',
            },
        }
        techs = self.recon.detect_technologies(host_data)
        assert 'Cloudflare' in techs
        assert 'Cloudflare CDN' in techs

    def test_express_detected(self):
        host_data = {
            'host': 'example.com',
            'http': None,
            'https': {
                'status': 200,
                'headers': {'Server': 'nginx', 'X-Powered-By': 'Express'},
                'server': 'nginx',
            },
        }
        techs = self.recon.detect_technologies(host_data)
        assert 'Express.js' in techs

    def test_vercel_detected(self):
        host_data = {
            'host': 'example.com',
            'http': None,
            'https': {
                'status': 200,
                'headers': {'Server': 'nginx', 'X-Vercel-Id': 'abc123'},
                'server': 'nginx',
            },
        }
        techs = self.recon.detect_technologies(host_data)
        assert 'Vercel' in techs


class TestColorDisable:
    """Tests for --no-color functionality."""

    def test_disable_colors(self):
        C.disable()
        assert C.R == ''
        assert C.G == ''
        assert C.BOLD == ''
        assert C.DIM == ''
        # Reset
        C.R = '\033[91m'
        C.G = '\033[92m'
        C.Y = '\033[93m'
        C.B = '\033[94m'
        C.M = '\033[95m'
        C.C = '\033[96m'
        C.W = '\033[97m'
        C.E = '\033[0m'
        C.BOLD = '\033[1m'
        C.DIM = '\033[2m'


class TestJSONReport:
    """Tests for JSON report output."""

    def setup_method(self):
        self.recon = GhostRecon('example.com', output_dir=Path(tempfile.mkdtemp()))
        from datetime import datetime
        self.recon.scan_start = datetime.now()

    def test_json_report_structure(self):
        report = self.recon.get_json_report()
        assert report['target'] == 'example.com'
        assert report['version'] == VERSION
        assert 'subdomains' in report
        assert 'dns_records' in report
        assert 'security_scores' in report
        assert 'scan_start' in report
        assert 'scan_end' in report

    def test_json_serializable(self):
        self.recon.subdomains.add('api.example.com')
        self.recon.dns_records = {'A': ['1.2.3.4']}
        report = self.recon.get_json_report()
        serialized = json.dumps(report, default=str)
        assert 'api.example.com' in serialized
        assert '1.2.3.4' in serialized


class TestTargetParsing:
    """Tests for target domain normalization."""

    def test_strips_https(self):
        recon = GhostRecon('https://example.com', output_dir=Path(tempfile.mkdtemp()))
        assert recon.target == 'example.com'

    def test_strips_http(self):
        recon = GhostRecon('http://example.com', output_dir=Path(tempfile.mkdtemp()))
        assert recon.target == 'example.com'

    def test_strips_trailing_slash(self):
        recon = GhostRecon('example.com/', output_dir=Path(tempfile.mkdtemp()))
        assert recon.target == 'example.com'

    def test_combined_strip(self):
        recon = GhostRecon('https://example.com/', output_dir=Path(tempfile.mkdtemp()))
        assert recon.target == 'example.com'


class TestGradeColor:
    """Tests for grade-to-color mapping."""

    def setup_method(self):
        self.recon = GhostRecon('example.com', output_dir=Path(tempfile.mkdtemp()))

    def test_a_grade_green(self):
        assert self.recon._grade_color('A') == C.G

    def test_f_grade_red(self):
        assert self.recon._grade_color('F') == C.R

    def test_c_grade_yellow(self):
        assert self.recon._grade_color('C') == C.Y


class TestInterestingFindings:
    """Tests for finding correlation logic."""

    def setup_method(self):
        self.recon = GhostRecon('example.com', output_dir=Path(tempfile.mkdtemp()))

    def test_missing_xframe_flagged(self):
        host_data = {
            'host': 'example.com',
            'http': None,
            'https': {'status': 200, 'headers': {'Server': 'nginx'}, 'server': 'nginx'},
        }
        self.recon.detect_technologies(host_data)
        types = [f['type'] for f in self.recon.interesting]
        assert 'missing_header' in types

    def test_insecure_cookie_flagged(self):
        host_data = {
            'host': 'example.com',
            'http': None,
            'https': {
                'status': 200,
                'headers': {'Server': 'nginx', 'Set-Cookie': 'session=abc123; Path=/'},
                'server': 'nginx',
            },
        }
        self.recon.detect_technologies(host_data)
        types = [f['type'] for f in self.recon.interesting]
        assert 'cookie_issue' in types
