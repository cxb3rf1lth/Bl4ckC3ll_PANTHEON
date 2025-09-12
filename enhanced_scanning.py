#!/usr/bin/env python3
"""
Enhanced Scanning Logic Module
Advanced scanning capabilities with intelligent depth and adaptive techniques
"""

import asyncio
import aiohttp
import json
import os
import time
import random
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import subprocess
import hashlib
import re

class AdaptiveScanManager:
    """Adaptive scanning manager with intelligent depth and resource management"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.scan_depth = self.config.get('scan_depth', 3)
        self.max_threads = self.config.get('max_threads', 20)
        self.timeout = self.config.get('timeout', 30)
        self.rate_limit = self.config.get('rate_limit', 10)  # requests per second
        self.user_agent = self.config.get('user_agent', 'Bl4ckC3ll_PANTHEON/9.0')
        
        # Adaptive thresholds
        self.success_threshold = 0.1  # If > 10% success rate, increase depth
        self.error_threshold = 0.3    # If > 30% error rate, decrease threads
        
        # Discovery tracking
        self.discovered_endpoints = set()
        self.discovered_technologies = set()
        self.discovered_parameters = set()
        self.scan_statistics = {
            'total_requests': 0,
            'successful_requests': 0,
            'errors': 0,
            'start_time': time.time()
        }
        
        # Load enhanced wordlists
        self.wordlists = self._load_enhanced_wordlists()
        self.payloads = self._load_enhanced_payloads()
    
    def _load_enhanced_wordlists(self) -> Dict[str, List[str]]:
        """Load enhanced wordlists from files"""
        wordlists = {}
        wordlists_dir = Path(__file__).parent / "wordlists_extra"
        
        if wordlists_dir.exists():
            for wordlist_file in wordlists_dir.glob("*.txt"):
                try:
                    with open(wordlist_file, 'r') as f:
                        wordlists[wordlist_file.stem] = [line.strip() for line in f if line.strip()]
                except Exception:
                    continue
        
        return wordlists
    
    def _load_enhanced_payloads(self) -> Dict[str, List[str]]:
        """Load enhanced payloads from files"""
        payloads = {}
        payloads_dir = Path(__file__).parent / "payloads"
        
        # Load comprehensive payloads JSON
        comprehensive_file = payloads_dir / "comprehensive_payloads.json"
        if comprehensive_file.exists():
            try:
                with open(comprehensive_file, 'r') as f:
                    payloads = json.load(f)
            except Exception:
                pass
        
        # Load individual payload files
        for payload_file in payloads_dir.glob("*.txt"):
            try:
                with open(payload_file, 'r') as f:
                    payloads[payload_file.stem] = [line.strip() for line in f if line.strip()]
            except Exception:
                continue
        
        return payloads
    
    async def adaptive_web_discovery(self, base_url: str) -> Dict[str, Any]:
        """Perform adaptive web discovery with intelligent depth adjustment"""
        print(f"🕷️ Starting adaptive web discovery for: {base_url}")
        
        results = {
            'base_url': base_url,
            'discovered_paths': [],
            'discovered_files': [],
            'interesting_responses': [],
            'technology_stack': [],
            'security_headers': {},
            'adaptive_stats': {}
        }
        
        # Phase 1: Basic reconnaissance
        basic_info = await self._basic_reconnaissance(base_url)
        results.update(basic_info)
        
        # Phase 2: Technology-specific discovery
        tech_results = await self._technology_specific_discovery(base_url, results['technology_stack'])
        results['discovered_paths'].extend(tech_results.get('paths', []))
        results['discovered_files'].extend(tech_results.get('files', []))
        
        # Phase 3: Adaptive depth scanning
        adaptive_results = await self._adaptive_depth_scanning(base_url, results['discovered_paths'])
        results['discovered_paths'].extend(adaptive_results.get('new_paths', []))
        
        # Phase 4: Parameter discovery
        param_results = await self._intelligent_parameter_discovery(base_url)
        results['discovered_parameters'] = param_results
        
        # Update statistics
        results['adaptive_stats'] = self._get_scan_statistics()
        
        return results
    
    async def _basic_reconnaissance(self, base_url: str) -> Dict[str, Any]:
        """Perform basic reconnaissance to identify technologies and basic structure"""
        results = {
            'technology_stack': [],
            'security_headers': {},
            'server_info': {},
            'discovered_paths': []
        }
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            ) as session:
                # Test main page
                async with session.get(base_url) as response:
                    headers = dict(response.headers)
                    content = await response.text()
                    
                    # Identify technologies
                    results['technology_stack'] = self._identify_technologies(headers, content)
                    
                    # Extract security headers
                    results['security_headers'] = self._extract_security_headers(headers)
                    
                    # Server information
                    results['server_info'] = {
                        'server': headers.get('Server', 'Unknown'),
                        'powered_by': headers.get('X-Powered-By', 'Unknown'),
                        'status_code': response.status
                    }
                    
                    # Extract links and potential paths
                    results['discovered_paths'] = self._extract_paths_from_content(content)
        
        except Exception as e:
            print(f"⚠️ Basic reconnaissance failed: {e}")
        
        return results
    
    def _identify_technologies(self, headers: Dict[str, str], content: str) -> List[str]:
        """Identify web technologies from headers and content"""
        technologies = set()
        
        # Header-based detection
        server = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        
        if 'apache' in server:
            technologies.add('Apache')
        if 'nginx' in server:
            technologies.add('Nginx')
        if 'iis' in server or 'microsoft' in server:
            technologies.add('IIS')
        if 'php' in powered_by:
            technologies.add('PHP')
        if 'asp.net' in powered_by:
            technologies.add('ASP.NET')
        
        # Content-based detection
        content_lower = content.lower()
        
        # JavaScript frameworks
        if 'react' in content_lower or 'react-dom' in content_lower:
            technologies.add('React')
        if 'angular' in content_lower or 'ng-' in content_lower:
            technologies.add('Angular')
        if 'vue' in content_lower or 'vuejs' in content_lower:
            technologies.add('Vue.js')
        if 'jquery' in content_lower:
            technologies.add('jQuery')
        
        # CMS detection
        if 'wp-content' in content_lower or 'wordpress' in content_lower:
            technologies.add('WordPress')
        if 'drupal' in content_lower:
            technologies.add('Drupal')
        if 'joomla' in content_lower:
            technologies.add('Joomla')
        
        # Backend technologies
        if '.php' in content_lower:
            technologies.add('PHP')
        if '.jsp' in content_lower or 'java' in content_lower:
            technologies.add('Java')
        if '.aspx' in content_lower or '.asp' in content_lower:
            technologies.add('ASP.NET')
        
        return list(technologies)
    
    def _extract_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract security-related headers"""
        security_headers = {}
        
        security_header_names = [
            'Content-Security-Policy', 'X-Frame-Options', 'X-XSS-Protection',
            'X-Content-Type-Options', 'Strict-Transport-Security',
            'X-Permitted-Cross-Domain-Policies', 'Referrer-Policy',
            'Feature-Policy', 'Permissions-Policy'
        ]
        
        for header_name in security_header_names:
            if header_name in headers:
                security_headers[header_name] = headers[header_name]
        
        return security_headers
    
    def _extract_paths_from_content(self, content: str) -> List[str]:
        """Extract potential paths from HTML content"""
        paths = set()
        
        # Extract href attributes
        href_pattern = r'href=["\'](.*?)["\']'
        hrefs = re.findall(href_pattern, content, re.IGNORECASE)
        
        # Extract src attributes
        src_pattern = r'src=["\'](.*?)["\']'
        srcs = re.findall(src_pattern, content, re.IGNORECASE)
        
        # Extract action attributes
        action_pattern = r'action=["\'](.*?)["\']'
        actions = re.findall(action_pattern, content, re.IGNORECASE)
        
        all_links = hrefs + srcs + actions
        
        for link in all_links:
            # Filter out external links and extract path
            if link.startswith('/') and not link.startswith('//'):
                path = link.split('?')[0].split('#')[0]  # Remove query params and fragments
                if path != '/' and len(path) > 1:
                    paths.add(path.lstrip('/'))
        
        return list(paths)[:50]  # Limit to first 50 discovered paths
    
    async def _technology_specific_discovery(self, base_url: str, technologies: List[str]) -> Dict[str, Any]:
        """Perform technology-specific discovery based on identified technologies"""
        results = {'paths': [], 'files': []}
        
        # Select appropriate wordlists based on technologies
        selected_wordlists = []
        
        for tech in technologies:
            tech_lower = tech.lower()
            if 'php' in tech_lower and 'technology_php' in self.wordlists:
                selected_wordlists.extend(self.wordlists['technology_php'])
            if 'java' in tech_lower and 'technology_java' in self.wordlists:
                selected_wordlists.extend(self.wordlists['technology_java'])
            if 'asp' in tech_lower and 'technology_aspx' in self.wordlists:
                selected_wordlists.extend(self.wordlists['technology_aspx'])
            if 'nodejs' in tech_lower and 'technology_nodejs' in self.wordlists:
                selected_wordlists.extend(self.wordlists['technology_nodejs'])
            if 'python' in tech_lower and 'technology_python' in self.wordlists:
                selected_wordlists.extend(self.wordlists['technology_python'])
            if 'wordpress' in tech_lower:
                selected_wordlists.extend(['wp-admin', 'wp-content', 'wp-config.php', 'wp-includes'])
        
        # Add general security paths
        if 'security_admin_panels' in self.wordlists:
            selected_wordlists.extend(self.wordlists['security_admin_panels'])
        if 'security_login_pages' in self.wordlists:
            selected_wordlists.extend(self.wordlists['security_login_pages'])
        
        # Remove duplicates and test paths
        unique_paths = list(set(selected_wordlists))[:100]  # Limit for performance
        
        if unique_paths:
            discovered = await self._test_paths_batch(base_url, unique_paths)
            results['paths'] = discovered
        
        return results
    
    async def _adaptive_depth_scanning(self, base_url: str, discovered_paths: List[str]) -> Dict[str, Any]:
        """Perform adaptive depth scanning based on success rates"""
        results = {'new_paths': []}
        
        if not discovered_paths:
            return results
        
        # Calculate current success rate
        success_rate = self._calculate_success_rate()
        
        # Adjust scanning parameters based on success rate
        if success_rate > self.success_threshold:
            # High success rate - increase depth
            current_depth = min(self.scan_depth + 1, 5)
            print(f"📈 High success rate ({success_rate:.2%}), increasing depth to {current_depth}")
        else:
            # Low success rate - maintain current depth
            current_depth = self.scan_depth
        
        # Perform depth scanning on discovered paths
        for path in discovered_paths[:10]:  # Limit to top 10 paths
            if current_depth > 1:
                depth_results = await self._scan_path_depth(base_url, path, current_depth)
                results['new_paths'].extend(depth_results)
        
        return results
    
    async def _scan_path_depth(self, base_url: str, base_path: str, depth: int) -> List[str]:
        """Scan a specific path to given depth"""
        discovered = []
        
        # Common subdirectories and files
        common_subs = ['admin', 'api', 'backup', 'config', 'data', 'files', 'images', 'js', 'css']
        
        for sub in common_subs:
            test_path = f"{base_path}/{sub}"
            if await self._test_single_path(base_url, test_path):
                discovered.append(test_path)
                
                # Recursive depth scan
                if depth > 1:
                    deeper_results = await self._scan_path_depth(base_url, test_path, depth - 1)
                    discovered.extend(deeper_results)
        
        return discovered
    
    async def _intelligent_parameter_discovery(self, base_url: str) -> List[Dict[str, Any]]:
        """Discover parameters intelligently based on application behavior"""
        parameters = []
        
        # Common parameter names from wordlists
        param_wordlist = self.wordlists.get('common_parameters', [])
        if not param_wordlist:
            param_wordlist = ['id', 'user', 'page', 'action', 'search', 'query', 'file', 'path']
        
        # Test parameters on main page and discovered endpoints
        test_urls = [base_url]
        if hasattr(self, 'discovered_endpoints'):
            test_urls.extend(list(self.discovered_endpoints)[:5])  # Limit testing
        
        for test_url in test_urls:
            for param in param_wordlist[:20]:  # Limit parameter testing
                # Test with different payload types
                test_payloads = ['1', 'test', '../', '<script>', "'"]
                
                for payload in test_payloads:
                    param_url = f"{test_url}?{param}={payload}"
                    response_info = await self._test_parameter_response(param_url)
                    
                    if response_info and response_info.get('interesting'):
                        parameters.append({
                            'parameter': param,
                            'payload': payload,
                            'url': param_url,
                            'response_info': response_info
                        })
        
        return parameters
    
    async def _test_paths_batch(self, base_url: str, paths: List[str]) -> List[str]:
        """Test multiple paths in batch with rate limiting"""
        discovered = []
        semaphore = asyncio.Semaphore(self.max_threads)
        
        async def test_single_path_limited(path):
            async with semaphore:
                await asyncio.sleep(1.0 / self.rate_limit)  # Rate limiting
                return await self._test_single_path(base_url, path)
        
        tasks = [test_single_path_limited(path) for path in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, bool) and result:
                discovered.append(paths[i])
            elif isinstance(result, Exception):
                self.scan_statistics['errors'] += 1
        
        return discovered
    
    async def _test_single_path(self, base_url: str, path: str) -> bool:
        """Test a single path and return True if interesting"""
        try:
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
                headers={'User-Agent': self.user_agent}
            ) as session:
                async with session.get(url) as response:
                    self.scan_statistics['total_requests'] += 1
                    
                    # Consider response interesting if:
                    # - Status code is 200, 301, 302, 403, 401
                    # - Content length > 0
                    # - Contains interesting keywords
                    
                    interesting_status = response.status in [200, 301, 302, 403, 401, 500]
                    
                    if interesting_status:
                        self.scan_statistics['successful_requests'] += 1
                        content = await response.text()
                        
                        # Check for interesting content
                        interesting_keywords = [
                            'admin', 'login', 'dashboard', 'config', 'error',
                            'database', 'backup', 'private', 'restricted'
                        ]
                        
                        content_lower = content.lower()
                        has_interesting_content = any(keyword in content_lower for keyword in interesting_keywords)
                        
                        return has_interesting_content or len(content) > 1000
                    
                    return False
        
        except Exception:
            self.scan_statistics['errors'] += 1
            return False
    
    async def _test_parameter_response(self, param_url: str) -> Optional[Dict[str, Any]]:
        """Test parameter response and analyze for interesting behavior"""
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
                headers={'User-Agent': self.user_agent}
            ) as session:
                async with session.get(param_url) as response:
                    content = await response.text()
                    
                    # Analyze response for interesting behavior
                    response_info = {
                        'status_code': response.status,
                        'content_length': len(content),
                        'interesting': False,
                        'indicators': []
                    }
                    
                    # Check for error messages or interesting patterns
                    error_patterns = [
                        r'sql.*error', r'mysql.*error', r'ora-\d+', r'postgresql.*error',
                        r'syntax.*error', r'warning:', r'fatal.*error', r'exception',
                        r'stack.*trace', r'debug.*info'
                    ]
                    
                    content_lower = content.lower()
                    for pattern in error_patterns:
                        if re.search(pattern, content_lower):
                            response_info['interesting'] = True
                            response_info['indicators'].append(f"Error pattern: {pattern}")
                    
                    # Check for unusual response sizes
                    if len(content) > 10000 or len(content) < 100:
                        response_info['interesting'] = True
                        response_info['indicators'].append(f"Unusual content length: {len(content)}")
                    
                    return response_info
        
        except Exception:
            return None
    
    def _calculate_success_rate(self) -> float:
        """Calculate current success rate"""
        if self.scan_statistics['total_requests'] == 0:
            return 0.0
        return self.scan_statistics['successful_requests'] / self.scan_statistics['total_requests']
    
    def _get_scan_statistics(self) -> Dict[str, Any]:
        """Get current scan statistics"""
        elapsed_time = time.time() - self.scan_statistics['start_time']
        requests_per_second = self.scan_statistics['total_requests'] / max(elapsed_time, 1)
        
        return {
            'total_requests': self.scan_statistics['total_requests'],
            'successful_requests': self.scan_statistics['successful_requests'],
            'errors': self.scan_statistics['errors'],
            'success_rate': self._calculate_success_rate(),
            'error_rate': self.scan_statistics['errors'] / max(self.scan_statistics['total_requests'], 1),
            'elapsed_time': elapsed_time,
            'requests_per_second': requests_per_second
        }
    
    async def enhanced_vulnerability_assessment(self, target_url: str) -> Dict[str, Any]:
        """Perform enhanced vulnerability assessment with multiple techniques"""
        print(f"🔍 Starting enhanced vulnerability assessment for: {target_url}")
        
        results = {
            'target_url': target_url,
            'xss_tests': [],
            'sqli_tests': [],
            'lfi_tests': [],
            'command_injection_tests': [],
            'security_misconfigurations': [],
            'assessment_summary': {}
        }
        
        # Load payloads
        xss_payloads = self.payloads.get('xss', [])[:20]  # Limit for performance
        sqli_payloads = self.payloads.get('sqli', [])[:20]
        lfi_payloads = self.payloads.get('lfi', [])[:15]
        cmd_payloads = self.payloads.get('command_injection', [])[:15]
        
        # Test XSS vulnerabilities
        if xss_payloads:
            xss_results = await self._test_xss_vulnerabilities(target_url, xss_payloads)
            results['xss_tests'] = xss_results
        
        # Test SQL injection
        if sqli_payloads:
            sqli_results = await self._test_sqli_vulnerabilities(target_url, sqli_payloads)
            results['sqli_tests'] = sqli_results
        
        # Test LFI vulnerabilities
        if lfi_payloads:
            lfi_results = await self._test_lfi_vulnerabilities(target_url, lfi_payloads)
            results['lfi_tests'] = lfi_results
        
        # Test command injection
        if cmd_payloads:
            cmd_results = await self._test_command_injection(target_url, cmd_payloads)
            results['command_injection_tests'] = cmd_results
        
        # Check security misconfigurations
        misconfig_results = await self._check_security_misconfigurations(target_url)
        results['security_misconfigurations'] = misconfig_results
        
        # Generate assessment summary
        results['assessment_summary'] = self._generate_assessment_summary(results)
        
        return results
    
    async def _test_xss_vulnerabilities(self, base_url: str, payloads: List[str]) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        xss_results = []
        
        # Common XSS test parameters
        test_params = ['search', 'q', 'query', 'name', 'message', 'comment', 'input']
        
        for payload in payloads[:10]:  # Limit for performance
            for param in test_params:
                test_url = f"{base_url}?{param}={payload}"
                
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=15),
                        headers={'User-Agent': self.user_agent}
                    ) as session:
                        async with session.get(test_url) as response:
                            content = await response.text()
                            
                            # Check if payload is reflected in response
                            if payload in content:
                                xss_results.append({
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'reflected': True,
                                    'status_code': response.status,
                                    'risk_level': self._assess_xss_risk(payload, content)
                                })
                
                except Exception:
                    continue
                
                # Rate limiting
                await asyncio.sleep(0.1)
        
        return xss_results
    
    async def _test_sqli_vulnerabilities(self, base_url: str, payloads: List[str]) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        sqli_results = []
        
        # Common SQL injection test parameters
        test_params = ['id', 'user', 'page', 'category', 'product']
        
        for payload in payloads[:10]:
            for param in test_params:
                test_url = f"{base_url}?{param}={payload}"
                
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=15),
                        headers={'User-Agent': self.user_agent}
                    ) as session:
                        async with session.get(test_url) as response:
                            content = await response.text()
                            
                            # Check for SQL error patterns
                            sql_error_patterns = [
                                r'mysql_fetch', r'ora-\d+', r'microsoft ole db',
                                r'syntax error', r'sqlstate', r'postgresql',
                                r'warning: mysql', r'sql error', r'database error'
                            ]
                            
                            content_lower = content.lower()
                            for pattern in sql_error_patterns:
                                if re.search(pattern, content_lower):
                                    sqli_results.append({
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'error_pattern': pattern,
                                        'status_code': response.status,
                                        'risk_level': 'HIGH'
                                    })
                                    break
                
                except Exception:
                    continue
                
                await asyncio.sleep(0.1)
        
        return sqli_results
    
    async def _test_lfi_vulnerabilities(self, base_url: str, payloads: List[str]) -> List[Dict[str, Any]]:
        """Test for Local File Inclusion vulnerabilities"""
        lfi_results = []
        
        test_params = ['file', 'page', 'include', 'path', 'template']
        
        for payload in payloads[:10]:
            for param in test_params:
                test_url = f"{base_url}?{param}={payload}"
                
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=15),
                        headers={'User-Agent': self.user_agent}
                    ) as session:
                        async with session.get(test_url) as response:
                            content = await response.text()
                            
                            # Check for file inclusion indicators
                            lfi_indicators = [
                                r'root:.*:0:0:', r'\[boot loader\]',
                                r'# /etc/passwd', r'bin/bash', r'bin/sh',
                                r'etc/shadow', r'boot.ini'
                            ]
                            
                            for indicator in lfi_indicators:
                                if re.search(indicator, content, re.IGNORECASE):
                                    lfi_results.append({
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'indicator': indicator,
                                        'status_code': response.status,
                                        'risk_level': 'HIGH'
                                    })
                                    break
                
                except Exception:
                    continue
                
                await asyncio.sleep(0.1)
        
        return lfi_results
    
    async def _test_command_injection(self, base_url: str, payloads: List[str]) -> List[Dict[str, Any]]:
        """Test for command injection vulnerabilities"""
        cmd_results = []
        
        test_params = ['cmd', 'exec', 'command', 'system', 'shell']
        
        for payload in payloads[:10]:
            for param in test_params:
                test_url = f"{base_url}?{param}={payload}"
                
                try:
                    start_time = time.time()
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=20),
                        headers={'User-Agent': self.user_agent}
                    ) as session:
                        async with session.get(test_url) as response:
                            response_time = time.time() - start_time
                            content = await response.text()
                            
                            # Check for command execution indicators
                            cmd_indicators = [
                                r'uid=\d+', r'gid=\d+', r'groups=',
                                r'Microsoft Windows', r'Directory of',
                                r'Volume Serial Number', r'total \d+'
                            ]
                            
                            # Check for time-based indicators (if payload contains sleep/delay)
                            time_based = 'sleep' in payload.lower() or 'delay' in payload.lower()
                            if time_based and response_time > 5:
                                cmd_results.append({
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'indicator': 'Time delay detected',
                                    'response_time': response_time,
                                    'risk_level': 'HIGH'
                                })
                                continue
                            
                            # Check content for command output
                            for indicator in cmd_indicators:
                                if re.search(indicator, content):
                                    cmd_results.append({
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'indicator': indicator,
                                        'status_code': response.status,
                                        'risk_level': 'CRITICAL'
                                    })
                                    break
                
                except Exception:
                    continue
                
                await asyncio.sleep(0.1)
        
        return cmd_results
    
    async def _check_security_misconfigurations(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for common security misconfigurations"""
        misconfigs = []
        
        # Test for common misconfiguration endpoints
        test_paths = [
            '.env', '.git/config', 'config.php', 'web.config',
            'phpinfo.php', 'info.php', 'test.php', 'debug.php',
            'admin.php', 'database.php', 'db.php', 'backup.zip',
            'backup.sql', 'dump.sql', '.htaccess', 'robots.txt'
        ]
        
        for path in test_paths:
            test_url = f"{base_url.rstrip('/')}/{path}"
            
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={'User-Agent': self.user_agent}
                ) as session:
                    async with session.get(test_url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            misconfig_info = {
                                'url': test_url,
                                'path': path,
                                'status_code': response.status,
                                'content_length': len(content),
                                'risk_level': 'MEDIUM'
                            }
                            
                            # Assess risk level based on content
                            if any(keyword in content.lower() for keyword in ['password', 'secret', 'key', 'token']):
                                misconfig_info['risk_level'] = 'HIGH'
                            
                            misconfigs.append(misconfig_info)
            
            except Exception:
                continue
            
            await asyncio.sleep(0.05)
        
        return misconfigs
    
    def _assess_xss_risk(self, payload: str, content: str) -> str:
        """Assess XSS risk level based on payload and response"""
        if '<script>' in payload.lower() and '<script>' in content.lower():
            return 'HIGH'
        elif any(event in payload.lower() for event in ['onerror', 'onload', 'onclick']):
            return 'HIGH'
        elif payload in content:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_assessment_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate vulnerability assessment summary"""
        summary = {
            'total_vulnerabilities': 0,
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'vulnerability_types': {},
            'recommendations': []
        }
        
        # Count vulnerabilities by type and risk
        vuln_types = ['xss_tests', 'sqli_tests', 'lfi_tests', 'command_injection_tests']
        
        for vuln_type in vuln_types:
            vulns = results.get(vuln_type, [])
            summary['vulnerability_types'][vuln_type] = len(vulns)
            summary['total_vulnerabilities'] += len(vulns)
            
            for vuln in vulns:
                risk = vuln.get('risk_level', 'LOW')
                if risk == 'HIGH' or risk == 'CRITICAL':
                    summary['high_risk'] += 1
                elif risk == 'MEDIUM':
                    summary['medium_risk'] += 1
                else:
                    summary['low_risk'] += 1
        
        # Add misconfigurations
        misconfigs = results.get('security_misconfigurations', [])
        summary['vulnerability_types']['misconfigurations'] = len(misconfigs)
        summary['total_vulnerabilities'] += len(misconfigs)
        
        for misconfig in misconfigs:
            risk = misconfig.get('risk_level', 'MEDIUM')
            if risk == 'HIGH':
                summary['high_risk'] += 1
            else:
                summary['medium_risk'] += 1
        
        # Generate recommendations
        if summary['high_risk'] > 0:
            summary['recommendations'].append('URGENT: Address high-risk vulnerabilities immediately')
        if summary.get('vulnerability_types', {}).get('sqli_tests', 0) > 0:
            summary['recommendations'].append('Implement input validation and parameterized queries')
        if summary.get('vulnerability_types', {}).get('xss_tests', 0) > 0:
            summary['recommendations'].append('Implement proper output encoding and CSP headers')
        if summary.get('vulnerability_types', {}).get('lfi_tests', 0) > 0:
            summary['recommendations'].append('Validate and sanitize file path inputs')
        
        return summary

# Helper function for integration with main script
async def run_enhanced_scanning(target_url: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
    """Run enhanced scanning with adaptive techniques"""
    scanner = AdaptiveScanManager(config)
    
    # Run web discovery
    discovery_results = await scanner.adaptive_web_discovery(target_url)
    
    # Run vulnerability assessment
    vuln_results = await scanner.enhanced_vulnerability_assessment(target_url)
    
    # Combine results
    combined_results = {
        'target_url': target_url,
        'discovery': discovery_results,
        'vulnerabilities': vuln_results,
        'scan_metadata': {
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'scanner_version': 'Enhanced_v1.0',
            'adaptive_features': True
        }
    }
    
    return combined_results