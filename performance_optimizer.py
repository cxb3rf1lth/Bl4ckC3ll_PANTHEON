#!/usr/bin/env python3
"""
Performance optimization utilities for Bl4ckC3ll_PANTHEON
Provides caching, async operations, and performance monitoring
"""

import time
import asyncio
import threading
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import functools


class PerformanceCache:
    """Simple in-memory cache for expensive operations"""
    
    def __init__(self, ttl: int = 3600, max_size: int = 1000):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.ttl = ttl
        self.max_size = max_size
        self.access_times: Dict[str, float] = {}
    
    def _generate_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """Generate cache key from function call"""
        key_data = f"{func_name}:{str(args)}:{str(sorted(kwargs.items()))}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired"""
        if key not in self.cache:
            return None
        
        entry = self.cache[key]
        if time.time() - entry['timestamp'] > self.ttl:
            self._remove(key)
            return None
        
        self.access_times[key] = time.time()
        return entry['value']
    
    def set(self, key: str, value: Any) -> None:
        """Set cache value"""
        if len(self.cache) >= self.max_size:
            self._evict_oldest()
        
        self.cache[key] = {
            'value': value,
            'timestamp': time.time()
        }
        self.access_times[key] = time.time()
    
    def _remove(self, key: str) -> None:
        """Remove cache entry"""
        self.cache.pop(key, None)
        self.access_times.pop(key, None)
    
    def _evict_oldest(self) -> None:
        """Evict least recently used entry"""
        if not self.access_times:
            return
        
        oldest_key = min(self.access_times.items(), key=lambda x: x[1])[0]
        self._remove(oldest_key)
    
    def clear(self) -> None:
        """Clear all cache entries"""
        self.cache.clear()
        self.access_times.clear()
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'ttl': self.ttl,
            'hit_ratio': 'N/A'  # Would need hit/miss tracking
        }


class PerformanceMonitor:
    """Monitor performance of operations"""
    
    def __init__(self):
        self.metrics: Dict[str, List[float]] = {}
        self.counters: Dict[str, int] = {}
        self.lock = threading.Lock()
    
    def record_timing(self, operation: str, duration: float) -> None:
        """Record timing for operation"""
        with self.lock:
            if operation not in self.metrics:
                self.metrics[operation] = []
            self.metrics[operation].append(duration)
            
            # Keep only last 1000 measurements
            if len(self.metrics[operation]) > 1000:
                self.metrics[operation] = self.metrics[operation][-1000:]
    
    def increment_counter(self, name: str) -> None:
        """Increment counter"""
        with self.lock:
            self.counters[name] = self.counters.get(name, 0) + 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        with self.lock:
            stats = {'counters': dict(self.counters), 'timings': {}}
            
            for operation, timings in self.metrics.items():
                if timings:
                    stats['timings'][operation] = {
                        'count': len(timings),
                        'avg': sum(timings) / len(timings),
                        'min': min(timings),
                        'max': max(timings),
                        'recent_avg': sum(timings[-10:]) / min(len(timings), 10)
                    }
            
            return stats
    
    def reset(self) -> None:
        """Reset all metrics"""
        with self.lock:
            self.metrics.clear()
            self.counters.clear()


# Global instances
performance_cache = PerformanceCache()
performance_monitor = PerformanceMonitor()


def cached(ttl: int = 3600):
    """Decorator to cache function results"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = performance_cache._generate_key(func.__name__, args, kwargs)
            
            # Try cache first
            cached_result = performance_cache.get(cache_key)
            if cached_result is not None:
                performance_monitor.increment_counter(f"{func.__name__}_cache_hit")
                return cached_result
            
            # Execute function
            start_time = time.time()
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            
            # Cache result and record timing
            performance_cache.set(cache_key, result)
            performance_monitor.record_timing(func.__name__, duration)
            performance_monitor.increment_counter(f"{func.__name__}_cache_miss")
            
            return result
        
        return wrapper
    return decorator


def timed(func: Callable) -> Callable:
    """Decorator to time function execution"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            duration = time.time() - start_time
            performance_monitor.record_timing(func.__name__, duration)
    
    return wrapper


class AsyncBatch:
    """Batch async operations for better performance"""
    
    def __init__(self, max_workers: int = 10, timeout: float = 30.0):
        self.max_workers = max_workers
        self.timeout = timeout
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def execute_batch(self, func: Callable, items: List[Any], **kwargs) -> List[Any]:
        """Execute function for each item in parallel"""
        futures = []
        results = []
        
        try:
            # Submit all tasks
            for item in items:
                future = self.executor.submit(func, item, **kwargs)
                futures.append((item, future))
            
            # Collect results
            for item, future in futures:
                try:
                    result = future.result(timeout=self.timeout)
                    results.append(result)
                except Exception as e:
                    print(f"Batch task failed for {item}: {e}")
                    results.append(None)
            
        except Exception as e:
            print(f"Batch execution failed: {e}")
        
        return results
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.executor.shutdown(wait=True)


def optimize_certificate_transparency_search(domain: str, limit: int = 100) -> List[str]:
    """Optimized certificate transparency search with caching"""
    import requests
    
    @cached(ttl=3600)  # Cache for 1 hour
    @timed
    def _fetch_certificates(domain: str, limit: int) -> List[str]:
        """Internal function to fetch certificates"""
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            certificates = response.json()
            
            # Extract unique domains
            domains = set()
            for cert in certificates[:limit]:
                name_value = cert.get('name_value', '').strip()
                if name_value:
                    # Handle multi-line certificates
                    for line in name_value.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('*.'):
                            domains.add(line)
            
            return list(domains)[:limit]
        
        except Exception as e:
            print(f"Certificate transparency search failed: {e}")
            return []
    
    return _fetch_certificates(domain, limit)


def get_performance_report() -> Dict[str, Any]:
    """Get comprehensive performance report"""
    return {
        'cache_stats': performance_cache.stats(),
        'performance_stats': performance_monitor.get_stats(),
        'timestamp': time.time()
    }


def clear_performance_cache():
    """Clear performance cache"""
    performance_cache.clear()
    performance_monitor.reset()


if __name__ == "__main__":
    # Test performance optimizations
    print("Testing performance optimizations...")
    
    # Test caching
    @cached(ttl=60)
    def slow_function(x):
        time.sleep(0.1)  # Simulate slow operation
        return x * 2
    
    start = time.time()
    result1 = slow_function(5)  # Should be slow
    time1 = time.time() - start
    
    start = time.time()
    result2 = slow_function(5)  # Should be fast (cached)
    time2 = time.time() - start
    
    print(f"First call: {time1:.3f}s")
    print(f"Cached call: {time2:.3f}s")
    print(f"Speedup: {time1/time2:.1f}x")
    
    # Print performance report
    report = get_performance_report()
    print(f"\nPerformance Report:")
    print(json.dumps(report, indent=2))