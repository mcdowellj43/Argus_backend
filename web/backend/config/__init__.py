#!/usr/bin/env python3
"""
Centralized Binary Findings System - Configuration Package
Provides the core configuration and rules engine for the enhanced modules
"""

__version__ = "2.1.0"
__author__ = "Argus Security Assessment Platform"

# Import main functions for easy access
try:
    from .findings_rules import evaluate_findings, display_findings_result
    from .findings_config import (
        get_module_rules, get_thresholds, get_risk_weights,
        get_severity_levels, get_category_mapping
    )
    
    # Mark as available
    __all__ = [
        'evaluate_findings',
        'display_findings_result', 
        'get_module_rules',
        'get_thresholds',
        'get_risk_weights',
        'get_severity_levels',
        'get_category_mapping'
    ]
    
    FINDINGS_SYSTEM_AVAILABLE = True
    
except ImportError as e:
    # Graceful fallback if components are missing
    FINDINGS_SYSTEM_AVAILABLE = False
    __all__ = []

# System information
SYSTEM_INFO = {
    "name": "Centralized Binary Findings System",
    "version": __version__,
    "enhanced_modules": 14,
    "total_modules_supported": 54,
    "available": FINDINGS_SYSTEM_AVAILABLE
}