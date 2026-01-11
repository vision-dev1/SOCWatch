"""Detection module initialization"""

from .brute_force import BruteForceDetector
from .suspicious_ip import SuspiciousIPDetector
from .patterns import PatternDetector

__all__ = ['BruteForceDetector', 'SuspiciousIPDetector', 'PatternDetector']
