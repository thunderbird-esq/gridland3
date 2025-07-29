"""
Adaptive port scanning for GRIDLAND.

This module provides an adaptive port scanner that uses historical data
to prioritize ports, aiming to find open camera ports faster.
"""

from typing import List, Dict

from ..core.config import get_port_manager


class AdaptivePortScanner:
    """Adaptive scanning that balances coverage with performance."""

    def __init__(self):
        self.port_manager = get_port_manager()
        self.port_success_rates = self._load_historical_data()

    def get_adaptive_port_list(self, target_coverage: float = 0.90) -> List[int]:
        """Return ports that achieve target coverage with minimal scan time."""

        # Sort ports by historical success rate
        sorted_ports = sorted(
            self.port_manager.all_ports,
            key=lambda p: self.port_success_rates.get(p, 0),
            reverse=True
        )

        # Calculate cumulative coverage
        cumulative_coverage = 0.0
        selected_ports = []

        for port in sorted_ports:
            success_rate = self.port_success_rates.get(port, 0.001)
            cumulative_coverage += success_rate
            selected_ports.append(port)

            if cumulative_coverage >= target_coverage:
                break

        return selected_ports

    def _load_historical_data(self) -> Dict[int, float]:
        """Load historical port success rates from previous scans."""
        # Implementation would load from persistent storage
        # Default rates based on CamXploit.py analysis
        return {
            80: 0.85, 443: 0.75, 8080: 0.70, 554: 0.60,
            37777: 0.45, 37778: 0.40, 8554: 0.35,
            # ... more ports with empirical success rates
        }
