import asyncio
import time
from unittest.mock import MagicMock, AsyncMock

import pytest
from aiohttp import web

from gridland.analyze.engines import AnalysisEngine, AnalysisTarget, AnalysisConfiguration


@pytest.mark.asyncio
async def test_analysis_engine(aiohttp_server):
    """Test the core analysis engine."""

    async def handler(request):
        return web.Response(text="Hello, world")

    app = web.Application()
    app.router.add_get('/', handler)
    server = await aiohttp_server(app)

    # Create test configuration
    config = AnalysisConfiguration(
        max_concurrent_targets=10,
        timeout_per_target=5.0,
        performance_mode="FAST"
    )

    engine = AnalysisEngine(config)

    # Create test targets
    targets = [
        AnalysisTarget(ip=server.host, port=server.port, service="http"),
    ]

    # Run analysis
    start_time = time.time()
    results = await engine.analyze_targets(targets)
    analysis_time = time.time() - start_time

    assert len(results) > 0
    assert analysis_time < 10

    # Get engine statistics
    stats = engine.get_statistics()
    assert stats['targets_analyzed'] > 0

    # Cleanup
    await engine.shutdown()
