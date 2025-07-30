import asyncio
from gridland.analyze.core import get_scheduler

async def test_scheduler():
    scheduler = get_scheduler()
    stats = scheduler.get_statistics()
    print(f"✅ Scheduler operational: {stats['active_workers']} workers active")
    return True

asyncio.run(test_scheduler())
