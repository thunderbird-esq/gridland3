from gridland.analyze.memory import get_memory_pool

def test_memory_pool():
    pool = get_memory_pool()
    vuln = pool.acquire_vulnerability_result()
    vuln.ip = "test"
    pool.release_vulnerability_result(vuln)
    stats = pool.get_pool_statistics()
    print(f"✅ Memory pool operational: {len(stats)} pools initialized")
    return True

test_memory_pool()
