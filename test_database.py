from gridland.analyze.core.database import get_signature_database

def test_database():
    db = get_signature_database()
    vulns = db.search_by_port(80)
    stats = db.get_statistics()
    print(f"✅ Database operational: {stats['total_signatures']} signatures loaded")
    print(f"   Port 80 vulnerabilities: {len(vulns)}")
    return True

test_database()
