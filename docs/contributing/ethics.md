# Ethical Use Guidelines

GRIDLAND is designed for **defensive security research, education, and authorized auditing ONLY**. All users and contributors must adhere to these ethical principles.

## Authorized Use

### Acceptable Uses

| Use Case | Description |
|----------|-------------|
| **Own Systems** | Testing cameras and devices you own |
| **Authorized Testing** | Systems with explicit written authorization |
| **Lab Environments** | Isolated test networks |
| **Education** | Learning about security in controlled settings |
| **CTF Challenges** | Capture the flag competitions |

### Prohibited Uses

| Use Case | Why Prohibited |
|----------|----------------|
| **Unauthorized Scanning** | Illegal under CFAA, Computer Misuse Act |
| **Mass Targeting** | Unethical and potentially illegal |
| **Credential Harvesting** | Unauthorized access is criminal |
| **Privacy Violations** | Accessing private feeds without consent |
| **Malicious Exploitation** | Using vulnerabilities to cause harm |

## Legal Framework

### United States

- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access is a federal crime
- **State Laws**: Additional state-level computer crime laws apply

### European Union

- **GDPR**: Privacy requirements for personal data
- **National Laws**: Country-specific computer crime legislation

### Authorization Requirements

Before any testing, ensure you have:

1. **Written Authorization** - Document permission from system owner
2. **Defined Scope** - Clear boundaries of what can be tested
3. **Time Window** - Agreed testing period
4. **Contact Information** - Emergency contacts for issues
5. **Incident Plan** - Procedure if something goes wrong

## Built-in Safeguards

GRIDLAND includes ethical safeguards:

### Credential Testing

```python
# Rate limiting prevents account lockouts
rate_limit_delay=0.1  # 100ms between attempts

# Attempt limiting prevents brute forcing
max_attempts_per_target=100

# Audit logging provides accountability
audit_log_path="credential_audit.csv"
```

### Consent Requirements

- `--test-credentials` flag requires explicit opt-in
- Not enabled by `--full-scan` (user must explicitly add)
- Warning displayed before testing begins

### Audit Trail

All credential testing is logged:
- Timestamp
- Target IP and port
- Username attempted
- URL tested
- Authentication type
- Result (success/failure)

## Responsible Disclosure

If you discover vulnerabilities:

1. **Document** the finding with reproduction steps
2. **Report** to the vendor/manufacturer first
3. **Allow** reasonable time for patch (90 days typical)
4. **Coordinate** disclosure timing with vendor
5. **Publish** after patch is available (if appropriate)

## Contributing Security Features

When adding security-related code:

- **Never** bypass ethical safeguards
- **Always** include rate limiting for network operations
- **Log** security-sensitive operations
- **Test** thoroughly before submitting
- **Document** potential misuse vectors

## Questions?

If unsure whether a use case is ethical, ask yourself:

1. Do I own this system or have written authorization?
2. Could my actions cause harm to others?
3. Would I be comfortable explaining my actions publicly?
4. Is this legal in my jurisdiction?

When in doubt, don't proceed without explicit authorization.
