# Pull Request

## Description
<!-- Provide a clear and concise description of your changes -->

## Type of Change
<!-- Mark relevant options with an 'x' -->

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📝 Documentation update
- [ ] 🎨 Code style update (formatting, renaming)
- [ ] ♻️ Code refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] ✅ Test update
- [ ] 🔒 Security fix
- [ ] 🔧 Configuration change
- [ ] 🗑️ Code removal

## Related Issues
<!-- Link related issues below. Use "Fixes #123" to auto-close issue when PR is merged -->

Fixes #
Related to #

## Changes Made
<!-- List the main changes in bullet points -->

-
-
-

## Testing Performed
<!-- Describe the tests you ran to verify your changes -->

### Unit Tests

```bash
# Command used to run tests
pytest tests/path/to/test.py -v
```

### Integration Tests
<!-- If applicable -->

### Manual Testing
<!-- Steps you performed manually -->

1.
2.
3.

## Test Coverage
<!-- Paste coverage report for affected modules -->

```
Module                    Stmts   Miss  Cover
---------------------------------------------
gridland/module.py           50      2    96%
---------------------------------------------
TOTAL                        50      2    96%
```

## Code Quality Checks
<!-- Confirm all checks pass -->

- [ ] ✅ Black formatting (`black --check gridland/ tests/`)
- [ ] ✅ isort imports (`isort --check-only gridland/ tests/`)
- [ ] ✅ Flake8 linting (`flake8 gridland/ tests/`)
- [ ] ✅ MyPy type checking (`mypy gridland/`)
- [ ] ✅ Bandit security scan (`bandit -r gridland/`)
- [ ] ✅ All tests passing (`pytest tests/`)
- [ ] ✅ Pre-commit hooks pass (`pre-commit run --all-files`)

## Documentation
<!-- Check all that apply -->

- [ ] 📝 Code comments added for complex logic
- [ ] 📖 Docstrings added/updated for public APIs
- [ ] 📚 README.md updated (if applicable)
- [ ] 📋 CHANGELOG.md updated (if user-facing change)
- [ ] 🎓 Example usage provided (if new feature)

## Performance Impact
<!-- Describe any performance implications -->

- [ ] ✅ No performance impact
- [ ] ⚡ Performance improvement (describe below)
- [ ] ⚠️ Performance regression (justified below)

**Details:**

## Security Considerations
<!-- Address any security implications -->

- [ ] ✅ No security impact
- [ ] 🔒 Security improvement (describe below)
- [ ] ⚠️ Potential security concern (addressed below)

**Details:**

## Breaking Changes
<!-- If this is a breaking change, describe migration path -->

### What breaks?

### Migration Guide

## Dependencies
<!-- List any new dependencies added -->

- [ ] ✅ No new dependencies
- [ ] 📦 New dependencies added:
  - Package: version (reason)

## Screenshots / Logs
<!-- If applicable, add screenshots or log outputs -->

```
# Paste relevant logs here
```

## Deployment Notes
<!-- Any special deployment considerations? -->

- [ ] ✅ No special deployment steps needed
- [ ] 📋 Special steps required:
  1.
  2.

## Checklist
<!-- Ensure all items are checked before requesting review -->

### Code Quality

- [ ] Code follows the project's style guidelines
- [ ] Self-review of code performed
- [ ] Comments added to complex code sections
- [ ] No debug/console statements left in code
- [ ] No TODO/FIXME comments (or tracked in issues)

### Testing

- [ ] New tests added for new functionality
- [ ] All tests pass locally
- [ ] Test coverage maintained/improved (≥70%)
- [ ] Edge cases considered and tested

### Documentation

- [ ] User-facing changes documented
- [ ] API changes documented
- [ ] Configuration changes documented
- [ ] README updated if needed

### Review

- [ ] PR title is clear and descriptive
- [ ] PR description is complete
- [ ] Commits are logical and well-described
- [ ] Ready for review

## Reviewer Notes
<!-- Any specific areas you'd like reviewers to focus on? -->

## Post-Merge Tasks
<!-- Any follow-up tasks after merge? -->

- [ ]
- [ ]

---

**By submitting this pull request, I confirm that my contribution is made under the terms of the project's MIT license.**
