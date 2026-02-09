# Contributing to SentinelOne Power Queries

Thank you for your interest in contributing to this project! This guide will help you understand how to contribute effectively.

## How to Contribute

### Reporting Issues
- Use the GitHub issue tracker to report bugs or suggest new queries
- Provide detailed descriptions including query purpose, expected behavior, and actual behavior
- Include relevant error messages or screenshots if applicable

### Submitting Queries

#### Query Requirements
1. **Functionality**: Query must work correctly and serve a clear purpose
2. **Documentation**: Must include proper inline documentation
3. **Performance**: Should be optimized for reasonable execution times
4. **Security**: Must not include hardcoded credentials or sensitive data

#### Query Template
Use this template for all new queries:

```kql
// [Query Title]
// Description: [What the query does in detail]
// Use Case: [When and why to use this query]
// Data Source: [Required SentinelOne tables]
// Instructions: [Optional customization steps]
// Author: [Your name or GitHub username]
// Last Updated: [YYYY-MM-DD]

[Your KQL query here]
```

#### Submission Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/query-name`)
3. Add your query to the appropriate category folder
4. Follow the naming convention: `descriptive-query-name.kql`
5. Test your query thoroughly
6. Commit with a descriptive message
7. Push to your fork
8. Open a pull request

### Code Style

#### KQL Best Practices
- Use clear, descriptive variable names
- Include comments for complex logic
- Use proper indentation (4 spaces)
- Break long queries into logical sections
- Use `let` statements for reusable values
- Optimize with early filters using `where` clauses
- Use `project` to limit returned columns

#### Example:
```kql
// Good practice
let TimeWindow = ago(24h);
let SuspiciousProcesses = dynamic(["powershell.exe", "cmd.exe"]);

ProcessEvents
| where TimeGenerated > TimeWindow
| where ProcessName in (SuspiciousProcesses)
| project TimeGenerated, DeviceName, ProcessName, ProcessCommandLine
| order by TimeGenerated desc
```

### Categories

Place queries in the appropriate category:
- `threat-hunting/` - Proactive threat hunting queries
- `threat-detection/` - Real-time detection queries
- `incident-response/` - Investigation and response queries
- `data-analysis/` - Baseline and trend analysis queries

If your query doesn't fit existing categories, propose a new category in your pull request.

### Testing

Before submitting:
1. Test in a non-production environment
2. Verify the query returns expected results
3. Check for performance issues with large datasets
4. Validate against multiple time ranges
5. Ensure no syntax errors

### Documentation Updates

If adding new features or categories:
- Update the main README.md
- Add examples if applicable
- Update the table of contents
- Document any new dependencies

### Pull Request Guidelines

#### PR Title Format
- Use descriptive titles: `Add query for detecting DLL hijacking`
- Not: `New query` or `Update`

#### PR Description Should Include
- Purpose of the query
- Category placement
- Testing performed
- Any special considerations
- Related issues (if applicable)

#### Review Process
1. Automated checks will run on your PR
2. Maintainers will review the code and documentation
3. Address any feedback or requested changes
4. Once approved, your PR will be merged

### Communication

- Be respectful and professional
- Provide constructive feedback
- Ask questions if anything is unclear
- Follow the code of conduct

## Recognition

Contributors will be acknowledged in:
- The query file itself (Author field)
- Release notes
- The project README (for significant contributions)

## Questions?

If you have questions about contributing:
- Open an issue with the `question` label
- Check existing issues and documentation
- Review closed PRs for examples

## Code of Conduct

### Our Standards
- Be welcoming and inclusive
- Respect differing viewpoints
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards others

### Unacceptable Behavior
- Harassment or discriminatory language
- Personal attacks
- Publishing others' private information
- Other unprofessional conduct

Thank you for contributing to making security operations better for everyone!
