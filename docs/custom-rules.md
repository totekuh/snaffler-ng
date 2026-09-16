# Custom Rules

Write TOML rules to extend or replace the built-in 106-rule set:

```bash
snaffler ... --rule-dir /path/to/rules/
```

## Example

```toml
# Find backup files by extension
[[ClassifierRules]]
EnumerationScope = "FileEnumeration"
RuleName = "FindBackupFiles"
MatchAction = "Snaffle"
Description = "Find potentially interesting backup files"
MatchLocation = "FileExtension"
WordListType = "Exact"
WordList = [".bak", ".backup", ".old", ".orig"]
Triage = "Yellow"

# Relay scripts to content scanning
[[ClassifierRules]]
EnumerationScope = "FileEnumeration"
RuleName = "SearchScriptsForCreds"
MatchAction = "Relay"
Description = "Scan script files for credentials"
MatchLocation = "FileExtension"
WordListType = "Exact"
WordList = [".ps1", ".sh", ".bat", ".cmd", ".py", ".rb", ".pl"]
RelayTargets = ["FindCredsInScripts"]

# Content regex rule (triggered by relay above)
[[ClassifierRules]]
EnumerationScope = "ContentsEnumeration"
RuleName = "FindCredsInScripts"
MatchAction = "Snaffle"
Description = "Find hardcoded credentials in scripts"
MatchLocation = "FileContentAsString"
WordListType = "Regex"
WordList = [
    "password\\s*=\\s*['\"][^'\"]+['\"]",
    "apikey\\s*=\\s*['\"][^'\"]+['\"]",
]
Triage = "Red"

# Skip directories (performance)
[[ClassifierRules]]
EnumerationScope = "DirectoryEnumeration"
RuleName = "SkipLogDirectories"
MatchAction = "Discard"
Description = "Skip log directories"
MatchLocation = "FilePath"
WordListType = "Contains"
WordList = ["/logs/", "/var/log/"]
```

## Rule Fields

| Field | Values |
|-------|--------|
| `EnumerationScope` | `FileEnumeration`, `ContentsEnumeration`, `DirectoryEnumeration` |
| `MatchAction` | `Snaffle` (report), `Relay` (pass to content rule), `Discard` (skip) |
| `MatchLocation` | `FileExtension`, `FileName`, `FilePath`, `FileContentAsString` |
| `WordListType` | `Exact`, `Contains`, `Regex` |
| `Triage` | `Green`, `Yellow`, `Red`, `Black` |
| `RelayTargets` | List of `RuleName`s to relay matched files to |

See `snaffler/rules/example_custom_rule.toml` for more examples.
