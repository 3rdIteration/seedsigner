# GitHub Workflows

This directory contains GitHub Actions workflows for the SeedSigner project.

## Claude Code Workflows

### Automatic Custom Instructions

Both `claude.yml` and `claude-code-review.yml` workflows automatically read and include custom instructions from the following files in the repository root:

- **CLAUDE.md**: Custom instructions for Claude Code agents
- **AGENTS.md**: Additional agent-specific instructions

These instruction files are automatically combined and passed to Claude Code via the `settings` parameter. This ensures that all Claude Code invocations (whether triggered by @claude mentions or automatic code reviews) follow the project-specific guidelines defined in these files.

#### How It Works

1. **Checkout**: The repository is checked out with the workflow
2. **Prepare Instructions**: A bash script reads both `CLAUDE.md` and `AGENTS.md` files (if they exist)
3. **Combine**: The contents are combined into a single instruction file at `/tmp/combined_instructions.txt`
4. **Create Settings**: A JSON settings file is created using `jq` with the combined instructions as the `systemPrompt`
5. **Run Claude**: The Claude Code action uses the settings file to apply the custom instructions

#### Workflow Files

- **claude.yml**: Triggered when @claude is mentioned in issues, PRs, or comments
- **claude-code-review.yml**: Automatically triggered on PR events (opened, synchronize, etc.)

#### Modifying Instructions

To update the instructions that Claude follows:

1. Edit `CLAUDE.md` or `AGENTS.md` in the repository root
2. Commit the changes
3. The next workflow run will automatically use the updated instructions

No workflow file changes are needed when updating instructions.
