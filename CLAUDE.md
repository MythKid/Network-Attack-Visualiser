# Network Attack Visualiser - Claude Code Instructions

## Session Initialisation

At the beginning of every new Claude Code session, before making any changes, respond with:

Hi MythKid 👋. I have successfully loaded the project instructions.

Then provide:

- Current Git branch
- Current Git status
- Current development phase
- Files likely to be modified
- Any blockers or concerns

If this initialisation is not completed, stop and wait for further instructions.

---

# Project Overview

This project is a defensive networking and cybersecurity application.

Purpose:

- Capture authorised network traffic.
- Detect suspicious network behaviour.
- Visualise attacks in real time.
- Demonstrate networking, cybersecurity and software engineering skills.
- Produce production-quality code suitable for a graduate portfolio.

This project is intended only for education, research and authorised laboratory environments.

Never build offensive malware.
Never build persistence mechanisms.
Never build credential theft.
Never target third-party systems.
Never encourage illegal activity.

---

# Working Style

Always:

- Read existing code before modifying it.
- Understand the project structure before making changes.
- Work in small logical phases.
- Explain significant architectural decisions.
- Keep code modular and maintainable.
- Prefer readability over cleverness.
- Preserve existing functionality unless explicitly instructed otherwise.
- Ask before making breaking architectural changes.
- Explain trade-offs when multiple implementations exist.

---

# Git Discipline

Always:

- Make small logical commits.
- Keep one logical change per commit.
- Show the proposed commit message before committing.
- Show `git status` before every commit.
- Run relevant tests before committing.
- Explain what changed before committing.

Never:

- Commit automatically.
- Push automatically.
- Force push.
- Rewrite Git history.
- Rebase published commits.
- Delete branches.
- Change Git remotes.
- Squash or amend commits without permission.

Always ask before running:

- git commit
- git push
- git merge
- git rebase
- git reset
- git clean

---

# Repository Safety

Never commit:

- .env
- .env.*
- API keys
- passwords
- tokens
- secrets
- private keys
- certificates
- *.db
- *.sqlite
- *.sqlite3
- *.pcap
- *.pcapng
- *.cap
- runtime logs
- temporary files
- generated build output
- node_modules
- __pycache__

Always use:

- .env.example
- placeholder values

---

# Dependencies

Before adding a major dependency explain:

- Why it is required.
- Alternative options.
- Licence.
- Maintenance status.
- Security considerations.
- Performance impact.

Do not install unnecessary packages.

Prefer mature and actively maintained libraries.

---

# Code Standards

Write production-quality code.

Always:

- Use clear variable names.
- Use type hints.
- Add docstrings where appropriate.
- Keep functions small.
- Keep classes focused.
- Handle errors explicitly.
- Validate external input.
- Avoid duplicated logic.

Never:

- Leave dead code.
- Leave commented-out experimental code.
- Ignore exceptions silently.
- Hardcode secrets.

---

# Architecture

Keep responsibilities separated.

Prefer modules such as:

- Packet Capture
- Detection Engine
- Alert Engine
- Backend API
- Frontend Dashboard
- Database Layer
- Docker Configuration
- Testing
- Documentation

Avoid unnecessary coupling between components.

---

# Detection Standards

Every detector should document:

- Detection objective.
- Detection logic.
- Observation window.
- Threshold.
- False positives.
- Limitations.

Never claim an attack with absolute certainty when using heuristics.

Use severity levels where appropriate.

---

# Networking Standards

Always:

- Handle malformed packets safely.
- Handle missing packet fields.
- Handle unexpected protocols.
- Keep packet capture independent from analysis.
- Minimise payload storage.
- Prefer metadata over payloads.
- Make thresholds configurable where practical.

Never log:

- Passwords
- Authentication tokens
- Cookies
- Sensitive payloads

---

# Docker Standards

Use:

- Minimal images.
- Health checks.
- Version pinning.
- Multi-stage builds where appropriate.
- Non-root containers whenever practical.

Never:

- Store secrets inside images.
- Expose unnecessary ports.
- Use privileged containers unless required and approved.

---

# Testing

Before marking work complete:

- Run relevant tests.
- Verify Docker builds successfully.
- Verify the application starts.
- Test normal behaviour.
- Test malformed input.
- Test failure scenarios.

Never claim something works unless it has actually been tested.

---

# Documentation

Whenever functionality changes update:

- README.md
- Architecture documentation
- Installation guide
- Environment variable documentation
- API documentation

Never document features that do not yet exist.

---

# Portfolio Quality

Treat this repository as production-quality software.

Assume future employers will inspect:

- Source code
- Git history
- Documentation
- Architecture
- Security practices

Prefer solutions that demonstrate:

- Networking knowledge
- Cybersecurity knowledge
- Software engineering
- System design
- Clean architecture
- Professional documentation

Explain engineering trade-offs whenever appropriate.

---

# Progress Tracking

Maintain:

docs/PROJECT_PROGRESS.md

After every completed phase update:

- Completed work
- Current phase
- Remaining work
- Known issues
- Next milestone

---

# End of Task Report

At the end of every completed task provide:

1. Summary of work completed
2. Files modified
3. Commands executed
4. Tests executed
5. Git status
6. Suggested commit message
7. Remaining work
8. Recommended next task

Never commit or push unless explicitly instructed.

---

# Final Reminder

Build this project as if it were being developed by a professional cybersecurity company.

Optimise for:

- Security
- Reliability
- Maintainability
- Scalability
- Readability
- Professionalism

Whenever multiple solutions are possible, choose the one that would make this repository the strongest portfolio project for a Networking & Cybersecurity graduate.
