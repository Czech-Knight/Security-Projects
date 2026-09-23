# GitHub transformation playbook

## Ownership and scope

Personal account: `Czech-Knight`. This rollout proposes changes only to six owned repositories, not to shared organization repositories.

| Repository | Base branch | Proposed PR | Deployment-sensitive areas preserved |
| --- | --- | --- | --- |
| cloud-security-drift-detector | main | [PR #10](https://github.com/Czech-Knight/cloud-security-drift-detector/pull/10) | Existing live AWS drift scan, Terraform and Python CI |
| Security-Projects | yash | [PR #2](https://github.com/Czech-Knight/Security-Projects/pull/2) | Existing GitHub Pages deployment and YashSec application source |
| Recordly | main | [PR #1](https://github.com/Czech-Knight/Recordly/pull/1) | Existing Code Quality, multi-platform signing and release workflow |
| strix-dev- | main | [PR #2](https://github.com/Czech-Knight/strix-dev-/pull/2) | Existing build/release workflow |
| Web-Dev | yash | [PR #1](https://github.com/Czech-Knight/Web-Dev/pull/1) | Application and deployment files |
| PTRep (private) | yash | [PR #1](https://github.com/Czech-Knight/PTRep/pull/1) | Application and authentication files |

## Checklist after PR checks pass

1. Review the six PRs and their exact diff, especially new CI workflow permissions, job names and dependencies. Merge individual PRs only after the relevant tests pass; automation is not active on the default branch until merged.
2. Under **Settings > Rules > Rulesets** (or **Branches**), create an active rule for the actual default branch. Block deletion and force pushes; require PRs and *actual passing* unit/build jobs. On a solo-owned repository, do not require an impossible external approval.
3. Under **Settings > Code security and analysis** (UI wording varies), enable Dependabot alerts and security updates. Review each automatic update PR with CI; never auto-merge dependency upgrades without tests. Enable GitHub secret scanning and push protection when available for that repository and account plan.
4. On the Cloud Drift Detector, confirm the protected `drift-scan` environment, `DRIFT_SCAN_ENABLED` and the existing AWS OIDC trust/role. The static Checkov scan needs no AWS credentials; never add AWS static keys to a workflow.
5. For YashSec and WorkforcePulse, use the **root-level** workflows for required checks; the old workflows under nested application directories are not activated by GitHub as repository workflows.
6. Review advisory reports in the relevant Actions run's **Artifacts** area. Triage real findings and false positives, apply remediations, then introduce an explicit *separate* failing policy gate for agreed severity thresholds. A green report-only workflow does not mean no vulnerabilities were detected.
7. For profile visibility, create a **public** repository named exactly `Czech-Knight` under that account, initialize with README.md, then copy [the profile source](GITHUB_PROFILE_README.md) into its root README.md. This account-level repository cannot be created by the currently connected integration.
8. For release evidence, only publish a Cloud Drift Detector GitHub release with tag `v<pyproject project.version>` after CI passes. The release workflow builds distributions, creates SHA256 checksums and requests GitHub provenance attestation. GitHub release-note categories are in the Cloud Drift Detector's `.github/release.yml`; generate and review the notes before publishing. Test against a controlled release before relying on automated publishing.
9. Private `PTRep` repository rulesets may require a GitHub plan upgrade; verify current plan availability in the account Settings. Do not make the repository public merely to unlock governance functionality.

## Scope and verification limitations

New secret candidate reports scan the checked-out working tree, not the full Git history or GitHub's server-side push protection. Security candidate reports include file names and hashed detections, not raw discovered secret values; treat them as sensitive metadata. Static Checkov, pip-audit and npm audit run in advisory mode to preserve existing merge behavior, but scanner installation/execution failures still require investigation. Scheduled and release-only workflows must be separately triggered after merge to establish their runtime behavior.

If a new workflow causes issues, disable it in the Actions UI or revert only its addition; existing application source and deployment pipelines were not replaced. Never revert shared application state or cloud resources to fix a repository workflow problem.
