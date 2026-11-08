# IAM PowerShell Toolkit

Seven commands for Active Directory reports, CSV membership and group requests, owner changes, and a read-only Microsoft Entra ID membership report. This portfolio uses standard AD cmdlets and plain CSV files for lab use and code review.

## What's included

| Command | What it does |
| --- | --- |
| `Get-IamADGroupReport` | Direct members, parent groups, description and primary owner |
| `Get-IamADUserGroupReport` | Direct AD group links for one or more users |
| `Invoke-IamMembershipCsv` | Add/remove direct group membership from a CSV |
| `Set-IamGroupOwner` | Change the primary owner and optionally a secondary-owner attribute |
| `New-IamADGroupsFromCsv` | Bulk-create security groups with owners, members and ticket metadata |
| `Export-IamGroupSnapshot` | Save a read-only JSON report of existing group information |
| `Get-IamGraphGroupMembership` | Read direct Entra ID group membership using Microsoft Graph |

The Graph report is **read-only**. Every AD write requires `-Commit`; write commands preview by default. Use `-Commit -WhatIf` to show the planned AD operations without applying them. `-Confirm` and PowerShell's confirmation preferences still apply to the outer command. Preview and `-WhatIf` still query AD, and requested local reports may be written.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+ on Windows for AD commands.
- RSAT Active Directory PowerShell module and permission to query the domain. Changes require corresponding AD permissions.
- A single AD domain/server for these examples. The public version does **not** implement cross-domain provisioning or a hybrid sync workflow.
- For the Graph command: `Microsoft.Graph.Authentication`, an authorized work/school account, and appropriate tenant consent.

```powershell
Import-Module .\IAMToolkit.psm1 -Force
Get-Command -Module IAMToolkit
```

## AD examples

The examples below use a **fictional** `corp.example.com` directory. Replace the server and OU with your own lab values.

Read group information:

```powershell
Get-IamADGroupReport -GroupName 'SG-Sample-App-Readers' -Server 'corp.example.com' |
    Format-List

Get-IamADGroupReport -Path .\Examples\groups.txt -Server 'corp.example.com' `
    -ExportPath .\group-report.csv

Get-IamADUserGroupReport -Path .\Examples\users.csv -Server 'corp.example.com' `
    -ExportPath .\user-groups.csv
```

The user report reads direct `memberOf` links. It excludes the user's primary group and does not expand nested groups.

Review and apply membership changes:

```powershell
Invoke-IamMembershipCsv -Path .\Examples\membership.csv -Server 'corp.example.com'
Invoke-IamMembershipCsv -Path .\Examples\membership.csv -Server 'corp.example.com' -Commit -WhatIf
Invoke-IamMembershipCsv -Path .\Examples\membership.csv -Server 'corp.example.com' -Commit `
    -ReportPath .\membership-results.csv
```

The membership CSV uses `GroupName`, `UserName`, and `Action` (`Add` or `Remove`). All rows are validated and resolved before writing; repeated group/user pairs are rejected, including aliases resolving to the same objects. Only security groups are supported, and adding a disabled user is rejected. A write or read-back failure stops further AD writes. Earlier changes are not rolled back; inspect AD before retrying a failed request.

Bulk group creation:

```powershell
$ou = 'OU=Groups,DC=corp,DC=example,DC=com'

New-IamADGroupsFromCsv -Path .\Examples\new-groups.csv -TargetOU $ou `
    -Server 'corp.example.com'

New-IamADGroupsFromCsv -Path .\Examples\new-groups.csv -TargetOU $ou `
    -Server 'corp.example.com' -Commit -WhatIf

New-IamADGroupsFromCsv -Path .\Examples\new-groups.csv -TargetOU $ou `
    -Server 'corp.example.com' -Commit -ReportPath .\create-results.csv `
    -TicketCommentsPath .\ticket-comments.csv
```

The creation CSV uses `GroupName`, `Description`, `PrimaryOwner`, `SecondaryOwner`, and `Members`. Optional columns are `TicketNumber` and `GroupScope` (default `Universal`). Put several members in one cell separated by semicolons. Owner/member values should be **sAMAccountNames** resolvable on the selected server.

- `ManagedBy` stores the primary owner.
- The secondary owner's DN goes into `extensionAttribute12` by default. This requires that attribute to exist in your AD schema and be available on groups; `extensionAttribute1` through `extensionAttribute15` are accepted. These fields are a lab convention, not a standard AD secondary-owner relationship, and may already have another purpose in your directory. Setting either owner does not grant permission to manage group membership.
- New groups receive ticket numbers in the AD `info` attribute when provided.
- The ticket comments CSV contains only groups whose creation and verification succeeded. Use a fresh output path for each run.
- An error after group creation may leave a **partially created** group. The script reports `Partial`, stops further writes, and does not automatically delete the group. A failed creation request can also have an uncertain server-side outcome; check AD before retrying.

Update an owner or save a read-only snapshot:

```powershell
Set-IamGroupOwner -GroupName 'SG-Sample-App-Readers' -Server 'corp.example.com' `
    -PrimaryOwner jdoe -Commit

Set-IamGroupOwner -GroupName 'SG-Sample-App-Readers' -Server 'corp.example.com' `
    -SecondaryOwner asmith -SecondaryOwnerAttribute extensionAttribute12

Export-IamGroupSnapshot -Path .\Examples\groups.txt -Server 'corp.example.com' `
    -OutputDirectory .\Snapshots
```

Owner changes resolve all requested groups before writes. A snapshot contains the same name-based summary as the group report; it is not a backup or a restore mechanism.

## Microsoft Graph / Entra ID

The Graph command uses the [direct membership endpoint](https://learn.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0) with the `microsoft.graph.group` cast. It returns direct groups, including distribution groups, rather than transitive or effective access. The cast requires `$count=true` and `ConsistencyLevel: eventual`; recent changes can take time to reach the index.

```powershell
Install-Module Microsoft.Graph.Authentication -Repository PSGallery -Scope CurrentUser
Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'GroupMember.Read.All' -ContextScope Process

Get-IamGraphGroupMembership -UserPrincipalName 'alex@contoso.com'
Get-IamGraphGroupMembership -Path .\Examples\graph-users.csv `
    -ExportPath .\entra-memberships.csv

Disconnect-MgGraph
```

The example uses delegated [`GroupMember.Read.All`](https://learn.microsoft.com/en-us/graph/permissions-reference#groupmemberreadall), which supports reading this membership relationship and basic group fields. It requires administrator consent. The endpoint documents `User.Read.All` as the least delegated permission for another user's membership relationship; with insufficient permission for group properties, Graph can return IDs with other fields null. Broad directory permissions, `Group.Read.All`, and write scopes are not needed for this report. Hidden memberships require separately authorized `Member.Read.Hidden`; the example does not request it, so do not treat the result as a complete entitlement audit.

The command follows the entire [`@odata.nextLink`](https://learn.microsoft.com/en-us/graph/paging) URL after validating it, and sends the consistency header on every page. It only makes GET requests and leaves authentication to `Microsoft.Graph.Authentication`. The example targets the public Microsoft Graph endpoint; national cloud endpoints are not supported. Users with no returned groups produce no report rows. Graph failures terminate the report rather than exporting a partial result.

## Testing and limits

`Tests/IAMToolkit.Tests.ps1` uses Pester 5 and mocked AD/Graph commands. Run from the repository root in a fresh PowerShell session:

```powershell
Install-Module Pester -MinimumVersion 5.0 -Repository PSGallery -Scope CurrentUser
Import-Module Pester -MinimumVersion 5.0
Invoke-Pester .\Tests\IAMToolkit.Tests.ps1
```

The tests exercise preview and `-WhatIf`, CSV validation, membership and owner changes, creation failures, and Graph pagination without a real directory or tenant. They do **not** establish live AD/Graph compatibility, permissions, schema configuration, or replication behavior. Before using a write command, test with disposable lab users and groups, including failed writes and partial creation. See [`docs/lab-checklist.md`](docs/lab-checklist.md).

There is no transactional rollback, retry/backoff for Graph throttling, cross-domain provisioning, privileged-account provisioning, or group deletion. Input validation cannot prevent concurrent directory changes between planning and writing.

## Notes

Sample users, groups and tickets are fictional. Don't upload real user exports, screenshots, logs, internal names, tokens or credential files to this repository. Review organizational code ownership and publication policies before sharing code based on workplace tasks.

Generated CSV/JSON may contain identity and entitlement data. Keep exports local and review them before sharing.
