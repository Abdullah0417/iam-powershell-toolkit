# IAM PowerShell Toolkit

PowerShell commands for reviewing Active Directory group access, processing CSV membership changes, creating security groups, and updating group owners. The Microsoft Graph command reports direct Entra ID group membership.

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

Every AD write requires `-Commit`; write commands preview by default. Use `-Commit -WhatIf` to show planned operations without applying them. Preview still queries AD and can save local reports. The Graph report only reads data.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+ on Windows for AD commands.
- RSAT Active Directory PowerShell module and permission to query the domain. Changes require corresponding AD permissions.
- One AD domain/server per run.
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

The membership CSV uses `GroupName`, `UserName`, and `Action` (`Add` or `Remove`). All rows are validated before writing. Repeated group/user pairs are rejected, including aliases for the same objects. Only security groups are supported, and disabled users cannot be added.

A write or verification failure stops the batch. Earlier changes are not rolled back; check AD before retrying.

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

The creation CSV uses `GroupName`, `Description`, `PrimaryOwner`, `SecondaryOwner`, and `Members`. Optional columns are `TicketNumber` and `GroupScope` (default `Universal`). Separate multiple members with semicolons. Use **sAMAccountNames** for owners and members, resolvable on the selected server.

- `ManagedBy` stores the primary owner.
- The secondary owner's DN goes into `extensionAttribute12` by default. You can select another attribute from `extensionAttribute1` through `extensionAttribute15`; it must exist on groups and be reserved for this use.
- New groups receive ticket numbers in the AD `info` attribute when provided.
- The ticket comments CSV contains only successfully created and verified groups. Requested CSV outputs are overwritten; when there are no rows, the file is empty without headers.
- An error after group creation can leave a **partially created** group. The script reports `Partial` and stops further writes without deleting the group. A failed response does not prove that AD made no change; check before retrying.

The secondary-owner attribute is a lab convention. AD has no native secondary-owner relationship, and neither owner field grants membership-management rights.

Update an owner or save a read-only snapshot:

```powershell
Set-IamGroupOwner -GroupName 'SG-Sample-App-Readers' -Server 'corp.example.com' `
    -PrimaryOwner jdoe -Commit

Set-IamGroupOwner -GroupName 'SG-Sample-App-Readers' -Server 'corp.example.com' `
    -SecondaryOwner asmith -SecondaryOwnerAttribute extensionAttribute12

Export-IamGroupSnapshot -Path .\Examples\groups.txt -Server 'corp.example.com' `
    -OutputDirectory .\Snapshots
```

Owner changes validate all requested groups before writing. To check a new primary owner against the existing secondary owner, supply `-SecondaryOwnerAttribute`. Without it, only `ManagedBy` is checked.

Snapshots save the group report as JSON. They cannot restore AD objects.

## Microsoft Graph / Entra ID

The Graph command uses the [direct membership endpoint](https://learn.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0) with the `microsoft.graph.group` cast. It returns direct groups, including distribution groups. It does not expand nested membership or calculate effective access.

The cast requires `$count=true` and `ConsistencyLevel: eventual`; recent changes can take time to appear in results.

```powershell
Install-Module Microsoft.Graph.Authentication -Repository PSGallery -Scope CurrentUser
Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'GroupMember.Read.All' -ContextScope Process

Get-IamGraphGroupMembership -UserPrincipalName 'alex@contoso.com'
Get-IamGraphGroupMembership -Path .\Examples\graph-users.csv `
    -ExportPath .\entra-memberships.csv

Disconnect-MgGraph
```

Delegated [`GroupMember.Read.All`](https://learn.microsoft.com/en-us/graph/permissions-reference#groupmemberreadall) reads memberships and basic group fields and requires administrator consent. `User.Read.All` can read another user's membership relationship with limited group details. No write scopes are needed.

Hidden memberships require separately authorized `Member.Read.Hidden`. The report is not a complete entitlement audit.

The command validates and follows [`@odata.nextLink`](https://learn.microsoft.com/en-us/graph/paging) and sends the consistency header on every page. Authentication uses the Graph module. Only the public Microsoft Graph endpoint is supported.

Users with no returned groups produce no rows. A Graph failure stops the report without exporting partial results.

## Testing and limits

`Tests/IAMToolkit.Tests.ps1` uses Pester 5 and mocked AD/Graph commands. Run from the repository root in a fresh PowerShell session:

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Repository PSGallery -Scope CurrentUser
Import-Module Pester -RequiredVersion 5.7.1
Invoke-Pester .\Tests\IAMToolkit.Tests.ps1
```

GitHub Actions runs these mocked tests and PSScriptAnalyzer warning/error checks on PowerShell 7 and Windows PowerShell 5.1. The tests cover preview and `-WhatIf`, CSV validation, membership and owner changes, creation failures, snapshots, and Graph pagination.

Live AD, Entra, permissions, and replication testing has not been performed for this project. Use the [`lab checklist`](docs/lab-checklist.md) to check behavior in a disposable environment before operational use.

There is no transactional rollback, retry/backoff for Graph throttling, cross-domain provisioning, privileged-account provisioning, or group deletion. Input validation cannot prevent concurrent directory changes between planning and writing.

## Sample data and reports

Sample users, groups and tickets are fictional. Reports from your own directory can contain identity and access data; keep those exports local and out of Git.
