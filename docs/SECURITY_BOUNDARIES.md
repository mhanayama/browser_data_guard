# Security boundaries and failure modes

## Conditional guarantee

After successful attachment to the configured NTFS volume, a new sensitive
`IRP_MJ_CREATE` whose normalized pre-create path lies at/below the configured root
is denied to every process except the single registered process object. Denial
returns `STATUS_ACCESS_DENIED` before that create reaches the filesystem. This
requires stable names, no aliases, no earlier handles and no trusted broker.
The PoC is a path gate, not persistent object-level mandatory access control.

| Operation | Untrusted behavior under protected path |
| --- | --- |
| Read, execute, directory list, CopyFile source, backup-intent read | Deny new handle |
| Write/append, DELETE, WRITE_DAC, WRITE_OWNER | Deny new handle |
| FILE_CREATE/OPEN_IF/OVERWRITE/SUPERSEDE, delete-on-close | Deny even with no requested content rights |
| MAXIMUM_ALLOWED or unmapped generic data rights | Deny conservatively |
| Metadata-only FILE_OPEN (attributes, READ_CONTROL, synchronize) | Allow, subject to ACL; filenames/metadata are not secrets in this model |
| Rename/delete/link via earlier handle; writes on earlier handle | Not mediated; known integrity and confidentiality gap |
| Cleanup/close and existing mappings | Not blocked/revoked |
| Trusted process opens | Allow, subject to filesystem ACL |
| Sensitive create with unavailable normalized name | Deny on attached volume, even outside root |

## Why CREATE is insufficient for a production boundary

* Existing handles survive policy activation and disconnect. DuplicateHandle can
  transfer an allowed handle to an untrusted process without another create.
  Read callbacks can add checks for explicit reads but cannot safely attribute
  every paging read to an origin process and cannot revoke existing mapped pages.
* A new mapping through a denied new open fails, but existing file handles and
  section handles can create/share mappings. Already faulted pages need no IO.
  Section-synchronization callbacks have documented failure constraints; this
  PoC does not invent STATUS_ACCESS_DENIED enforcement at that callback.
* NTFS hard links outside the root refer to the same data. FILE_OPEN_BY_FILE_ID,
  short names, device aliases, case-sensitive directories and reparse resolution
  need object identity and canonicalization tests. Normalized path matching does
  not prove all aliases are recognized. Alternate streams under a matched path
  are included, but streams through an outside hard link remain a gap.
* Rename/link creation and ancestor renames can move protected data outside the
  root; an old DELETE-capable handle bypasses a new-open restriction. A reparse
  point inside the root can redirect data outside it. An outside junction to the
  root may resolve back inside, but this is a test observation, not a guarantee.
  File-name tunneling can invalidate a normalized pre-create final component.
* Local NTFS attachment excludes SMB, ReFS, FAT, snapshots and raw volume access.
  Root device names can change after reboot. Resolve and configure again in the
  VM. Filter load/attach failure and unload are **unprotected**, never healthy.

Production prerequisites include volume-scoped file IDs, link-set tracking,
stream contexts, source/destination rename/link checks (including ancestors),
reparse policy, safe pre-create/post-create identity reconciliation, process
creation/image binding, and a handle/mapping policy. A fail-closed pre-create
decision must still prevent destructive operations before they occur. Adding
post-create cancellation alone does not solve these issues.

## Availability and stability risks

Name lookup errors deny sensitive opens volume-wide. Backup, indexing, AV,
crash reporting, updaters and migration tools can fail. A browser that starts
before registration can see access-denied errors or fail to start. Revocation
does not stop IO on old handles. Denying writes can break SQLite WAL recovery,
LevelDB locks and browser shutdown if legitimate subprocesses lack their own
grant. The PoC has no browser subprocess grant automation. Do not activate this
lab-only policy on live profiles. The notifier's read-only location inventory
does not change this restriction or establish a browser/credential boundary.

Audit uses bounded nonpaged storage and process references; loss is counted, not
permission fallback. Filter Manager teardown must quiesce callbacks before
global resources are freed. Unload intentionally removes protection and is for
VM recovery, not tamper resistance. Never unload as an automatic error response.

**Runtime checked:** a dedicated Windows 11 evaluation VM ran synthetic access
tests, test-signed installation, unload/reload and Driver Verifier standard checks
targeting BdgDriver.sys. Existing handles, mappings and outside hard links were
confirmed as limitations. These bounded tests do not establish exhaustive IRQL,
race or lifetime correctness. Full fault injection, protocol fuzzing, long-running
stress and genuine-browser compatibility remain unvalidated.
