# Threat model

## Assets and adversary

Target assets are local browser cookies, SQLite companions, Local Storage, and
Chromium Local State. A compromised ordinary application under the same Windows
user can call Win32/native file APIs, copy files, request backup intent, choose
paths and access masks, and run concurrently. It must not receive a new content
handle through the configured protected path while the filter is active.

The current implementation protects only synthetic fixtures. It does not claim
that Chrome, Edge, or Firefox sessions are protected. Browser rules and trust
binding are a subsequent phase described in ARCHITECTURE.md.

## Trusted computing base and assumptions

Windows kernel, local NTFS, Filter Manager, driver binary/configuration, elevated
administrators/SYSTEM and the policy service are trusted. Service configuration,
hash pins, binaries and logs must have administrator-controlled ACLs. A normal
user must not be able to alter service ImagePath or options. The lab's explicit
unsigned option is not a production authorization method. Trust applies to one
process object, without automatic descendants. Existing process access rights
that permit injection into that process are outside this boundary.

Activate on a fresh fixture tree with no existing handles, mappings, hard links,
reparse points, or concurrent namespace manipulation. Ancestors must be stable.
These assumptions are required for the PoC's path-based guarantee, not established
by simply installing the driver. Do not put valuable data in the lab tree.

## Exclusions

Kernel attackers; privileged driver/service tampering; malicious extensions;
DevTools; process injection, hollowing, or malicious DLLs in a trusted process;
trusted software exporting data to unprotected files; secrets already in memory;
offline disks, raw-volume reads, VSS snapshots, remote shares and other machines.
Handle duplication and pre-existing mappings are explicit PoC gaps even for an
ordinary user. BDG is not a general EDR and never needs to terminate the requester
for denial to take effect.

## Abuse cases and response

| Case | Initial behavior |
| --- | --- |
| Stealer uses ReadFile, CopyFile or SQLite through protected path | Sensitive open denied before filesystem access |
| Stealer renames executable to chrome.exe | No trust; exact referenced process object required |
| PID recycled after trusted process exits | New object is denied |
| Service dies or malformed policy arrives | Root retained; disconnect removes trust; invalid messages fail |
| Requester asks MAXIMUM_ALLOWED or truncate with zero access | Conservatively denied |
| Audit consumer stalls/floods | Bounded ring, explicit loss count; denial continues |
| Existing hard link outside root, open by ID, namespace race | Known bypass; not advertised as protected |
| Duplicate trusted handle or use an earlier mapping | Known bypass; no revocation guarantee |
| Browser update changes image hash | Reverification required; no automatic path/name allow |
| Administrator unloads filter | Explicit protection gap; outside tamper-resistance scope |

Security testing must distinguish expected gaps from passing protection tests.
Successful synthetic tests do not validate browser compatibility or establish
protection against all session theft.
