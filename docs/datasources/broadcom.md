# Broadcom (VMware)

Broadcom publishes the VMware security advisories (VMSA) on its support portal. NVD lists only
`open_vm_tools` for several VMware Tools CVEs, and the CNA records in the CVE List name the product
inconsistently with wildcard versions (`13.x.x.x`). The portal's **Response Matrix** is the
version-precise source for **VMware Tools** (the Windows product, `cpe:2.3:a:vmware:tools`) and VMware
Workstation.

## Support portal
- **List:** `POST https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList`
  (JSON body `pageNumber`, `pageSize`, `searchVal`, `segment`; no login). Segments synced: `VC` (VMware
  Cloud Foundation family) and `VA` (VMware Avi).
- **Advisory page:** the `notificationUrl` of each list entry (HTML) with the Response Matrix table.
- **Local path:** `broadcom/index.json` (list entries) and `broadcom/advisories/<notificationId>.html`
- **Sync:** `vdb sync broadcom` (member of the `advisories` group). An advisory is fetched when its
  `updated` stamp changed or its page is missing; a failed download is retried by the next run.
- **Affected:** `vdb affected broadcom`

## Response Matrix → affected

```
Product | Component | Version        | Running On      | CVE            | Fixed Version
VMware Tools | N/A  | 12.x.x, 11.x.x | Windows, Linux  | CVE-2025-41244 | 12.5.4
```

becomes `cpe:2.3:a:vmware:tools`, introduced `11` (lowest of the listed lines, wildcards removed),
fixed `12.5.4`. Skipped: fixed values that are not versions (`Unaffected`, `KB92148`, `Patch Pending`),
rows that run only on Linux or macOS, and products without a mapping (`_PRODUCTS` in
`ingest/affected/sources/broadcom.py`; extend per product once its fixed versions are plain versions).
The rows coexist with NVD's; the matcher ORs the lanes.

```
cve_vendor          ✅  {severity, advisory, title, url}   (source=broadcom)
advisory            ✅  VMSA / VC…DSA id, title, severity, published, updated
affected            ✅  coord=cpe — VMware Tools, Workstation
```
