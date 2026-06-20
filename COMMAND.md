# Useful Commands

## Ingest CLI

The `ingest` container runs persistently. Use `docker compose exec` with the `vdb` wrapper:

```bash
docker compose exec ingest vdb schema
docker compose exec ingest vdb sync redhat
docker compose exec ingest vdb import redhat
docker compose exec ingest vdb hasura-init
docker compose exec ingest vdb create-token --ttl 90
docker compose exec ingest vdb pipeline <job-name>
```

`import` is also available as a shorthand:

```bash
docker compose exec ingest import suse debian alpine almalinux rocky oracle
```

## Docker

### Run a Python one-liner inside the ingest container

```bash
docker compose exec ingest python3 -c "<python code>"
```

#### Examples

Inspect keys of a CVRF vulnerability entry:
```bash
docker compose exec ingest python3 -c "import json,glob; f=sorted(glob.glob('/data/msrc/cvrf/*.json'))[0]; d=json.load(open(f)); print(list(d['Vulnerability'][0].keys()))"
```

Find ADV-numbered vulnerability entries:
```bash
docker compose exec ingest python3 -c "import json,glob; files=sorted(glob.glob('/data/msrc/cvrf/*.json')); found=[(f,v) for f in files for v in json.load(open(f)).get('Vulnerability',[]) if not str(v.get('CVE','')).startswith('CVE-')][:3]; [print('File:',f,'CVE field:',repr(v.get('CVE')),'Title:',v.get('Title',{}).get('Value','')) for f,v in found]"
```
