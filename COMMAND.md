# Useful Commands

## Docker

### Run a Python one-liner inside the ingest container
```
docker compose run --rm --entrypoint python3 ingest -c "<python code>"
```

**Why `--entrypoint python3`**: The ingest container's default entrypoint intercepts all commands. Without overriding it, `python3` is passed as an argument to the entrypoint script, not executed directly.

#### Examples

Inspect keys of a CVRF vulnerability entry:
```
docker compose run --rm --entrypoint python3 ingest -c "import json,glob; f=sorted(glob.glob('/data/msrc/cvrf/*.json'))[0]; d=json.load(open(f)); print(list(d['Vulnerability'][0].keys()))"
```

Find ADV-numbered vulnerability entries:
```
docker compose run --rm --entrypoint python3 ingest -c "import json,glob; files=sorted(glob.glob('/data/msrc/cvrf/*.json')); found=[(f,v) for f in files for v in json.load(open(f)).get('Vulnerability',[]) if not str(v.get('CVE','')).startswith('CVE-')][:3]; [print('File:',f,'CVE field:',repr(v.get('CVE')),'Title:',v.get('Title',{}).get('Value','')) for f,v in found]"
```

### Standard ingest commands
```
docker compose run --rm ingest sync microsoft
docker compose run --rm ingest import microsoft
docker compose run --rm ingest schema
docker compose run --rm ingest hasura-init
```
