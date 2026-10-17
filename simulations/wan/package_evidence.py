#!/usr/bin/env python3
"""Export completed evidence without build output or SQLite binary stores."""
import gzip, json, pathlib, shutil, sqlite3, sys
src, dest=map(pathlib.Path,sys.argv[1:])
dest.mkdir(parents=True,exist_ok=True)
for summary in sorted(src.glob('*/summary.json')):
    run=summary.parent
    target=dest/run.name
    target.mkdir(exist_ok=True)
    shutil.copy2(summary,target/'summary.json')
    with (run/'trace.jsonl').open('rb') as f, gzip.open(target/'trace.jsonl.gz','wb',compresslevel=9) as g: shutil.copyfileobj(f,g)
    for db_path in sorted(run.glob('receiver-*.sqlite')):
        db=sqlite3.connect(f'file:{db_path}?mode=ro',uri=True)
        db.row_factory=sqlite3.Row
        integrity=db.execute('PRAGMA integrity_check').fetchone()[0]
        assert integrity=='ok'
        data={'integrity_check':integrity,'binding':[dict(r) for r in db.execute('SELECT * FROM replication_binding')],
            'events':[dict(r) for r in db.execute('SELECT * FROM replication_events ORDER BY sequence')]}
        (target/(db_path.stem+'.json')).write_text(json.dumps(data,indent=2)+'\n')
        db.close()
    log=src/(run.name+'.log')
    if log.exists():shutil.copy2(log,dest/log.name)
for name in ['source-binary.sha256','campaign-summary.json']:
    if (src/name).exists():shutil.copy2(src/name,dest/name)
