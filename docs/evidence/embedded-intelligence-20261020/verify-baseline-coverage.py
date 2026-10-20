import datetime, importlib.util, json, os, pathlib, sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
spec=importlib.util.spec_from_file_location('verification','/tmp/verify-embedded-intelligence.py')
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
engine=create_engine(os.environ['DATABASE_URL'])
with sessionmaker(engine)() as db:
    coverage=module.database_coverage(db,datetime.datetime.fromisoformat(sys.argv[1]))
pathlib.Path('/tmp/baseline-coverage.json').write_text(json.dumps(coverage,indent=2))
print(json.dumps(coverage['totals']))
engine.dispose()
