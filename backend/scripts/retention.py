import os
from datetime import datetime,timedelta,UTC
from app.database import SessionLocal
from app.models import Event
def run(days=int(os.getenv("TELEMETRY_RETENTION_DAYS","90")),dry_run=True):
    db=SessionLocal();cutoff=datetime.now(UTC).replace(tzinfo=None)-timedelta(days=days);query=db.query(Event).filter(Event.timestamp<cutoff);count=query.count()
    if not dry_run:query.delete(synchronize_session=False);db.commit()
    db.close();return {"cutoff":cutoff.isoformat()+"Z","eligible":count,"deleted":0 if dry_run else count,"dry_run":dry_run}
if __name__=="__main__":print(run(dry_run=os.getenv("RETENTION_APPLY","false").lower()!="true"))
