import json,logging
from datetime import datetime,UTC

STANDARD=set(logging.makeLogRecord({}).__dict__)
class JsonFormatter(logging.Formatter):
    def format(self,record):
        data={"timestamp":datetime.now(UTC).isoformat(),"level":record.levelname,"logger":record.name,"message":record.getMessage()}
        data.update({k:v for k,v in record.__dict__.items() if k not in STANDARD and k not in {"message","asctime"} and isinstance(v,(str,int,float,bool,type(None)))})
        if record.exc_info:data["exception"]=self.formatException(record.exc_info)
        return json.dumps(data)
def configure_logging():
    handler=logging.StreamHandler();handler.setFormatter(JsonFormatter());logger=logging.getLogger("cirt_lens");logger.handlers=[handler];logger.setLevel(logging.INFO);logger.propagate=False
