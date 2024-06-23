"logger main setting"
import logging
# from fastapi import FastAPI


logger = logging.getLogger()
logger.setLevel(logging.INFO)

ch = logging.StreamHandler()
fh = logging.FileHandler(filename="example.log")
formatter = logging.Formatter("%(asctime)s %(message)s")

ch.setFormatter(formatter)
fh.setFormatter(formatter)
logger.addHandler(ch)
logger.addHandler(fh)

logger.warning("is when this event was logged.")