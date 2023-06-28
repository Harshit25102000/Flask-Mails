from celery import shared_task,Celery
from celery_config import *

@shared_task(bind=True,ignore_result=False)
def func(self):
    print("celery running")