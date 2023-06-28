from celery import Celery
import celeryconfig2
# celery config
BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

# initialize celery app
def get_celery_app_instance(app):
    celery = Celery(
        app.import_name,
        backend=BROKER_URL,
        broker=BROKER_URL
    )
    #celery.conf.update(app.config)
    celery.config_from_object(celeryconfig2)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery