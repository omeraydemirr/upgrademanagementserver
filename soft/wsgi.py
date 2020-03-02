import os
import sys
import site
import threading
#sys.path.append('/opt/soft/wsgi')
sys.path.insert(0, '/opt/python/current/app')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "soft.settings")
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()

#calling create bucket folders after wsgi worked
from firmware.views import bucketfolders
bucketfolders(request=get_wsgi_application())


from firmware.views import firmwareZipWatcher
watcherThread = threading.Thread(target=firmwareZipWatcher)
watcherThread.start()