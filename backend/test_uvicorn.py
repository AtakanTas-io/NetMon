import sys
import uvicorn
import server
import threading
import time

print("Starting uvicorn test")
config = uvicorn.Config(server.app, host="127.0.0.1", port=8000, log_config=None)
http = uvicorn.Server(config)
def run():
    try:
        http.run()
    except Exception as e:
        print(f"UVICORN ERROR: {e}")

t = threading.Thread(target=run, daemon=True)
t.start()
time.sleep(3)
print("Finished waiting")
