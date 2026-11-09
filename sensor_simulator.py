"""Симулятор датчиков парковки (требование R4).

Запуск (во втором терминале, пока работает сайт):
    python sensor_simulator.py
Каждые несколько секунд случайное место «занимается» или «освобождается»
датчиком. Забронированные места датчик не трогает.
Остановить: Ctrl+C.
"""
import json
import os
import random
import sys
import time
import urllib.request

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
TOKEN = os.environ.get("PARKGO_SENSOR_TOKEN", "parkgo-sensor-demo")
PAUSE = (float(os.environ.get("SENSOR_MIN", 3)), float(os.environ.get("SENSOR_MAX", 6)))


def get_spots():
    with urllib.request.urlopen(URL + "/api/spots", timeout=5) as r:
        return json.load(r)


def send(spot_id, status):
    req = urllib.request.Request(
        URL + "/api/sensor",
        data=json.dumps({"spot_id": spot_id, "status": status}).encode(),
        headers={"Content-Type": "application/json", "X-Sensor-Token": TOKEN},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status


print(f"Датчики подключены к {URL}. Ctrl+C - остановить.")
try:
    while True:
        spots = [s for s in get_spots() if s["status"] in ("Available", "Occupied")]
        if spots:
            s = random.choice(spots)
            new = "Occupied" if s["status"] == "Available" else "Available"
            send(s["id"], new)
            print(f"{time.strftime('%H:%M:%S')}  {s['loc']} / {s['name']}: {s['status']} -> {new}")
        time.sleep(random.uniform(*PAUSE))
except KeyboardInterrupt:
    print("\nДатчики остановлены.")
except Exception as e:
    print("Ошибка (сайт запущен?):", e)
