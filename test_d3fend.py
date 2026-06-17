# test_d3fend.py
import requests, json

r = requests.get("https://d3fend.mitre.org/api/offensive-technique/attack/T1110.json", timeout=15)
print(json.dumps(r.json(), indent=2)[:2000])