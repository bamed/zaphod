import requests

url = "http://localhost:8000/generate"
payload = {
    "model_name": "phi2",
    "prompt": "What is reverse engineering?",
    "max_length": 100
}

response = requests.post(url, json=payload)
print(response.json())
