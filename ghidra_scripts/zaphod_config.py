import json
import os
from java.net import URL
from java.io import BufferedReader, InputStreamReader

class ZaphodConfig:
    CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".ghidra", "zaphod_config.json")
    DEFAULT_CONFIG = {
        "api_endpoint": "http://localhost:8000",
        "api_key": ""
    }
    
    @classmethod
    def ensure_config_dir(cls):
        config_dir = os.path.dirname(cls.CONFIG_FILE)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
    
    @classmethod
    def load_config(cls):
        try:
            cls.ensure_config_dir()
            if os.path.exists(cls.CONFIG_FILE):
                with open(cls.CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    return dict(cls.DEFAULT_CONFIG, **config)
        except Exception as e:
            print("Warning: Could not load config: %s" % str(e))
        return dict(cls.DEFAULT_CONFIG)
    
    @classmethod
    def update_config(cls, api_endpoint, api_key):
        try:
            cls.ensure_config_dir()
            config = {
                "api_endpoint": api_endpoint.rstrip("/"),
                "api_key": api_key
            }
            with open(cls.CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print("Error saving config: %s" % str(e))
            return False

def make_api_request(endpoint, payload):
    try:
        config = ZaphodConfig.load_config()
        full_url = "%s%s" % (config["api_endpoint"], endpoint)
        
        url = URL(full_url)
        conn = url.openConnection()
        conn.setDoOutput(True)
        conn.setRequestMethod("POST")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("X-API-Key", config["api_key"])
        
        if payload:
            payload_json = json.dumps(payload)
            conn.getOutputStream().write(payload_json.encode('utf-8'))
        
        if conn.getResponseCode() == 200:
            reader = BufferedReader(InputStreamReader(conn.getInputStream()))
            response = ""
            line = reader.readLine()
            while line:
                response += line
                line = reader.readLine()
            reader.close()
            return json.loads(response)
            
        error_stream = conn.getErrorStream()
        if error_stream:
            reader = BufferedReader(InputStreamReader(error_stream))
            error_message = reader.readLine()
            reader.close()
            print("API Error (%d): %s" % (conn.getResponseCode(), error_message))
        else:
            print("API Error: %d" % conn.getResponseCode())
        return None
            
    except Exception as e:
        print("Request failed: %s" % str(e))
        return None