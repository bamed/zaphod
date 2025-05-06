import json
import os
from java.net import URL
from java.io import File, FileWriter, BufferedReader, InputStreamReader
from javax.swing import JOptionPane
from java.util import HashMap

class ZaphodConfig:
    CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".ghidra", "zaphod_config.json")
    DEFAULT_CONFIG = {
        "api_endpoint": "http://localhost:8000",
        "api_key": ""
    }
    
    @classmethod
    def ensure_config_dir(cls):
        """Ensures the config directory exists."""
        config_dir = os.path.dirname(cls.CONFIG_FILE)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
    
    @classmethod
    def load_config(cls):
        """Loads configuration from file or returns default."""
        try:
            cls.ensure_config_dir()
            if os.path.exists(cls.CONFIG_FILE):
                with open(cls.CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Ensure all required fields exist
                    return dict(cls.DEFAULT_CONFIG, **config)
        except Exception as e:
            print("Warning: Could not load config: %s" % str(e))
        
        return dict(cls.DEFAULT_CONFIG)
    
    @classmethod
    def update_config(cls, api_endpoint, api_key):
        """Updates the configuration file."""
        try:
            cls.ensure_config_dir()
            config = {
                "api_endpoint": api_endpoint.rstrip("/"),  # Remove trailing slash
                "api_key": api_key
            }
            
            with open(cls.CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            return True
            
        except Exception as e:
            print("Error saving config: %s" % str(e))
            return False

def make_api_request(endpoint, payload):
    """Makes a request to the Zaphod API with the configured settings."""
    try:
        config = ZaphodConfig.load_config()
        full_url = "%s%s" % (config["api_endpoint"], endpoint)
        
        # Create connection
        url = URL(full_url)
        conn = url.openConnection()
        conn.setDoOutput(True)
        conn.setRequestMethod("POST")
        
        # Set headers
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("X-API-Key", config["api_key"])
        
        # Send request
        if payload:
            payload_json = json.dumps(payload)
            conn.getOutputStream().write(payload_json.encode('utf-8'))
        
        # Read response
        if conn.getResponseCode() == 200:
            reader = BufferedReader(InputStreamReader(conn.getInputStream()))
            response = ""
            line = reader.readLine()
            while line:
                response += line
                line = reader.readLine()
            reader.close()
            
            return json.loads(response)
        else:
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

# Configure Zaphod API endpoint and key
# @category: Zaphod
# @toolbar 
#@author
#@category ZAPHOD
#@keybinding
#@menupath Tools.ZAPHOD.Configure API
#@toolbar

from zaphod_config import ZaphodConfig
from javax.swing import JOptionPane

def run():
    """Run the configuration dialog."""
    try:
        current_config = ZaphodConfig.load_config()
        
        # Get API endpoint
        api_endpoint = JOptionPane.showInputDialog(
            None,
            "Enter Zaphod API endpoint:",
            current_config['api_endpoint']
        )
        
        if api_endpoint is None:
            return
            
        # Get API key
        api_key = JOptionPane.showInputDialog(
            None,
            "Enter Zaphod API key:",
            current_config['api_key']
        )
        
        if api_key is None:
            return
        
        # Save configuration
        if ZaphodConfig.update_config(api_endpoint, api_key):
            print("Configuration saved successfully!")
            print("API Endpoint: %s" % api_endpoint)
            print("API Key: %s" % ('*' * len(api_key)))
        else:
            print("Failed to save configuration!")

    except Exception as e:
        print("Error configuring Zaphod: %s" % e)

if __name__ == '__main__':
    run()