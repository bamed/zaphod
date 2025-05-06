#@author
#@category ZAPHOD
#@keybinding ctrl shift C
#@menupath Tools.ZAPHOD.Configure API
#@toolbar

from javax.swing import JOptionPane
from zaphod_config import ZaphodConfig

def run():
    try:
        current_config = ZaphodConfig.load_config()
        
        api_endpoint = JOptionPane.showInputDialog(
            None,
            "Enter Zaphod API endpoint:",
            current_config['api_endpoint']
        )
        
        if api_endpoint is None:
            return
            
        api_key = JOptionPane.showInputDialog(
            None,
            "Enter Zaphod API key:",
            current_config['api_key']
        )
        
        if api_key is None:
            return
        
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