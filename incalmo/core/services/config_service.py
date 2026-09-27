import os
import json
from config.attacker_config import AttackerConfig

CONFIG_PATH = "./config/config.json"


class ConfigService:
    def __init__(self):
        self.config = self.load_config()

    def load_config(self):
        # Check if config.json exists
        if not os.path.exists(CONFIG_PATH):
            raise FileNotFoundError("config.json not found")

        # Load config.json
        with open(CONFIG_PATH, "r") as f:
            config = f.read()
            json_config = json.loads(config)

        c2c_server_override = os.environ.get("C2C_SERVER")
        if c2c_server_override:
            json_config["c2c_server"] = c2c_server_override

        # Victim-reachable C2 URL for target-side downloads. Env override wins; otherwise fall
        # back to c2c_server so existing single-address setups behave exactly as before.
        agent_override = os.environ.get("C2C_SERVER_AGENTS")
        if agent_override:
            json_config["agent_c2c_server"] = agent_override
        if not json_config.get("agent_c2c_server"):
            json_config["agent_c2c_server"] = json_config.get("c2c_server")

        return AttackerConfig(**json_config)

    def get_config(self):
        return self.config
