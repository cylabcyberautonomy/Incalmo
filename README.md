
# Incalmo: An Autonomous LLM-assisted System for Red Teaming Multi-Host Networks

<div align="center">

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
![GitHub issues](https://img.shields.io/github/issues/bsinger98/Incalmo?style=flat-square)
![GitHub pull requests](https://img.shields.io/github/issues-pr/bsinger98/Incalmo?style=flat-square)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/bsinger98/Incalmo?style=flat-square)
![GitHub contributors](https://img.shields.io/github/contributors/bsinger98/Incalmo?style=flat-square)
![GitHub stars](https://img.shields.io/github/stars/bsinger98/Incalmo?style=flat-square)
![GitHub forks](https://img.shields.io/github/forks/bsinger98/Incalmo?style=flat-square)

Incalmo is an autonomous AI-driven network penetration testing tool that automatically conducts intelligent red-teaming activities with the aim to enhance and assist operator abilities when performing complex network attack tasks.

**Research Paper**: [On the Feasibility of Using LLMs to Execute Multistage Network Attacks](https://arxiv.org/abs/2501.16466)

**Website**: Visit our [website](https://www.incalmo.ai/) for more information! 
</div>

---


## Table Of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)
- [Support](#support)

## Prerequisites

- **[Docker Desktop](https://www.docker.com/)** - Required for containerized environment
- **[Python 3.13+](https://www.python.org/downloads/)** - Required for local development
- **[uv](https://github.com/astral-sh/uv)** - Fast Python package installer (recommended) or pip
- **LLM API Keys** - At least one of the following:
  - [OpenAI API Key](https://platform.openai.com/api-keys) - For GPT models
  - [Anthropic API Key](https://console.anthropic.com/) - For Claude models
  - [Google API Key](https://makersuite.google.com/app/apikey) - For Gemini models
  - [DeepSeek API Key](https://platform.deepseek.com/) - For DeepSeek models
- **[Node.js](https://nodejs.org/en)** (Optional) - Only needed for [UI Interface](#ui-interface-optional)
## Installation

#### 1. Setup configuration

Create a configuration file by copying the example:

```bash
cp config/config_example.json config/config.json
```

Then edit `config/config.json` as needed.

#### 2. Set API Keys

Create an environment file by copying the example:

```bash
cp .env.example .env
```

Then add LLM API keys to `.env`.

#### 3. Start the Development Environment

Navigate to the docker directory and start the containers:

```bash
cd docker
docker compose up
```

> **MHBench Integration**
>
> Before starting the containers, set the `MODE` environment variable to `"remote"` in both `docker/docker-compose.attacker.yml` and `docker/docker-compose.yml`.
>
> Before Step 4, compile and set up the MHBench environment for your experiment. Ensure `config.json` has the C2 server configured as:
> ```json
> "c2c_server": "http://localhost:8888"
> ```

#### 4. Run Incalmo

In a new terminal window, attach to the running container and execute Incalmo:

   ```bash
   cd docker
   docker compose exec attacker /bin/bash
   uv run main.py
   ```

### UI Interface (optional)

If you want to use the web-based interface for Incalmo:

#### 1. Start Backend

Follow Steps 1 through 3 in the [installation instructions](#installation).

#### 2. Install Node.js dependencies

Install Node dependencies:

   ```bash
   cd incalmo/frontend/incalmo-ui
   npm install
   ```

#### 3. Start the React Server

Once dependencies are installed, run the react server:

   ```bash
   npm start
   ```

This will lauch the frontend at [http://localhost:3000](http://localhost:3000)

## Usage

Note: A "strategy" is the logic behind an attack. See the [strategies/](incalmo/core/strategies) folder for examples of llm based attacks and state machine based attacks.

To use an your choice of an LLM-based attack:

- Follow the [setup](#installation) and then:

- Specify in ```config/config.json``` what LLMs to use (list is available in the [registry](incalmo/core/strategies/llm/langchain_registry.py)). Use the ```config_example.json``` as a template

  The optional top-level `attacker_briefing` string adds authored starting knowledge to the initial prompt. It supplements the existing mission and action instructions without adding hosts or access permissions. Omit it to keep the existing prompt.

- Run ```main.py``` as described in the setup

- Observe the status of the attack through the logs in the output directory. Your attack will be timestamped and used to name the logs folder

This is the most stable way to test attack.

Incalmo also supports creating non-LLM state-machine strategies. To use a custom (non-LLM/manual) strategy for attacks:

-  Follow the [setup](#installation) and then:

- Specify in ```config/config.json``` what manual strategy to use (list is available in [strategies/state_machine](incalmo/core/strategies/state_machine)). Use the ```config_example_state_machine.json``` as a template and fill in the strategy name as the class name.

- Run ```main.py``` as described in the setup

- Observe the status of the attack through the logs in the output directory. Your attack will be timestamped and used to name the logs folder

- To create your own basic strategy, create a file in [strategies/state_machine](incalmo/core/strategies/state_machine) as follows:

```
class YourStrategyName(IncalmoStrategy):
    async def step(self) -> bool:
    # Your attack/strategy logic
```
It may be easier to look at examples of existing strategies to understand formatting and strategy abilities

To use the UI:

- Instead of running ```main.py```, launch the frontend and use the UI to start and stop attacks and observe logs. This is the cleanest/easiest way to observe the attacks in real time 
    
## Tech Stack

**Backend:** Python 3.13, Flask, Celery, SQLite \
**LLM Integration:** LangChain, OpenAI, Anthropic, Google Gemini, DeepSeek \
**Frontend:** React, TypeScript, Node.js \
**Containerization:** Docker, Docker Compose \
**Package Management:** uv 

## Project Structure

```
Incalmo/
├── .env.example               # Template for environment configuration
├── CITATION.cff               # Research paper citation metadata
├── LICENSE                    # MIT License
├── main.py                    # CLI entry point - runs Incalmo strategy
├── README.md                  # Project Guide
├── config/                    # Configuration management
├── docker/                    # Docker containerization
│   ├── attacker/              # Attacker container configuration
│   └── equifax/               # Target environment (Equifax breach simulation)
│       ├── database/          # Database server container
│       └── webserver/         # Web server container
├── incalmo/                   # Core application code
│   ├── incalmo_runner.py      # Main strategy execution runner
│   ├── server.py              # Flask server entry point
│   ├── api/                   # Client API for C2 server communication
│   ├── c2server/              # Command & Control server
│   │   ├── agents/            # Agent implementations
│   │   ├── celery/            # Async task queue
│   │   ├── payloads/          # Exploit and deployment payloads
│   │   └── routes/            # Flask blueprints for API endpoints
│   ├── core/                  # Core attack framework
│   │   ├── actions/           # Action classes 
│   │   │   ├── EmptyServiceActions/   # Placeholder actions
│   │   │   ├── HighLevel/         # High-level actions
│   │   │   │   └── llm_agents/        # LLM-agent action implementations
│   │   │   └── LowLevel/          # Low-level commands
│   │   │       └── privledge_escalation/      # Privilege escalation exploits
│   │   ├── models/            # Core domain models
│   │   │   ├── events/        # Event system for state updates
│   │   │   └── network/       # Network infrastructure models
│   │   ├── services/          # Core logic services
│   │   └── strategies/        # Attack strategies
│   │       ├── llm/               # LLM-based strategies
│   │       ├── state_machine/     # Rule-based strategies
│   │       ├── testers/           # Strategy testing utilities
│   │       └── util/              # Strategy utilities
│   ├── frontend/              # Web interface
│   │   └── incalmo-ui/        # React-based UI
│   └── models/                # Shared data models (Pydantic)
└── output/                    # Execution logs and results

```

## Contributing

Contributions are always welcome! Please raise issues or make PR's if you have ideas on how to improve this project


## License

This project is licensed under the [MIT](LICENSE) License
## Acknowledgements

To cite this project or paper, check out the [Citation](CITATION.cff) specifications


## Support

For support, email hello@incalmo.ai

