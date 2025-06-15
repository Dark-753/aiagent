# AGIS-Terminus 🤖

An AI-powered terminal assistant that helps you execute commands safely using natural language.

## Features

- Natural language task processing
- Voice input support
- Multi-OS command generation (Windows/Linux/macOS)
- Command safety checks
- Detailed logging
- REST API support
- Rich CLI interface

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Dark-753/aiagent.git
cd aiagent
```

2. Set up the virtual environment:
- Windows: Run `setup.bat`
- Linux/macOS: Run `python setup_venv.py`

3. Set your API keys:
```bash
# Windows
set OPENAI_API_KEY=your_openai_key
set ANTHROPIC_API_KEY=your_anthropic_key

# Linux/macOS
export OPENAI_API_KEY=your_openai_key
export ANTHROPIC_API_KEY=your_anthropic_key
```

## Usage

### CLI Mode
```bash
python agis_terminus.py
```

### API Mode
```bash
python agis_terminus_api.py
```

Then send POST requests to `http://localhost:5000/execute-task`:
```json
{
    "task": "Install nginx and start it",
    "os": "linux"
}
```

## Project Structure

- `agis_terminus.py` - Main CLI application
- `agis_terminus_api.py` - Flask API server
- `voice_input.py` - Voice input handling
- `terminus_logger.py` - Logging system
- `setup.bat` - Windows setup script
- `setup_venv.py` - Cross-platform setup script
- `requirements.txt` - Python dependencies

## Requirements

- Python 3.8+
- OpenAI API key
- Anthropic API key (optional)
- PyAudio (for voice input)

## License

MIT License

## Author

[Dark-753](https://github.com/Dark-753) 