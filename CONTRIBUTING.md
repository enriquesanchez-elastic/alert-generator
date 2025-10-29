# Contributing to Alerts Generator

Thank you for your interest in contributing to Alerts Generator!

## Development Setup

1. **Clone the repository** (if contributing externally):
   ```bash
   git clone https://github.com/enriquesanchez-elastic/alert-generator
   cd alert-generator
   ```

2. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -e ".[dev]"  # Install with dev dependencies
   ```

## Code Structure

The project follows a modular architecture:

```
alerts_generator/
├── config/          # Configuration management
├── models/          # Data models (Campaign, Scenario, Alert)
├── generators/      # Alert and event generators
├── indexers/        # Storage backends (Elasticsearch)
├── time_distribution/  # Time distribution strategies
├── utils/           # Utilities (logging, etc.)
├── core.py          # Main orchestration
└── cli.py           # Command-line interface
```

## Adding New Features

### Adding a New Generator

1. Create a new generator class in `alerts_generator/generators/`
2. Inherit from `BaseGenerator` or `ScenarioBasedGenerator` if appropriate
3. Implement required methods
4. Register the generator in `alerts_generator/generators/__init__.py`

### Adding a New Time Distribution Strategy

1. Create a new strategy class in `alerts_generator/time_distribution/strategies.py`
2. Inherit from `TimeDistributionStrategy`
3. Implement `calculate_offset()` method
4. Add the strategy to `get_strategy()` function

### Adding a New Indexer (Backend)

1. Create a new indexer class in `alerts_generator/indexers/`
2. Inherit from `BaseIndexer`
3. Implement `index_alert()`, `index_events()`, and `delete_all()` methods
4. Register in `alerts_generator/indexers/__init__.py`

### Adding Custom Scenarios

Create a YAML file following the format in `example_custom_scenarios.yaml`:

```yaml
scenarios:
  - name: "Your Attack Name"
    description: "Description of the attack"
    severity: "high"  # low, medium, high, or critical
    processes:
      - name: "process1"
        executable: "/path/to/executable"
        args: ["arg1", "arg2"]
        working_dir: "/working/directory"
        user: "username"
      # ... more processes
    malware_file:
      name: "malware.exe"
      path: "/path/to/malware.exe"
      extension: ".exe"
```

## Code Style

- Follow PEP 8 style guide
- Use type hints for all function signatures
- Add docstrings following Google style
- Line length: 100 characters (configured in `pyproject.toml`)
- Run `black` for formatting: `black alerts_generator/`
- Run `ruff` for linting: `ruff check alerts_generator/`

## Testing

1. **Run tests**:
   ```bash
   pytest
   ```

2. **Run with coverage**:
   ```bash
   pytest --cov=alerts_generator --cov-report=html
   ```

3. **Run specific test**:
   ```bash
   pytest tests/test_generators/test_alert.py
   ```

## Submitting Changes

1. **Create a branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and test them

3. **Commit with descriptive messages**:
   ```bash
   git commit -m "Add feature: description of what you added"
   ```

4. **Push and create a pull request**

## Documentation

- Update docstrings when adding new functions/classes
- Update README.md if adding new features or changing usage
- Keep examples up-to-date

## Questions?

If you have questions, please open an issue for discussion.
