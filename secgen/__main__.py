"""Entry point for running secgen as a module.

Usage:
    python -m secgen --help
    python -m secgen --count 20 --index-all
    python -m secgen world create --hosts 50 --users 100
"""

from secgen.cli import main

if __name__ == "__main__":
    main()
