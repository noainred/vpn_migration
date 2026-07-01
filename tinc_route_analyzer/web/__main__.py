"""Enable ``python -m tinc_route_analyzer.web``."""

from .server import main

if __name__ == "__main__":
    raise SystemExit(main())
