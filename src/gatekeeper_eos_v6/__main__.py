"""Allow `python -m gatekeeper_eos_v6` to run the factory CLI."""

from gatekeeper_eos_v6.factory import main
import sys

sys.exit(main())
