"""Implements an email carrier under the general transport obligations of HIVEMIND-TRANSPORT-1 §2."""
from hivemind_email.carrier import EmailCarrier, Frame, CarrierBuffer, SMTPIMAPTransport
from hivemind_email.wormhole import EmailWormhole
from hivemind_email.bridge import EmailBridge
from hivemind_email.client import HiveMindEmailClient
from hivemind_email.version import __version__

__all__ = [
    "EmailCarrier",
    "Frame",
    "CarrierBuffer",
    "SMTPIMAPTransport",
    "EmailWormhole",
    "EmailBridge",
    "HiveMindEmailClient",
    "__version__",
]
