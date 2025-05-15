import ssl
import socket
from datetime import datetime

def get_ssl_certificate_info(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "valid_from": cert.get("notBefore"),
                    "valid_until": cert.get("notAfter"),
                    "serial_number": cert.get("serialNumber"),
                }
    except Exception as e:
        return {"error": str(e)}