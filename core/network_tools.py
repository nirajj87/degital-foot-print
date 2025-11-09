import socket, ssl, logging, dns.resolver, whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def whois_lookup(domain):
    try:
        return dict(whois.whois(domain))
    except Exception as e:
        logging.debug(f"whois failed: {e}")
        return {"error": str(e)}

def dns_lookup(domain):
    out = {}
    for rtype in ["A","MX","NS","TXT"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            out[rtype] = [r.to_text() for r in answers]
        except Exception as e:
            out[rtype] = f"error: {e}"
    return out

def fetch_ssl(domain, port=443, timeout=6):
    info = {"error": None, "parsed": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
                pem = ssl.DER_cert_to_PEM_cert(der)
                info["pem"] = pem
                try:
                    cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
                    info["parsed"] = {
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "not_before": str(cert.not_valid_before),
                        "not_after": str(cert.not_valid_after),
                    }
                except Exception as e:
                    info["parsed_error"] = str(e)
    except Exception as e:
        info["error"] = str(e)
    return info