# Extra CA certificates for the Docker image

Put PEM certificates with the extension `.crt` here (one per file) before you run `docker build`.
They are added to the image's system trust store and used by pip during the build, and at run time by `requests` and the aiguard core.

Typical use: the Check Point gateway's HTTPS Inspection **outbound CA**, when the machine that builds or runs the image sits behind that gateway.
Without it, `pip install` in the build fails with a certificate error, because the gateway re-signs pypi.org and download.pytorch.org.

Only public CA certificates belong here. Never put private keys here (`*.key`, `*.pem`, `*.p12`, `*.pfx` are excluded from the image and from git).
This folder's `*.crt` files are ignored by git, so a lab CA is never committed.
