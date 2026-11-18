# Security model and reports

GreyTab is a local audit application. Use it only with authorization for the target. The launcher binds its API and proxy to loopback; do not expose the control API on a network interface. Its command runner intentionally executes commands with your user's privileges.

The API rejects origins from audited web pages and DNS-rebinding hostnames; extension origins are allowed. Local native clients and other permitted extensions remain part of the trusted machine environment. This is not an authentication boundary against another local process running as your user.

The dedicated browser profile contains target cookies and credentials. The local database, macros, raw tool commands, projects and reports may contain secrets. AI features send selected evidence to the provider you configure. Local JSON configuration writes are private/atomic; protect the entire installation and its backups accordingly.

The production browser keeps its sandbox and trusts the GreyTab proxy's certificate public key for that browser process. It does not import a global CA. Rendered responses are sandboxed static previews. Uploaded wordlist names are restricted to the wordlist directory, and executable runtime downloads are verified against pinned hashes.

Please report reproducible security issues through the repository owner's GitHub contact or private security reporting when available. Include version, Linux distribution, reproduction steps and a sanitized example. Do not post live credentials or target traffic in public issues.
