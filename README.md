# Automated Web Security Header Scanner

Student: Omkar  
Institution: Sandip University  
Topic: Automated Web Scanner (security headers and a limited CORS response review)

## Description
This educational project sends one HTTP GET request to one user-selected URL and reviews selected response headers. It does not crawl, submit forms, scan ports, fuzz inputs, or attempt exploitation. Use only a site you own or are explicitly authorized to assess. Missing headers are review prompts, not proof of a vulnerability.

## Technologies
- Python 3.10 or later
- Python standard library for the scanner
- JupyterLab and IPython kernel for the notebook

## Files
- Omkar_AutomatedWebScanner.py: standalone command-line scanner
- Omkar_AutomatedWebScanner.ipynb: explanation and synthetic, offline example
- Omkar_ProjectReport.docx: project documentation and evidence checklist
- requirements.txt: notebook environment dependencies; scanner has no third-party runtime dependency

## Setup and run
1. Install Python 3.10 or later.
2. Install notebook tools with python -m pip install -r requirements.txt.
3. Run python Omkar_AutomatedWebScanner.py and enter one URL, or provide it as an argument.
4. Type YES only after confirming ownership or permission. Otherwise no request is sent.
5. For the notebook, run jupyter lab and open the notebook.

## Evidence
For a permitted target, capture the URL, permission confirmation, UTC timestamp, HTTP status, and findings. Remove cookies, tokens, private hostnames, and personal data. If using the notebook's synthetic example, label it as a demonstration and not a live scan.

## Limitations
The scanner reviews one response and does not follow redirects. If a redirect is returned, review its destination manually and scan it only if authorized. CORS is only a preliminary observation: it does not send an Origin header or test browser behavior. Header suitability depends on the application. This is not a penetration test, compliance audit, or proof of security.

## References
- OWASP Secure Headers Project: https://owasp.org/projects/secure-headers-project/
- MDN CORS guide: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS
- MDN CORS security guidance: https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/CORS
- MDN Strict-Transport-Security: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
- MDN Referrer-Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
