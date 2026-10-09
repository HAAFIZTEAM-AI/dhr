"""HAAFIZ detection core.

Subpackages
-----------
``core``        SSRF guard -- every outbound fetch goes through it.
``intel``       Threat intelligence: brand-impersonation detection and the
                federated multi-source verdict. See docs/DETECTION.md.
``scoring``     The noisy-OR ensemble that combines analyzer modules.
``verdict``     Plain-language rendering into seven languages, including the
                spoken form used by the IVR channel.
``analyzers``   Detectors too specific to live in the generic ``analyzers/``
                package (currently the digital-arrest coercion signature).

Why this package is called ``haafiz`` and not ``app``
-----------------------------------------------------
``ai-service/app.py`` is the FastAPI entrypoint. A directory called ``app/``
next to it shadows the module -- Python resolves packages before modules -- so
``import app`` returns the package, the server object disappears, and
``uvicorn app:app`` fails to boot. This is not hypothetical: the Dockerfile
shipped with ``COPY app ./app`` and ``CMD uvicorn app.main:app``, which copied a
package containing no server and then tried to import a module that did not
exist. The container could never have started.

**Do not create an ``app/`` directory in this service.**
"""
