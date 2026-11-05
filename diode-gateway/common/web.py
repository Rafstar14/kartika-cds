import os


def harden(app):
    """Header keamanan standar. UI hanya memuat script/CSS dari origin sendiri."""
    frames = os.environ.get("DIODE_FRAME_ANCESTORS", "http://127.0.0.1:8000 http://localhost:8000")

    @app.after_request
    def _headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
            f"form-action 'none'; base-uri 'none'; frame-ancestors {frames}")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp
    return app
