from .._json import error_envelope

NO_TOKEN = error_envelope(
    "not_configured",
    "No Webroot credentials. Send the X-Webroot-Username, X-Webroot-Password, "
    "X-Webroot-Client-Id, X-Webroot-Client-Secret, and X-Webroot-Parent-Keycode headers.",
    False,
)
