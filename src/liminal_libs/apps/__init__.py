"""The apps' frame (liminal-libs 1.7.0; the user, 2026-11-04: "define all this stuff in liminal
libs ... the library basically facilitates the interprocess communication, the way the apps can
bind to each other, or interoperate, or seamlessly connect ... As well as the framework for the
graphics"): `App` (an app's page, tray and routes served at its own port: app.py), `Tray` and
`TrayItem` (its icons: tray.py), `LoginClient` (what any program asks the login app: login.py).
What is particular to one app (its users, its views) stays in that app's package."""
from .app import App, Refused, attach_registry, make_handler  # noqa: F401
from .authorization import EnvironmentLogin, Login, Unauthorized, pair_name, saved_variables, variable_name  # noqa: F401
from .binding import FORWARDED, PASSED_BACK, START_SECONDS, Binding, forward, start_app, tray_of, wait_for  # noqa: F401
from .login import (DEFAULT_URL, PAIRS_PATH, SESSION_HEADER, SUPER_TITLE_VAR, SUPER_URL_VAR, SUPER_VAR, URL_VAR,  # noqa: F401
                    LoginClient, LoginRefused, LoginUnreachable, inherited_by, pairs_wanted)
from .scope import CFG_VAR, FILE_NAME, REMOTES_VAR, Scope, remote_url, remotes_from  # noqa: F401
from .traffic import CLASSES, RecordingLogin, Traffic, node_of, program_name  # noqa: F401
from .tray import Tray, TrayItem  # noqa: F401
