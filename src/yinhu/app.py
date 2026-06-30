import ctypes
import os
import sys


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def elevate() -> None:
    """Relaunch the current process with UAC prompt; exit on success."""
    params = " ".join(f'"{a}"' for a in sys.argv)
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    if ret > 32:
        sys.exit(0)


def main() -> None:
    from .ui.main_window import MainWindow

    admin = is_admin() if os.name == "nt" else True
    app = MainWindow(is_admin=admin, on_elevate=elevate)
    app.mainloop()


if __name__ == "__main__":
    main()
