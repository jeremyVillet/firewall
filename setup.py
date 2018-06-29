from cx_Freeze import setup, Executable

base = None

executables = [Executable("SupFireWall.py", base=base)]

packages = []
options = {
    'build_exe': {
        'packages':packages,
    },
}

setup(
    name = "SupFireWall",
    options = options,
    version = "1.0.0",
    description = 'Firewall for window',
    executables = executables
)