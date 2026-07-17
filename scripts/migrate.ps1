# PowerShell wrapper for database migrations script.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

# Find the virtual environment python if it exists
if (Test-Path "$RootDir\.venv\Scripts\python.exe") {
    $PythonExec = "$RootDir\.venv\Scripts\python.exe"
} elseif (Test-Path "$RootDir\venv\Scripts\python.exe") {
    $PythonExec = "$RootDir\venv\Scripts\python.exe"
} else {
    $PythonExec = "python"
}

# Run migration script
& $PythonExec "$RootDir\migrate.py" $args
