#!/bin/sh
# One command to build (if needed) and run the log analyser.
# Usage: ./analyse.sh <logfile> [options]

DIR="$(cd "$(dirname "$0")" && pwd)"

# Compile when there is no build yet, or a .java file changed since the last build.
if [ ! -f "$DIR/out/.built" ] || [ -n "$(find "$DIR/src" -name '*.java' -newer "$DIR/out/.built")" ]; then
    echo "Compiling..."
    mkdir -p "$DIR/out"
    javac -d "$DIR/out" "$DIR"/src/loganalyser/*.java || exit 1
    touch "$DIR/out/.built"
fi

exec java -cp "$DIR/out" loganalyser.Main "$@"
