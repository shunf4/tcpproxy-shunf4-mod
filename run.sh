#!/bin/bash
set -eo pipefail

DIR=$( cd "$(dirname "$0")"; pwd -P )
cd "$DIR"

if [ -f "$DIR"/env.source ]; then
	source "$DIR"/env.source
fi

		
if ! ( [ "$PORT" -gt 0 ] 2>/dev/null && [ "$PORT" -lt 65536 ] 2>/dev/null ) ; then
	PORT=1091
fi

if [ -z "$CA_PEM" ]; then
	CA_PEM="c:/path/to/ca.pem"
fi

if [ -z "$CA_KEY_PEM" ]; then
	CA_KEY_PEM="c:/path/to/ca_key.pem"
fi

if [ -z "$LOG_DIR" ]; then
	LOG_DIR="c:/path/to/log/dir/"
else
	mkdir -p "$LOG_DIR"
fi

if [ -z "$PYTHON_BIN" ]; then
	PYTHON_BIN="python3"
fi

FLAG_SHOULD_DECRYPT_TLS=''
if [ "$SHOULD_DECRYPT_TLS" = "1" ]; then
	FLAG_SHOULD_DECRYPT_TLS=' -s'
fi

OTHER_ARGS="${OTHER_ARGS-"-pi 127.0.0.1 -pp 27082 -pt SOCKS5"}"

"$PYTHON_BIN" -u "$DIR"/tcpproxy.py -s5 -lp "$PORT" ${OTHER_ARGS} -ac "$CA_PEM" -ak "$CA_KEY_PEM" ${FLAG_SHOULD_DECRYPT_TLS} -v -im "textdump:logdir=\"$LOG_DIR\",hexdump:wsdirection=1:logdir=\"$LOG_DIR\"" -om "textdump:logdir=\"$LOG_DIR\",hexdump:wsdirection=1:logdir=\"$LOG_DIR\"" "$@"

