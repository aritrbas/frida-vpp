#!/usr/bin/env bash
# run_tests.sh — Set up VCL configs and run all 4 frida-vpp tests
#
# Usage:
#   ./run_tests.sh              # run all tests sequentially
#   ./run_tests.sh echo         # run echo (TCP) test only
#   ./run_tests.sh http         # run HTTP test only
#   ./run_tests.sh setup        # only create VCL configs, don't run tests
#
# Requirements:
#   - VPP running with:  session { enable use-app-socket-api }
#   - LD_LIBRARY_PATH pointing at the VPP lib dir (or set VPP_LIB below)
#   - Frida installed:   pip3 install frida frida-tools

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTERCEPTOR="$SCRIPT_DIR/../interceptor.js"

VPP_LIB="${VPP_LIB:-/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu}"
VPP_APP_SOCKET="${VPP_APP_SOCKET:-/run/vpp/app_ns_sockets/default}"

SERVER_VCL_DIR="/tmp/server-share"
CLIENT_VCL_DIR="/tmp/client-share"
SERVER_VCL="$SERVER_VCL_DIR/vcl.conf"
CLIENT_VCL="$CLIENT_VCL_DIR/vcl.conf"

ECHO_PORT="${ECHO_PORT:-9876}"
HTTP_PORT="${HTTP_PORT:-8080}"

FRIDA_WAIT_SECS=15   # seconds to wait for server to become ready
LOG_DIR="/tmp"

# ── Colours ───────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

# ── Step 1: Create VCL configs ────────────────────────────────────────────────

setup_vcl_configs() {
    info "Creating VCL config files..."
    mkdir -p "$SERVER_VCL_DIR" "$CLIENT_VCL_DIR"

    cat > "$SERVER_VCL" <<EOF
vcl {
  rx-fifo-size 4000000
  tx-fifo-size 4000000
  app-scope-local
  app-scope-global
  use-mq-eventfd
  app-socket-api $VPP_APP_SOCKET
}
EOF

    cp "$SERVER_VCL" "$CLIENT_VCL"

    info "  Server VCL: $SERVER_VCL"
    info "  Client VCL: $CLIENT_VCL"
}

# ── Preflight checks ──────────────────────────────────────────────────────────

preflight() {
    local ok=1

    if ! pgrep -f '/bin/vpp' >/dev/null 2>&1; then
        warn "VPP does not appear to be running (no vpp process found)."
        warn "Start it with:  sudo vpp 'unix { nodaemon cli-listen /run/vpp/cli.sock } session { enable use-app-socket-api }'"
        ok=0
    fi

    if [[ ! -S "$VPP_APP_SOCKET" ]]; then
        warn "VPP app socket not found: $VPP_APP_SOCKET"
        ok=0
    fi

    if ! command -v frida >/dev/null 2>&1; then
        warn "frida not found in PATH. Install with:  pip3 install frida frida-tools"
        ok=0
    fi

    if [[ ! -f "$INTERCEPTOR" ]]; then
        warn "interceptor.js not found at: $INTERCEPTOR"
        ok=0
    fi

    if [[ $ok -eq 0 ]]; then
        echo ""
        fail "One or more preflight checks failed. Aborting."
        exit 1
    fi
}

# ── Generic server/client runner ──────────────────────────────────────────────

# run_server <name> <binary> <log> [extra_args...]
run_server() {
    local name="$1" binary="$2" log="$3"
    shift 3

    info "Starting $name server (log: $log)..."

    LD_LIBRARY_PATH="$VPP_LIB" \
    VCL_CONFIG="$SERVER_VCL" \
    frida -f "$binary" -l "$INTERCEPTOR" "$@" </dev/null >"$log" 2>&1 &

    echo $!
}

# wait_for_listen <log> <ready_pattern> <timeout_secs>
wait_for_listen() {
    local log="$1" pattern="$2" timeout="$3"
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if grep -q "$pattern" "$log" 2>/dev/null; then
            return 0
        fi
        sleep 1
        (( elapsed++ )) || true
    done
    return 1
}

# run_client <name> <binary> <log> [extra_args...]  → returns frida exit code
run_client() {
    local name="$1" binary="$2" log="$3"
    shift 3

    info "Running $name client (log: $log)..."

    LD_LIBRARY_PATH="$VPP_LIB" \
    VCL_CONFIG="$CLIENT_VCL" \
    frida -f "$binary" -l "$INTERCEPTOR" "$@" </dev/null >"$log" 2>&1 || true
}

# ── Test: Echo (TCP) ──────────────────────────────────────────────────────────

run_echo_test() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "TEST 1: Echo (TCP) — port $ECHO_PORT"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local server_log="$LOG_DIR/echo_server.log"
    local client_log="$LOG_DIR/echo_client.log"
    local server_pid

    server_pid=$(run_server "echo" "$SCRIPT_DIR/echo_server" "$server_log")

    if ! wait_for_listen "$server_log" "Listening" "$FRIDA_WAIT_SECS"; then
        fail "Echo server did not become ready within ${FRIDA_WAIT_SECS}s"
        kill "$server_pid" 2>/dev/null || true
        return 1
    fi
    pass "Echo server listening"
    # frida exits when stdin hits EOF; resolve the actual binary PID for liveness checks
    local actual_pid
    actual_pid=$(pgrep -f "$SCRIPT_DIR/echo_server" 2>/dev/null | head -1)
    [[ -n "$actual_pid" ]] && server_pid="$actual_pid"

    run_client "echo" "$SCRIPT_DIR/echo_client" "$client_log" \
        -- "127.0.0.1:${ECHO_PORT}" "hello frida-vpp"

    # Validate
    local result=0
    if grep -q "\[client\] Echo: hello frida-vpp" "$client_log"; then
        pass "Echo client: got correct echo response"
    else
        fail "Echo client: expected '[client] Echo: hello frida-vpp' not found"
        result=1
    fi

    if grep -q "\[client\] Done\." "$client_log"; then
        pass "Echo client: completed cleanly"
    else
        fail "Echo client: '[client] Done.' not found — possible hang or crash"
        result=1
    fi

    # Check server still alive
    sleep 2
    if kill -0 "$server_pid" 2>/dev/null; then
        pass "Echo server: still running after connection (no crash)"
    else
        fail "Echo server: exited unexpectedly"
        result=1
    fi

    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true

    echo ""
    if [[ $result -eq 0 ]]; then
        pass "Echo (TCP) test: ALL CHECKS PASSED"
    else
        fail "Echo (TCP) test: SOME CHECKS FAILED (see $client_log / $server_log)"
    fi
    return $result
}

# ── Test: HTTP ────────────────────────────────────────────────────────────────

run_http_test() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "TEST 2: HTTP — port $HTTP_PORT"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local server_log="$LOG_DIR/http_server.log"
    local client_root_log="$LOG_DIR/http_client_root.log"
    local client_health_log="$LOG_DIR/http_client_health.log"
    local server_pid

    server_pid=$(run_server "HTTP" "$SCRIPT_DIR/http_server" "$server_log" \
        -- "$HTTP_PORT")

    if ! wait_for_listen "$server_log" "Listening" "$FRIDA_WAIT_SECS"; then
        fail "HTTP server did not become ready within ${FRIDA_WAIT_SECS}s"
        kill "$server_pid" 2>/dev/null || true
        return 1
    fi
    pass "HTTP server listening on port $HTTP_PORT"
    # frida exits when stdin hits EOF; resolve the actual binary PID for liveness checks
    local actual_pid
    actual_pid=$(pgrep -f "$SCRIPT_DIR/http_server" 2>/dev/null | head -1)
    [[ -n "$actual_pid" ]] && server_pid="$actual_pid"

    # Request 1: GET /
    run_client "HTTP(GET /)" "$SCRIPT_DIR/http_client" "$client_root_log" \
        -- "127.0.0.1:${HTTP_PORT}" /

    # Request 2: GET /health
    run_client "HTTP(GET /health)" "$SCRIPT_DIR/http_client" "$client_health_log" \
        -- "127.0.0.1:${HTTP_PORT}" /health

    # Validate
    local result=0

    if grep -q "PASS: got HTTP 200 OK" "$client_root_log"; then
        pass "HTTP GET /: 200 OK"
    else
        fail "HTTP GET /: expected '200 OK' not found"
        result=1
    fi

    if grep -q "PASS: got HTTP 200 OK" "$client_health_log"; then
        pass "HTTP GET /health: 200 OK"
    else
        fail "HTTP GET /health: expected '200 OK' not found"
        result=1
    fi

    # Check server handled both requests
    local req_count
    req_count=$(grep -c "http_server.*GET" "$server_log" 2>/dev/null || echo 0)
    if [[ $req_count -ge 2 ]]; then
        pass "HTTP server: handled $req_count requests"
    else
        warn "HTTP server: only $req_count request(s) logged (expected 2)"
    fi

    # Check server still alive
    sleep 2
    if kill -0 "$server_pid" 2>/dev/null; then
        pass "HTTP server: still running after requests (no crash)"
    else
        fail "HTTP server: exited unexpectedly"
        result=1
    fi

    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true

    echo ""
    if [[ $result -eq 0 ]]; then
        pass "HTTP test: ALL CHECKS PASSED"
    else
        fail "HTTP test: SOME CHECKS FAILED (see logs in $LOG_DIR/)"
    fi
    return $result
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    local mode="${1:-all}"

    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║     frida-vpp test runner                ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    info "VPP lib:        $VPP_LIB"
    info "App socket:     $VPP_APP_SOCKET"
    info "interceptor.js: $INTERCEPTOR"
    info "Logs:           $LOG_DIR/"
    echo ""

    setup_vcl_configs

    if [[ "$mode" == "setup" ]]; then
        pass "VCL configs created. Done."
        exit 0
    fi

    preflight

    local overall=0

    case "$mode" in
        echo)
            run_echo_test || overall=1
            ;;
        http)
            run_http_test || overall=1
            ;;
        all)
            run_echo_test || overall=1
            # Give VPP a moment between tests
            sleep 3
            run_http_test || overall=1
            ;;
        *)
            echo "Usage: $0 [all|echo|http|setup]"
            exit 1
            ;;
    esac

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [[ $overall -eq 0 ]]; then
        pass "All tests passed."
    else
        fail "One or more tests failed. Check logs in $LOG_DIR/."
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit $overall
}

main "${1:-all}"
