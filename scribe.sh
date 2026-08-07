#!/usr/bin/env sh
set -eu

chmd="data/syscalls.chmd"

# =========
# extract
# =========

log() { echo "[chimera] $*" >&2; }

extract_args() {
    name="$1"
    rn="$2"

    log "extract_args: $name"
    man 2 "$name" 2>/dev/null | col -b |
    awk -v name="$name" '
    NR == FNR && /^[^-#]/ {
        split($0, a, "=")
        R[a[1]] = a[2]
        next
    }

    function ren(n) {
        if (n in R) return R[n]
        return n
    }

    function is_section_header(s) { return s ~ /^[A-Z]/ && s !~ /^[[:space:]]/ }
    function is_include(s)         { return s ~ /^[[:space:]]*#/ }
    function is_blank(s)           { return s ~ /^[[:space:]]*$/ }
    function is_comment_line(s)    { return s ~ /^[[:space:]]*\/\*/ }

    function paren_depth(s) {
        d = 0
        for (i = 1; i <= length(s); i++) {
            c = substr(s, i, 1)
            if (c == "(") d++
            if (c == ")") d--
        }
        return d
    }

    function extract_proto_params(proto) {
        if (match(proto, "\\<" name "[[:space:]]*\\(")) {
            remaining = substr(proto, RSTART + RLENGTH)
            depth = 1; params = ""
            for (i = 1; i <= length(remaining) && depth > 0; i++) {
                c = substr(remaining, i, 1)
                if (c == "(") depth++
                if (c == ")") depth--
                if (depth > 0) params = params c
            }
            return params
        }

        if (match(proto, "syscall[[:space:]]*\\([[:space:]]*SYS_" name "[[:space:]]*,")) {
            remaining = substr(proto, RSTART + RLENGTH)
            depth = 1; params = ""
            for (i = 1; i <= length(remaining) && depth > 0; i++) {
                c = substr(remaining, i, 1)
                if (c == "(") depth++
                if (c == ")") depth--
                if (depth > 0) params = params c
            }
            return params
        }

        return ""
    }

    function parse_params(p) {
        if (p == "") return ""

        if (index(p, ";")) { n = split(p, s, ";"); p = s[n] }
        gsub(/\[[^]]*\]/, "", p)

        result = ""
        n = split(p, arr, ",")

        for (i = 1; i <= n; i++) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", arr[i])
            if (arr[i] == "" || arr[i] == "...") continue

            last = ""; tmp = arr[i]
            while (match(tmp, /[a-zA-Z_][a-zA-Z0-9_]*/)) {
                last = substr(tmp, RSTART, RLENGTH)
                tmp = substr(tmp, RSTART + RLENGTH)
            }
            if (last == "" || last == "void") continue

            last = ren(last)

            if (result != "") result = result ","
            result = result last
        }

        return result
    }

    /^[A-Z]/ && !/^[[:space:]]/ { section = $1; next }

    section == "SYNOPSIS" {
        if (is_include($0) || is_blank($0)) {
            if (in_proto && proto != "") {
                depth = paren_depth(proto)
                if (depth <= 0 && proto ~ /\(/) {
                    params = extract_proto_params(proto)
                    if (result == "") result = parse_params(params)
                }
            }
            in_proto = 0; proto = ""
            next
        }

        if (is_comment_line($0)) {
            if (in_proto) {
                proto = proto " " $0
                depth = paren_depth(proto)
                if (depth <= 0 && proto ~ /\(/) {
                    params = extract_proto_params(proto)
                    if (result == "") result = parse_params(params)
                    in_proto = 0; proto = ""
                }
            }
            next
        }

        if (!in_proto && ($0 ~ "\\<" name "\\(" && $0 !~ "\\<" name "\\(\\)" && $0 !~ "\\<" name "\\([[:digit:]]")) {
            in_proto = 1; proto = $0
            depth = paren_depth(proto)
            if (depth <= 0 && proto ~ /\(/) {
                params = extract_proto_params(proto)
                if (result == "") result = parse_params(params)
                in_proto = 0; proto = ""
            }
            next
        }

        if (!in_proto && ($0 ~ "syscall[[:space:]]*\\([[:space:]]*SYS_" name "[),]")) {
            in_proto = 1; proto = $0
            depth = paren_depth(proto)
            if (depth <= 0 && proto ~ /\(/) {
                params = extract_proto_params(proto)
                if (result == "") result = parse_params(params)
                in_proto = 0; proto = ""
            }
            next
        }

        if (in_proto) {
            proto = proto " " $0
            depth = paren_depth(proto)
            if (depth <= 0 && proto ~ /\(/) {
                params = extract_proto_params(proto)
                if (result == "") result = parse_params(params)
                in_proto = 0; proto = ""
            }
        }
    }

    END {
        if (in_proto && proto != "") {
            depth = paren_depth(proto)
            if (depth <= 0 && proto ~ /\(/) {
                params = extract_proto_params(proto)
                if (result == "") result = parse_params(params)
            }
        }
        if (result != "") print result; else print "[chimera] no match" > "/dev/stderr"
    }
    ' "$rn" -
}

# =========
# main
# =========

echo "-t>sysdata" > "$chmd"

grep -vhE '^(#|-t>|$)' data/arm64/syscall_64.chmd data/x86/syscall_64.chmd \
         data/arm64/syscall_32.chmd data/x86/syscall_32.chmd \
 | awk '{print $2}' | sort -u | while read -r name; do
    log "processing: $name"
    args=$(extract_args "$name" data/scribe_arg.chmd)

    # fallback: strip trailing digits (handles 2,32,64 compat variants)
    if [ -z "$args" ]; then
        trimmed=$(echo "$name" | sed 's/[0-9][0-9]*$//')
        if [ -n "$trimmed" ] && [ "$trimmed" != "$name" ]; then
            log "  fallback digits: $name -> $trimmed"
            args=$(extract_args "$trimmed" data/scribe_arg.chmd)
        fi
    fi

    # fallback: strip _time64 suffix
    if [ -z "$args" ]; then
        trimmed=$(echo "$name" | sed 's/_time64$//')
        if [ -n "$trimmed" ] && [ "$trimmed" != "$name" ]; then
            log "  fallback time64: $name -> $trimmed"
            args=$(extract_args "$trimmed" data/scribe_arg.chmd)
        fi
    fi

    # fallback: alias redirect
    if [ -z "$args" ]; then
        mapped=$(awk -F= -v n="$name" '!/^[#-]/ && $1 == n {print $2; exit}' data/scribe_alias.chmd)
        if [ -n "$mapped" ]; then
            log "  fallback alias: $name -> $mapped"
            args=$(extract_args "$mapped" data/scribe_arg.chmd)
        fi
    fi

    if [ -n "$args" ]; then
        log "  result: $args"
        echo "$name: $args" >> "$chmd"
    else
        log "  no args found"
    fi
done
