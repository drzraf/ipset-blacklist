#!/bin/bash
#
# usage nft-blacklist.sh <configuration file>
# eg: nft-blacklist.sh /etc/nft-blacklist/nft-blacklist.conf
#
# lib-friendly, you can do: `. nft-blacklist.conf; . nft-blacklist.sh; extract_v4 mylist*.txt`

# can be executable name or custom path of either `iprange`
# (not IPv6 support: https://github.com/firehol/iprange/issues/14)
# * or `cidr-merger` (https://github.com/zhanhb/cidr-merger)
# * or `aggregate-prefixes` (Python)
DEFAULT_CIDR_MERGER=cidr-merger
NFT=nft  # can be "sudo /sbin/nft" or whatever to apply the ruleset
DEFAULT_HOOK=input # use "prerouting" if you need to drop packets before other prerouting rule chains
DEFAULT_CHAIN=input
SET_NAME_PREFIX=blacklist
SET_NAME_V4="${SET_NAME_PREFIX}_v4"
SET_NAME_V6="${SET_NAME_PREFIX}_v6"
IPV4_REGEX="(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{2})?"
IPV6_REGEX="(?:(?:[0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|\
(?:[0-9a-f]{1,4}:){1,7}:|\
(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|\
(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|\
(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|\
(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|\
(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|\
[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})|\
:(?:(?::[0-9a-f]{1,4}){1,7}|:)|\
::(?:[f]{4}(?::0{1,4})?:)?\
(?:(25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3,3}\
(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|\
(?:[0-9a-f]{1,4}:){1,4}:\
(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3,3}\
(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9]))\
(?:/[0-9]{1,3})?"

function exists() { command -v "$1" &>/dev/null ; }
function count_entries() { wc -l "$1" | cut -d' ' -f1 ; }

validate() {
    if [[ -z "$1" ]]; then
	echo "Error: please specify a configuration file, e.g. $0 /etc/nft-blacklist/nft-blacklist.conf"
	exit 1
    fi

    # shellcheck source=nft-blacklist.conf
    if ! source "$1"; then
	echo "Error: can't load configuration file $1"
	exit 1
    fi

    if ! type -P curl grep sed sort wc date &>/dev/null; then
	echo >&2 "Error: searching PATH fails to find executables among: curl grep sed sort wc date"
	exit 1
    fi
}

download() {
    BLACKLIST_TMP_DIR="$1" && shift
    (( $VERBOSE )) && echo -n "Downloading ${#BLACKLISTS[@]} sources into $BLACKLIST_TMP_DIR : "

    for url in "${BLACKLISTS[@]}"; do
	nc=$(curl --version|head -1|awk '{if ($2 > 7.83) print("--no-clobber")}')
	HTTP_RC=$(curl -L -A "nft-blacklist/1.0 (https://github.com/leshniak/nft-blacklist)" --connect-timeout 10 --max-time 10 -O $nc --output-dir "$BLACKLIST_TMP_DIR" -s -w "%{http_code}" "$url")
	# On file:// protocol, curl returns "000" per-file (file:///tmp/[1-3].txt would return "000000000" whether the 3 files exist or not)
	# A sequence of 3 resources would return "200200200"
	if (( HTTP_RC == 200 || HTTP_RC == 302 )) || [[ $HTTP_RC =~ ^(000|200){1,}$ ]]; then
	    (( $VERBOSE )) && echo -n "."
	elif (( HTTP_RC == 503 )); then
	    echo -e "\\nUnavailable (${HTTP_RC}): $url"
	else
	    echo >&2 -e "\\nWarning: curl returned HTTP response code $HTTP_RC for URL $url"
	fi
    done

    (( $VERBOSE )) && echo -e "\\n"
}

extract_v4() {
    # sort -nu does not work as expected
    command grep -hPo "^$IPV4_REGEX" "$@" | \
	sed -r 's/^0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)$/\1.\2.\3.\4/;/^(0\.0\.0\.0|10\.|127\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|22[4-9]\.|23[0-9]\.)/d' | \
	sort -n | sort -mu
}

extract_v6() {
    command grep -hPio "^$IPV6_REGEX" "$@" | sed -r -e '/^([0:]+\/0|fe80:)/Id' | sort -d | sort -mu
}

optimize() {
    local v4file="$1" && shift
    local v6file="$1" && shift
    local tmpv4=$(mktemp -t nft-blacklist-opti-ip4-XXX)
    local tmpv6=$(mktemp -t nft-blacklist-opti-ip6-XXX)

    (( $VERBOSE )) && echo -e "Optimizing entries...\\nFound: $(count_entries "$v4file") IPv4, $(count_entries "$v6file") IPv6"

    if [[ $CIDR_MERGER =~ merger ]]; then
	$CIDR_MERGER -o "$tmpv4" -o "$tmpv6" "$v4file" "$v6file"
    elif [[ $CIDR_MERGER =~ iprange ]]; then
	$CIDR_MERGER --optimize "$v4file" >| "$tmpv4"
	$CIDR_MERGER --optimize "$v6file" >| "$tmpv6"
    elif [[ $CIDR_MERGER =~ aggregate-prefixes ]]; then
	$CIDR_MERGER -s "$v4file" >| "$tmpv4"
	$CIDR_MERGER -s "$v6file" >| "$tmpv6"
    fi
    (( $VERBOSE )) && echo -e "Saved: $(count_entries "$tmpv4") IPv4, $(count_entries "$tmpv6") IPv6\\n"
    command mv -f "$tmpv4" "$v4file"
    command mv -f "$tmpv6" "$v6file"
}

generate_ruleset() {
    cat <<EOF
#
# Created by nft-blacklist (https://github.com/leshniak/nft-blacklist) at $(date -uIseconds)
# Blacklisted entries: $(count_entries "$IP_BLACKLIST_FILE") IPv4, $(count_entries "$IP6_BLACKLIST_FILE") IPv6
#
# Sources used:
$(printf "#   - %s\n" "${BLACKLISTS[@]}")
#
add table inet $TABLE
add counter inet $TABLE $SET_NAME_V4
add counter inet $TABLE $SET_NAME_V6
add set inet $TABLE $SET_NAME_V4 { type ipv4_addr; flags interval; auto-merge; }
flush set inet $TABLE $SET_NAME_V4
add set inet $TABLE $SET_NAME_V6 { type ipv6_addr; flags interval; auto-merge; }
flush set inet $TABLE $SET_NAME_V6
add chain inet $TABLE $CHAIN { type filter hook $HOOK priority filter - 1; policy accept; }
flush chain inet $TABLE $CHAIN
add rule inet $TABLE $CHAIN iif "lo" accept
add rule inet $TABLE $CHAIN meta pkttype { broadcast, multicast } accept
$([[ ! -z "$IP_WHITELIST" ]] && echo -e "\\nadd rule inet $TABLE $CHAIN ip saddr { $IP_WHITELIST } accept")
$([[ ! -z "$IP6_WHITELIST" ]] && echo -e "\\nadd rule inet $TABLE $CHAIN ip6 saddr { $IP6_WHITELIST } accept")
${CHAIN_PREAMBLE}
add rule inet $TABLE $CHAIN ip saddr @$SET_NAME_V4 counter name $SET_NAME_V4 drop
add rule inet $TABLE $CHAIN ip6 saddr @$SET_NAME_V6 counter name $SET_NAME_V6 drop
EOF

    if [[ -s "$IP_BLACKLIST_FILE" ]]; then
	cat <<EOF
add element inet $TABLE $SET_NAME_V4 {
$(sed -rn -e '/^[#$;]/d' -e "s/^([0-9./]+).*/  \\1,/p" "$IP_BLACKLIST_FILE")
}
EOF
    fi

    if [[ -s "$IP6_BLACKLIST_FILE" ]]; then
	cat <<EOF
add element inet $TABLE $SET_NAME_V6 {
$(sed -rn -e '/^[#$;]/d' -e "s/^(([0-9a-f:.]+:+[0-9a-f]*)+(\/[0-9]{1,3})?).*/  \\1,/Ip" "$IP6_BLACKLIST_FILE")
}
EOF
    fi
}

# If source (to reuse functions), don't exit
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && validate "$@"

[[ ${VERBOSE:-no} =~ ^1|on|true|yes$ ]] && let VERBOSE=1 || let VERBOSE=0
[[ ${DRY_RUN:-no} =~ ^1|on|true|yes$ ]] && let DRY_RUN=1 || let DRY_RUN=0
[[ ${DO_OPTIMIZE_CIDR:-yes} =~ ^1|on|true|yes$ ]] && let OPTIMIZE_CIDR=1 || let OPTIMIZE_CIDR=0
[[ ${KEEP_TMP_FILES:-no} =~ ^1|on|true|yes$ ]] && let KEEP_TMP_FILES=1 || let KEEP_TMP_FILES=0
CIDR_MERGER="${CIDR_MERGER:-$DEFAULT_CIDR_MERGER}"
HOOK="${HOOK:-$DEFAULT_HOOK}"
CHAIN="${CHAIN:-$DEFAULT_CHAIN}"
CHAIN_PREAMBLE=$(eval echo "${CHAIN_PREAMBLE}")

if exists $CIDR_MERGER && (( $OPTIMIZE_CIDR )); then
  let OPTIMIZE_CIDR=1
elif (( $OPTIMIZE_CIDR )); then
  let OPTIMIZE_CIDR=0
  echo >&2 "Warning: $CIDR_MERGER is not available"
fi

# If source (to reuse functions), stop here
[[ "${BASH_SOURCE[0]}" != "${0}" ]] && return;

if [[ ! -d $(dirname "$IP_BLACKLIST_FILE") || ! -d $(dirname "$IP6_BLACKLIST_FILE") || ! -d $(dirname "$RULESET_FILE") ]]; then
  echo >&2 "Error: missing directory(s): $(dirname "$IP_BLACKLIST_FILE" "$IP6_BLACKLIST_FILE" "$RULESET_FILE" | sort -u)"
  exit 1
fi

## Processing starts
# Download
TMP_SOURCES_DIR=${TMP_SOURCES_DIR:-$(mktemp -d -t nft-blacklist-sources-XXX)}
download "$TMP_SOURCES_DIR"
extract_v4 "$TMP_SOURCES_DIR"/* >| "$IP_BLACKLIST_FILE"
extract_v6 "$TMP_SOURCES_DIR"/* >| "$IP6_BLACKLIST_FILE"
(( $KEEP_TMP_FILES )) || rm -rf "$TMP_SOURCES_DIR"

# Optimization
(( $OPTIMIZE_CIDR )) && optimize "$IP_BLACKLIST_FILE" "$IP6_BLACKLIST_FILE"
generate_ruleset >| "$RULESET_FILE"

# Loading
if (( ! $DRY_RUN )); then
  (( $VERBOSE )) && echo "Applying ruleset..."
  $NFT -f "$RULESET_FILE" || { echo >&2 "Failed to apply the ruleset"; exit 1; }
fi

if (( $VERBOSE )); then
  echo
  echo "IPv4 blacklisted: $(wc -l "$IP_BLACKLIST_FILE" | cut -d' ' -f1)"
  echo "IPv6 blacklisted: $(wc -l "$IP6_BLACKLIST_FILE" | cut -d' ' -f1)"
fi

(( $VERBOSE )) && echo "Done!"

exit 0
