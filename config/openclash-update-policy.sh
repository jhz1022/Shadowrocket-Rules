#!/bin/sh
# Invoke the native updater through the existing authenticated loopback proxy.
# No node URL, credential, routing policy or curl implementation is duplicated.
set -eu
umask 077
update_dir=$(mktemp -d /tmp/openclash-policy.XXXXXX)
cleanup() { rm -f "$update_dir/.curlrc"; rmdir "$update_dir"; }
trap cleanup EXIT HUP INT TERM
ruby -e '
  def setting(key)
    IO.popen(["uci", "-q", "get", key], &:read).chomp
  end
  port = setting("openclash.config.mixed_port")
  abort "Invalid local proxy port" unless port.match?(/\A[0-9]+\z/) && (1..65535).cover?(port.to_i)
  puts "proxy = " + "http://127.0.0.1:#{port}".dump
  puts "noproxy = \"\""
  if setting("openclash.@authentication[0].enabled") == "1"
    user = setting("openclash.@authentication[0].username")
    pass = setting("openclash.@authentication[0].password")
    abort "Missing local proxy authentication" if user.empty? || pass.empty?
    puts "proxy-user = " + "#{user}:#{pass}".dump
  end
' > "$update_dir/.curlrc"
if CURL_HOME="$update_dir" /usr/share/openclash/openclash.sh "$@"; then
  exit 0
else
  exit "$?"
fi
