#!/bin/sh
# Sourced by scripts/update.sh and scripts/pull-on-exit.sh (it runs nothing by itself): the rules for which commit a Sentinel may move to.
#
# A Sentinel on Automatic updates moves to the commit cvENGINE named in its heartbeat (the "target"), never to "whatever origin/<branch> is now".
# Commits are not signature-checked in 1.4.0, so this is as far as the trust goes: the server's named commit, and that it is on the repository's
# own branch and ahead of what runs here.
#
#   check_update_target REQUESTED BRANCH ALLOW_MOVE RUNNING...
#
# Succeeds with the full commit id in TARGET_FULL. Otherwise returns 1 with a plain sentence in REFUSAL and changes nothing. The caller has fetched
# origin/BRANCH. REQUESTED must be a commit the fetched history contains and origin/BRANCH reaches (a commit pushed to another branch is not an
# update), and every RUNNING commit (the deployed one, HEAD) must be an ancestor of it or equal: no downgrade, no sideways move, unless ALLOW_MOVE is
# 1, which only a person typing --allow-non-descendant by hand gets.
check_update_target() {
  _req=$1 _branch=$2 _allow=$3
  shift 3
  REFUSAL=""
  TARGET_FULL=""
  case "$_req" in
    ''|*[!0-9a-f]*) REFUSAL="the requested commit '$_req' is not a commit id (7 to 40 hex digits)"; return 1 ;;
  esac
  if [ "${#_req}" -lt 7 ] || [ "${#_req}" -gt 40 ]; then
    REFUSAL="the requested commit '$_req' is not a commit id (7 to 40 hex digits)"
    return 1
  fi
  _full=$(git rev-parse --verify --quiet "$_req^{commit}") || { REFUSAL="the requested commit $_req is not in the history fetched from origin/$_branch"; return 1; }
  git merge-base --is-ancestor "$_full" "origin/$_branch" || { REFUSAL="the requested commit $_req is not reachable from origin/$_branch, so it is not an update"; return 1; }
  for _run in "$@"; do
    [ -n "$_run" ] || continue
    git cat-file -e "$_run^{commit}" 2>/dev/null || continue
    if ! git merge-base --is-ancestor "$_run" "$_full" && [ "$_allow" != 1 ]; then
      REFUSAL="the requested commit $_req is not a descendant of the commit this Sentinel runs ($(printf '%s' "$_run" | cut -c1-12)): no downgrade and no sideways move"
      return 1
    fi
  done
  TARGET_FULL=$_full
  return 0
}
