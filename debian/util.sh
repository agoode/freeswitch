#!/bin/bash
##### -*- mode:shell-script; indent-tabs-mode:nil; sh-basic-offset:2 -*-
##### Author: Travis Cross <tc@traviscross.com>

set -e

ddir="."
[ -n "${0%/*}" ] && ddir="${0%/*}"
cd $ddir/../

#### lib

err () {
  echo "$0 error: $1" >&2
  exit 1
}

announce () {
  cat >&2 <<EOF

########################################################################
## $1
########################################################################

EOF
}

xread () {
  local xIFS="$IFS"
  IFS=''
  read $@
  local ret=$?
  IFS="$xIFS"
  return $ret
}

mk_dver () { echo "$1" | sed -e 's/-/~/g'; }
mk_uver () { echo "$1" | sed -e 's/-.*$//' -e 's/~/-/'; }
dsc_source () { dpkg-parsechangelog | grep '^Source:' | awk '{print $2}'; }
dsc_ver () { dpkg-parsechangelog | grep '^Version:' | awk '{print $2}'; }
up_ver () { mk_uver "$(dsc_ver)"; }
dsc_base () { echo "$(dsc_source)_$(dsc_ver)"; }
up_base () { echo "$(dsc_source)-$(up_ver)"; }

find_distro () {
  case "$1" in
    experimental) echo "sid";;
    unstable) echo "sid";;
    testing) echo "stretch";;
    stable) echo "jessie";;
    oldstable) echo "wheezy";;
    *) echo "$1";;
  esac
}

find_suite () {
  case "$1" in
    sid) echo "unstable";;
    stretch) echo "testing";;
    jessie) echo "stable";;
    wheezy) echo "oldstable";;
    *) echo "$1";;
  esac
}

#### debian/rules helpers

create_dbg_pkgs () {
  for x in $ddir/*; do
    test ! -d $x && continue
    test "$x" = "tmp" -o "$x" = "source" && continue
    test ! "$x" = "${x%-dbg}" && continue
    test ! -d $x/usr/lib/debug && continue
    mkdir -p $x-dbg/usr/lib
    mv $x/usr/lib/debug $x-dbg/usr/lib/
  done
}

cwget () {
  local url="$1" f="${1##*/}"
  echo "fetching: $url to $f" >&2
  if [ -n "$FS_FILES_DIR" ]; then
    if ! [ -s "$FS_FILES_DIR/$f" ]; then
      (cd $FS_FILES_DIR && wget -N "$url")
    fi
    cp -a $FS_FILES_DIR/$f .
  else
    wget -N "$url"
  fi
}

getlib () {
  local url="$1" f="${1##*/}"
  cwget "$url"
  tar -xv --no-same-owner --no-same-permissions -f "$f"
  rm -f "$f" && mkdir -p $f && touch $f/.download-stamp
}

getlibs () {
  # get pinned libraries
  getlib http://files.freeswitch.org/downloads/libs/sphinxbase-0.8.tar.gz
  getlib http://files.freeswitch.org/downloads/libs/pocketsphinx-0.8.tar.gz
  getlib http://files.freeswitch.org/downloads/libs/communicator_semi_6000_20080321.tar.gz
  getlib http://download.zeromq.org/zeromq-2.1.9.tar.gz \
    || getlib http://download.zeromq.org/historic/zeromq-2.1.9.tar.gz
  getlib http://files.freeswitch.org/downloads/libs/freeradius-client-1.1.7.tar.gz
  #getlib http://files.freeswitch.org/downloads/libs/v8-3.24.14.tar.bz2
}

check_repo_clean () {
  git diff-index --quiet --cached HEAD \
    || err "uncommitted changes present"
  git diff-files --quiet \
    || err "unclean working tree"
  git diff-index --quiet HEAD \
    || err "unclean repository"
  ! git ls-files --other --error-unmatch . >/dev/null 2>&1 \
    || err "untracked files or build products present"
}

get_last_release_ver () {
  grep -m1 -e '^AC_INIT' configure.ac \
    | cut -d, -f2 \
    | sed -e 's/\[//' -e 's/\]//' -e 's/ //g'
}

get_nightly_version () {
  local commit="$(git rev-list -n1 --abbrev=10 --abbrev-commit HEAD)"
  echo "$(get_last_release_ver)+git~$(date -u '+%Y%m%dT%H%M%SZ')~$commit"
}

get_nightly_revision_human () {
  echo "git $(git rev-list -n1 --abbrev=7 --abbrev-commit HEAD) $(date -u '+%Y-%m-%d %H:%M:%SZ')"
}

create_orig () {
  {
    set -e
    local OPTIND OPTARG
    local uver="" hrev="" bundle_deps=true modules_list="" zl=9e
    while getopts 'bm:nv:z:' o "$@"; do
      case "$o" in
        m) modules_list="$OPTARG";;
        n) uver="nightly";;
        v) uver="$OPTARG";;
        z) zl="$OPTARG";;
      esac
    done
    shift $(($OPTIND-1))
    if [ -z "$uver" ] || [ "$uver" = "nightly" ]; then
      uver="$(get_nightly_version)"
      hrev="$(get_nightly_revision_human)"
    fi
    local treeish="$1" dver="$(mk_dver "$uver")"
    local orig="../freeswitch_$dver.orig.tar.xz"
    [ -n "$treeish" ] || treeish="HEAD"
    check_repo_clean
    git reset --hard "$treeish"
    mv .gitattributes .gitattributes.orig
    local -a args=(-e '\bdebian-ignore\b')
    test "$modules_list" = "non-dfsg" || args+=(-e '\bdfsg-nonfree\b')
    grep .gitattributes.orig "${args[@]}" \
      | while xread l; do
      echo "$l export-ignore" >> .gitattributes
    done
    if $bundle_deps; then
      (cd libs && getlibs)
      git add -f libs
    fi
    ./build/set-fs-version.sh "$uver" "$hrev" && git add configure.ac
    echo "$uver" > .version && git add -f .version
    git commit --allow-empty -m "nightly v$uver"
    git archive -v \
      --worktree-attributes \
      --format=tar \
      --prefix=freeswitch-$uver/ \
      HEAD \
      | xz -c -${zl}v > $orig
    mv .gitattributes.orig .gitattributes
    git reset --hard HEAD^ && git clean -fdx
  } 1>&2
  echo $orig
}

set_modules_quicktest () {
  cat > debian/modules.conf <<EOF
applications/mod_commands
EOF
}

create_dsc () {
  {
    set -e
    local OPTIND OPTARG modules_conf="" modules_list="" speed="normal" suite_postfix="" suite_postfix_p=false zl=9
    local modules_add=""
    while getopts 'f:m:p:s:u:z:' o "$@"; do
      case "$o" in
        f) modules_conf="$OPTARG";;
        m) modules_list="$OPTARG";;
        p) modules_add="$modules_add $OPTARG";;
        s) speed="$OPTARG";;
        u) suite_postfix="$OPTARG"; suite_postfix_p=true;;
        z) zl="$OPTARG";;
      esac
    done
    shift $(($OPTIND-1))
    local distro="$(find_distro $1)" orig="$2"
    local suite="$(find_suite $distro)"
    local orig_ver="$(echo "$orig" | sed -e 's/^.*_//' -e 's/\.orig\.tar.*$//')"
    local dver="${orig_ver}-1~${distro}+1"
    $suite_postfix_p && { suite="${distro}${suite_postfix}"; }
    [ -x "$(which dch)" ] \
      || err "package devscripts isn't installed"
    if [ -n "$modules_conf" ]; then
      cp $modules_conf debian/modules.conf
    fi
    local bootstrap_args=""
    if [ -n "$modules_list" ]; then
      if [ "$modules_list" = "non-dfsg" ]; then
        bootstrap_args="-mnon-dfsg"
      else set_modules_${modules_list}; fi
    fi
    if test -n "$modules_add"; then
      for x in $modules_add; do
        bootstrap_args="$bootstrap_args -p${x}"
      done
    fi
    (cd debian && ./bootstrap.sh -c $distro $bootstrap_args)
    case "$speed" in
      paranoid) sed -i ./debian/rules \
        -e '/\.stamp-bootstrap:/{:l2 n; /\.\/bootstrap.sh -j/{s/ -j//; :l3 n; b l3}; b l2};' ;;
      reckless) sed -i ./debian/rules \
        -e '/\.stamp-build:/{:l2 n; /make/{s/$/ -j/; :l3 n; b l3}; b l2};' ;;
    esac
    [ "$zl" -ge "1" ] || zl=1
    git add debian/rules
    dch -b -m -v "$dver" --force-distribution -D "$suite" "Nightly build."
    git add debian/changelog && git commit -m "nightly v$orig_ver"
    dpkg-source -i.* -Zxz -z${zl} -b .
    dpkg-genchanges -S > ../$(dsc_base)_source.changes
    local dsc="../$(dsc_base).dsc"
    git reset --hard HEAD^ && git clean -fdx
  } 1>&2
  echo $dsc
}

fmt_debug_hook () {
  cat <<'EOF'
#!/bin/bash
export debian_chroot="cow"
cd /tmp/buildd/*/debian/..
/bin/bash < /dev/tty > /dev/tty 2> /dev/tty
EOF
}

get_sources () {
  local tgt_distro="$1"
  while read type path distro components; do
    test "$type" = deb || continue
    prefix=`echo $distro | awk -F/ '{print $1}'`
    suffix="`echo $distro | awk -F/ '{print $2}'`"
    if test -n "$suffix" ; then full="$tgt_distro/$suffix" ; else full="$tgt_distro" ; fi
    printf "$type $path $full $components\n"
  done < "$2"
}

get_mirrors () {
  file=${2-/etc/apt/sources.list}
  announce "Using apt sources file: $file"
  get_sources "$1" "$file" | tr '\n' '|' | head -c-1; echo
}

build_debs () {
  {
    set -e
    local OPTIND OPTARG debug_hook=false hookdir="" cow_build_opts=""
    local keep_pbuilder_config=false keyring="" custom_keyring="/tmp/fs.gpg"
    local use_custom_sources=true
    local custom_sources_file="/etc/apt/sources.list"
    while getopts 'BbdK:kT:t' o "$@"; do
      case "$o" in
        B) cow_build_opts="--debbuildopts '-B'";;
        b) cow_build_opts="--debbuildopts '-b'";;
        d) debug_hook=true;;
        k) keep_pbuilder_config=true;;
        K) custom_keyring="$OPTARG";;
        t) custom_sources_file="/etc/apt/sources.list";;
        T) custom_sources_file="$OPTARG";;
      esac
    done
    shift $(($OPTIND-1))
    if [ "$custom_sources_file" == "/etc/apt/sources.list" ]; then
      # If you are using the system sources, then it is reasonable that you expect to use all of the supplementary repos too
      cat /etc/apt/sources.list > /tmp/fs.sources.list
      if [ "$(ls -A /etc/apt/sources.list.d)" ]; then
        for X in /etc/apt/sources.list.d/*; do cat $X >> /tmp/fs.sources.list; done
      fi
      custom_sources_file="/tmp/fs.sources.list"
      apt-key exportall > "/tmp/fs.gpg"
      custom_keyring="/tmp/fs.gpg"
    fi
    if [ "$custom_sources_file" == "" ]; then
      # Caller has explicitly set the custom sources file to empty string. They must intend to not use additional mirrors.
      use_custom_sources=false
    fi
    if [[ "$custom_source_file" == "/tmp/fs.sources.list" && ! -e "/tmp/fs.sources.list" ]]; then
      echo "deb http://files.freeswitch.org/repo/deb/debian/ jessie main" >> "/tmp/fs.sources.list"
    fi
    if [[ "$custom_keyring" == "/tmp/fs.gpg" && ! -r "/tmp/fs.gpg" ]]; then
      cat << EOF > "/tmp/fs.gpg"
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.12 (GNU/Linux)

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
=06q/
-----END PGP PUBLIC KEY BLOCK-----
EOF
    fi

    local distro="$(find_distro $1)" dsc="$2" arch="$3"
    if [ -z "$distro" ] || [ "$distro" = "auto" ]; then
      if ! (echo "$dsc" | grep -e '-[0-9]*~[a-z]*+[0-9]*'); then
        err "no distro specified or found"
      fi
      local x="$(echo $dsc | sed -e 's/^[^-]*-[0-9]*~//' -e 's/+[^+]*$//')"
      distro="$(find_distro $x)"
    fi
    [ -n "$arch" ] || arch="$(dpkg-architecture | grep '^DEB_BUILD_ARCH=' | cut -d'=' -f2)"
    [ -x "$(which cowbuilder)" ] \
      || err "package cowbuilder isn't installed"
    local cow_img=/var/cache/pbuilder/base-$distro-$arch.cow
    if [ -e "$custom_keyring" ]; then
      keyring="$custom_keyring"
    else
      keyring="$(mktemp /tmp/keyringXXXXXXXX.asc)"
      apt-key exportall > "$keyring"
    fi
    cow () {
      if ! $use_custom_sources; then
        echo "Using system sources $keyring $distro $custom_sources_file"
        cowbuilder "$@" \
          --distribution $distro \
          --architecture $arch \
          --basepath $cow_img
      else
        echo "Using custom sources $keyring $distro $custom_sources_file"
        cowbuilder "$@" \
          --distribution $distro \
          --architecture $arch \
          --basepath $cow_img \
          --keyring "$keyring" \
          --othermirror "$(get_mirrors $distro $custom_sources_file)"
      fi
    }
    if ! [ -d $cow_img ]; then
      announce "Creating base $distro-$arch image..."
      local x=30
      while ! cow --create; do
        [ $x -lt 1 ] && break; sleep 120; x=$((x-1))
      done
    fi
    announce "Updating base $distro-$arch image..."
    local x=30
    local opts="--override-config"
    $keep_pbuilder_config && opts=""
    while ! cow --update $opts; do
      [ $x -lt 1 ] && break; sleep 120; x=$((x-1))
    done
    announce "Building $distro-$arch DEBs from $dsc..."
    if $debug_hook; then
      mkdir -p .hooks
      fmt_debug_hook > .hooks/C10shell
      chmod +x .hooks/C10shell
      hookdir=$(pwd)/.hooks
    fi
    cow --build $dsc \
      --hookdir "$hookdir" \
      --buildresult ../ \
      $cow_build_opts
    if [ ! -e "$custom_keyring" ]; then
      # Cleanup script created temporary file
      rm -f $keyring
    fi
  } 1>&2
  echo ${dsc%.dsc}_${arch}.changes
}

default_distros () {
  local host_distro="Debian"
  test -z "$(which lsb_release)" || host_distro="$(lsb_release -is)"
  case "$host_distro" in
    Debian) echo "sid jessie wheezy" ;;
    Ubuntu) echo "utopic trusty" ;;
    *) err "Unknown host distribution \"$host_distro\"" ;;
  esac
}

build_all () {
  local OPTIND OPTARG
  local orig_opts="" dsc_opts="" deb_opts="" modlist=""
  local archs="" distros="" orig="" depinst=false par=false
  while getopts 'a:bc:df:ijkK:l:m:no:p:s:tT:u:v:z:' o "$@"; do
    case "$o" in
      a) archs="$archs $OPTARG";;
      b) orig_opts="$orig_opts -b";;
      c) distros="$distros $OPTARG";;
      d) deb_opts="$deb_opts -d";;
      f) dsc_opts="$dsc_opts -f$OPTARG";;
      i) depinst=true;;
      j) par=true;;
      k) deb_opts="$deb_opts -k";;
      K) deb_opts="$deb_opts -K$OPTARG";;
      l) modlist="$OPTARG";;
      m) orig_opts="$orig_opts -m$OPTARG"; dsc_opts="$dsc_opts -m$OPTARG";;
      n) orig_opts="$orig_opts -n";;
      o) orig="$OPTARG";;
      p) dsc_opts="$dsc_opts -p$OPTARG";;
      s) dsc_opts="$dsc_opts -s$OPTARG";;
      t) deb_opts="$deb_opts -t";;
      T) deb_opts="$deb_opts -T$OPTARG";;
      u) dsc_opts="$dsc_opts -u$OPTARG";;
      v) orig_opts="$orig_opts -v$OPTARG";;
      z) orig_opts="$orig_opts -z$OPTARG"; dsc_opts="$dsc_opts -z$OPTARG";;
    esac
  done
  shift $(($OPTIND-1))
  [ -n "$archs" ] || archs="amd64 i386"
  [ -n "$distros" ] || distros="$(default_distros)"
  ! $depinst || aptitude install -y \
    rsync git less cowbuilder ccache \
    devscripts equivs build-essential yasm
  [ -n "$orig" ] || orig="$(create_orig $orig_opts HEAD | tail -n1)"
  if [ -n "$modlist" ]; then
    local modtmp="$(mktemp /tmp/modules-XXXXXXXXXX.conf)"
    > $modtmp
    for m in "$modlist"; do printf '%s\n' "$m" >> $modtmp; done
    dsc_opts="$dsc_opts -f${modtmp}"; fi
  [ -n "$orig" ] || orig="$(create_orig $orig_opts HEAD | tail -n1)"
  mkdir -p ../log
  > ../log/changes.txt
  echo; echo; echo; echo
  trap 'echo "Killing children...">&2; for x in $(jobs -p); do kill $x; done' EXIT
  if [ "${orig:0:2}" = ".." ]; then
    echo "true" > ../log/builds-ok.txt
    for distro in $distros; do
      echo "Creating $distro dsc..." >&2
      local dsc="$(create_dsc $dsc_opts $distro $orig 2>../log/$distro.txt | tail -n1)"
      echo "Done creating $distro dsc." >&2
      if [ "${dsc:0:2}" = ".." ]; then
        local lopts="-b"
        for arch in $archs; do
          {
            echo "Building $distro-$arch debs..." >&2
            local changes="$(build_debs $lopts $deb_opts $distro $dsc $arch 2>../log/$distro-$arch.txt | tail -n1)"
            echo "Done building $distro-$arch debs." >&2
            if [ "${changes:0:2}" = ".." ]; then
              echo "$changes" >> ../log/changes.txt
            else
              echo "false" > ../log/builds-ok.txt
            fi
          } &
          $par || wait
          lopts="-B"
        done
      fi
    done
    ! $par || wait
  fi
  [ -z "$modlist" ] || rm -f $modtmp
  trap - EXIT
  cat ../log/changes.txt
  test "$(cat ../log/builds-ok.txt)" = true || exit 1
}

usage () {
  cat >&2 <<EOF
$0 [opts] [cmd] [cmd-opts]

options:

  -d Enable debugging mode.

commands:

  archive-orig

  build-all

    [ This must be run as root! ]

    -a Specify architectures
    -c Specify distributions
    -d Enable cowbuilder debug hook
    -f <modules.conf>
      Build only modules listed in this file
    -i Auto install build deps on host system
    -j Build debs in parallel
    -k Don't override pbuilder image configurations
    -K [/path/to/keyring.asc]
       Use custom keyring file for sources.list in build environment
       in the format of: apt-key exportall > /path/to/file.asc
    -l <modules>
    -m [ quicktest | non-dfsg ]
      Choose custom list of modules to build
    -n Nightly build
    -o <orig-file>
      Specify existing .orig.tar.xz file
    -p <module>
      Include otherwise avoided module
    -s [ paranoid | reckless ]
      Set FS bootstrap/build -j flags
    -t Use system /etc/apt/sources.list in build environment(does not include /etc/apt/sources.list.d/*.list)
    -T [/path/to/sources.list]
       Use custom /etc/apt/sources.list in build environment
    -u <suite-postfix>
      Specify a custom suite postfix
    -v Set version
    -z Set compression level

  build-debs <distro> <dsc-file> <architecture>

    [ This must be run as root! ]

    -B Binary architecture-dependent build
    -b Binary-only build
    -d Enable cowbuilder debug hook
    -k Don't override pbuilder image configurations
    -K [/path/to/keyring.asc]
       Use custom keyring file for sources.list in build environment
       in the format of: apt-key exportall > /path/to/file.asc
    -t Use system /etc/apt/sources.list in build environment
    -T [/path/to/sources.list]
       Use custom /etc/apt/sources.list in build environment

  create-dbg-pkgs

  create-dsc <distro> <orig-file>

    -f <modules.conf>
      Build only modules listed in this file
    -m [ quicktest | non-dfsg ]
      Choose custom list of modules to build
    -p <module>
      Include otherwise avoided module
    -s [ paranoid | reckless ]
      Set FS bootstrap/build -j flags
    -u <suite-postfix>
      Specify a custom suite postfix
    -z Set compression level

  create-orig <treeish>

    -m [ quicktest | non-dfsg ]
      Choose custom list of modules to build
    -n Nightly build
    -v Set version
    -z Set compression level

EOF
  exit 1
}

while getopts 'dh' o "$@"; do
  case "$o" in
    d) set -vx;;
    h) usage;;
  esac
done
shift $(($OPTIND-1))

cmd="$1"; [ -n "$cmd" ] || usage
shift
case "$cmd" in
  archive-orig) archive_orig "$@" ;;
  build-all) build_all "$@" ;;
  build-debs) build_debs "$@" ;;
  create-dbg-pkgs) create_dbg_pkgs ;;
  create-dsc) create_dsc "$@" ;;
  create-orig) create_orig "$@" ;;
  *) usage ;;
esac
