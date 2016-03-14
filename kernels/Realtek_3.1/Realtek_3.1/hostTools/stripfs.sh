#! /bin/sh

FS_DIR=$1

# Temporary file to collect the names of files that we need to process
FILE_LIST=.strip

# Command used to get rid of unnecesary sections
DROP_SECTIONS="xargs -n1 $OBJCOPY --remove-section .comment \
  --remove-section .pdr --remove-section .debug_macinfo \
  --remove-section .gnu.version --remove-section .gnu.version_r \
  --remove-section .mdebug.abi32"

# Command used to strip libraries/modules
STRIP_LIBS="xargs $STRIP --strip-unneeded"

# Command used to strip executables
STRIP_EXES="xargs $STRIP --strip-all"

# Some modules can't be stripped
MODS_KEEPSYM="! -name ip_conntrack_pt.* ! -name ip_nat_pt.* ! -name modules.*map ! -name modules.dep ! -name modules.symbols ! -name modules.alias"

# Find kernel modules that should be stripped.
echo "stripping kernel modules..."
find $FS_DIR/lib/modules -type f $MODS_KEEPSYM > $FILE_LIST

# Some libraries can't be stripped
LIBS_KEEPSYM=

# In case we want to debug, don't strip the threads library
LIBS_KEEPSYM="$LIBS_KEEPSYM ! -name libpthread*.so"
# But do drop any unneeded sections
echo $FS_DIR/lib/libpthread-*.so | $DROP_SECTIONS

# Find shared libraries
echo "stripping shared libraries..."
find $FS_DIR/lib -maxdepth 1 -type f $LIBS_KEEPSYM >> $FILE_LIST

## Find PPP plugins
#echo "stripping PPP plugins..."
#find $FS_DIR/lib/pppd -type f >> $FILE_LIST

# Strip unneeded symbols/sections from all found files
#  (preserve what's necessary for relocation)
$DROP_SECTIONS < $FILE_LIST
$STRIP_LIBS < $FILE_LIST

rm -f $FILE_LIST

# Find executables (binaries)
echo "stripping binaries..."
find $FS_DIR/bin $FS_DIR/sbin -type f |\
    xargs file | grep "executable" | grep -v "shell script" | sed 's/:.*//' > $FILE_LIST

# Strip all symbols (and unneeded sections) from executables
$DROP_SECTIONS < $FILE_LIST
$STRIP_EXES < $FILE_LIST

rm -f $FILE_LIST
