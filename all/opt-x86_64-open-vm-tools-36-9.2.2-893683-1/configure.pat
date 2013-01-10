--- configure.orig	Sun Dec 23 17:04:02 2012
+++ configure	Sun Dec 23 17:06:21 2012
@@ -17371,18 +17371,8 @@
 
    else
       true
-      as_fn_error $? "glib >= 2.6.0 is required." "$LINENO" 5
    fi
 
-
-
-   if test -z "gmodule-2.0"; then
-      as_fn_error $? "'library' parameter is required.'" "$LINENO" 5
-   fi
-   if test -z "GMODULE"; then
-      as_fn_error $? "'lvar' parameter is required.'" "$LINENO" 5
-   fi
-
    ac_vmw_have_lib=0
    ac_vmw_have_lib_func=0
    ac_vmw_have_lib_header=0
@@ -17577,18 +17567,8 @@
 
    else
       true
-      as_fn_error $? "gmodule >= 2.6.0 is required." "$LINENO" 5
    fi
 
-
-
-   if test -z "gobject-2.0"; then
-      as_fn_error $? "'library' parameter is required.'" "$LINENO" 5
-   fi
-   if test -z "GOBJECT"; then
-      as_fn_error $? "'lvar' parameter is required.'" "$LINENO" 5
-   fi
-
    ac_vmw_have_lib=0
    ac_vmw_have_lib_func=0
    ac_vmw_have_lib_header=0
@@ -17783,18 +17763,9 @@
 
    else
       true
-      as_fn_error $? "gobject >= 2.6.0 is required." "$LINENO" 5
    fi
 
 
-
-   if test -z "gthread-2.0"; then
-      as_fn_error $? "'library' parameter is required.'" "$LINENO" 5
-   fi
-   if test -z "GTHREAD"; then
-      as_fn_error $? "'lvar' parameter is required.'" "$LINENO" 5
-   fi
-
    ac_vmw_have_lib=0
    ac_vmw_have_lib_func=0
    ac_vmw_have_lib_header=0
@@ -17989,7 +17960,6 @@
 
    else
       true
-      as_fn_error $? "glib >= 2.6.0 is required." "$LINENO" 5
    fi
 
 # Extract the first word of "glib-genmarshal", so it can be a program name with args.
@@ -18030,24 +18000,11 @@
 fi
 
 
-
-if test "$have_genmarshal" != "yes"; then
-   as_fn_error $? "glib-genmarshal is required; make sure it's available in your path." "$LINENO" 5
-fi
-
 #
 # Parts of our Linux code require more recent version of glib
 #
 if test "$os" = "linux"; then
 
-
-   if test -z "glib-2.0"; then
-      as_fn_error $? "'library' parameter is required.'" "$LINENO" 5
-   fi
-   if test -z "GLIB2"; then
-      as_fn_error $? "'lvar' parameter is required.'" "$LINENO" 5
-   fi
-
    ac_vmw_have_lib=0
    ac_vmw_have_lib_func=0
    ac_vmw_have_lib_header=0
@@ -18252,14 +18209,6 @@
 # Check for fuse.
 #
 
-
-   if test -z "fuse"; then
-      as_fn_error $? "'library' parameter is required.'" "$LINENO" 5
-   fi
-   if test -z "FUSE"; then
-      as_fn_error $? "'lvar' parameter is required.'" "$LINENO" 5
-   fi
-
    ac_vmw_have_lib=0
    ac_vmw_have_lib_func=0
    ac_vmw_have_lib_header=0
@@ -18485,14 +18434,6 @@
       fi
    fi
 
-
-
-   if test -z "pam"; then
-      as_fn_error $? "'library' parameter is required.'" "$LINENO" 5
-   fi
-   if test -z "PAM"; then
-      as_fn_error $? "'lvar' parameter is required.'" "$LINENO" 5
-   fi
 
    ac_vmw_have_lib=0
    ac_vmw_have_lib_func=0
