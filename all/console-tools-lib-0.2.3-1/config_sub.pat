--- config.sub.orig	2011-03-14 08:22:18.228546816 +0100
+++ config.sub	2011-03-14 08:34:01.559172497 +0100
@@ -163,7 +163,7 @@
 	# We use `pc' rather than `unknown'
 	# because (1) that's what they normally are, and
 	# (2) the word "unknown" tends to confuse beginning users.
-	i[34567]86)
+	i[34567]86 | x86_64)
 	  basic_machine=$basic_machine-pc
 	  ;;
 	# Object if more than one company name word.
