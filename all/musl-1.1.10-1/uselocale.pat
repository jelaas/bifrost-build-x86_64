From 63f4b9f18f3674124d8bcb119739fec85e6da005 Mon Sep 17 00:00:00 2001
From: Timo Teräs <timo.teras@iki.fi>
Date: Fri, 05 Jun 2015 07:39:42 +0000
Subject: fix uselocale((locale_t)0) not to modify locale

commit 68630b55c0c7219fe9df70dc28ffbf9efc8021d8 made the new locale to
be assigned unconditonally resulting in crashes later on.
---
diff --git a/src/locale/uselocale.c b/src/locale/uselocale.c
index b70a0c1..0fc5ecb 100644
--- a/src/locale/uselocale.c
+++ b/src/locale/uselocale.c
@@ -8,9 +8,7 @@ locale_t __uselocale(locale_t new)
 	locale_t old = self->locale;
 	locale_t global = &libc.global_locale;
 
-	if (new == LC_GLOBAL_LOCALE) new = global;
-
-	self->locale = new;
+	if (new) self->locale = new == LC_GLOBAL_LOCALE ? global : new;
 
 	return old == global ? LC_GLOBAL_LOCALE : old;
 }
--
cgit v0.9.0.3-65-g4555
