--- src/ipc/semctl.c.orig	Sat Sep 22 12:38:03 2012
+++ src/ipc/semctl.c	Sat Sep 22 12:38:34 2012
@@ -11,8 +11,8 @@
 	arg = va_arg(ap, long);
 	va_end(ap);
 #ifdef SYS_semctl
-	return syscall(SYS_semctl, id, num, cmd | 0x100, arg);
+	return syscall(SYS_semctl, id, num, cmd, arg);
 #else
-	return syscall(SYS_ipc, IPCOP_semctl, id, num, cmd | 0x100, &arg);
+	return syscall(SYS_ipc, IPCOP_semctl, id, num, cmd, &arg);
 #endif
 }
--- src/ipc/msgctl.c.orig	Sat Sep 22 12:38:14 2012
+++ src/ipc/msgctl.c	Sat Sep 22 12:38:55 2012
@@ -5,8 +5,8 @@
 int msgctl(int q, int cmd, struct msqid_ds *buf)
 {
 #ifdef SYS_msgctl
-	return syscall(SYS_msgctl, q, cmd | 0x100, buf);
+	return syscall(SYS_msgctl, q, cmd, buf);
 #else
-	return syscall(SYS_ipc, IPCOP_msgctl, q, cmd | 0x100, 0, buf, 0);
+	return syscall(SYS_ipc, IPCOP_msgctl, q, cmd, 0, buf, 0);
 #endif
 }
