mkdir -p /home/build/mini-native-x86_64/var/lib
cp /etc/resolv.conf /home/build/mini-native-x86_64/etc
cp /etc/hosts /home/build/mini-native-x86_64/etc
setarch x86_64 chroot /home/build/mini-native-x86_64 /bin/chroot-setup.sh
