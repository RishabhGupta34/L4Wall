kernel="5.4.0-050400-generic"
    kernlist="$(grep -i "menuentry '" /boot/grub/grub.cfg|sed -r "s|--class .*$||g")"
    printf "%s$kernlist\n" | logger
    menuline="$(printf "%s$kernlist\n"|grep -ne $kernel | grep -v recovery | cut -f1 -d":")"
    menunum="$(($menuline-2))"
    grub-reboot "1>$menunum"
    echo "The next grub's menu entry will be choosen after the reboot:\n 1>$menunum" | logger

    reboot
