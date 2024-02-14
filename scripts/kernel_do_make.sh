#! /bin/bash
make -j$(nproc)
sudo make modules_install
sudo make install
sudo cp arch/x86_64/boot/bzImage ../shared_folder/bzImage
sudo cp /boot/initrd.img-5.16.0+ ../shared_folder/initrd.img-5.16.0+
