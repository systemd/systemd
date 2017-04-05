# -*- mode: meson -*-

hwdb_files = files('''
  20-pci-vendor-model.hwdb
  20-pci-classes.hwdb
  20-usb-vendor-model.hwdb
  20-usb-classes.hwdb
  20-sdio-vendor-model.hwdb
  20-sdio-classes.hwdb
  20-bluetooth-vendor-product.hwdb
  20-acpi-vendor.hwdb
  20-OUI.hwdb
  20-net-ifname.hwdb
  60-evdev.hwdb
  60-keyboard.hwdb
  60-sensor.hwdb
  70-mouse.hwdb
  70-pointingstick.hwdb
  70-touchpad.hwdb
'''.split())

if conf.get('ENABLE_HWDB', 0) == 1
  install_data(hwdb_files,
               install_dir : udevhwdbdir)
endif
