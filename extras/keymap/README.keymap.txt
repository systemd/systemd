= The udev keymap tool =

== Introduction ==

This udev extension configures computer model specific key mappings. This is
particularly necessary for the non-standard extra keys found on many laptops,
such as "brightness up", "next song", "www browser", or "suspend". Often these
are accessed with the Fn key.

Every key produces a "scan code", which is highly vendor/model specific for the
nonstandard keys. This tool maintains mappings for these scan codes to standard
"key codes", which denote the "meaning" of the key. The key codes are defined
in /usr/include/linux/input.h.

If some of your keys on your keyboard are not working at all, or produce the
wrong effect, then a very likely cause of this is that the scan code -> key
code mapping is incorrect on your computer.

== Structure ==

udev-keymap consists of the following parts:

 keymaps/*:: mappings of scan codes to key code names
   
 95-keymap.rules:: udev rules for mapping system vendor/product names and
 input module names to one of the keymaps above

 keymap:: manipulate an evdev input device:
  * write a key map file into a device (used by udev rules)
  * dump current scan → key code mapping
  * interactively display scan and key codes of pressed keys

 findkeyboards:: display evdev input devices which belong to actual keyboards,
 i. e. those suitable for the keymap program

 fdi2rules.py:: convert hal keymap FDIs into udev rules and key map files
 (Please note that this is far from perfect, since the mapping between fdi and
  udev rules is not straightforward, and impossible in some cases.)

== Fixing broken keys ==

In order to make a broken key work on your system and send it back to upstream
for inclusion you need to do the following steps:

 1. Find the keyboard device.

 Run /lib/udev/findkeyboards. This should always give you an "AT
 keyboard" and possibly a "module". Some laptops (notably Thinkpads, Sonys, and
 Acers) have multimedia/function keys on a separate input device instead of the
 primary keyboard. The keyboard device should have a name like "input/event3".
 In the following commands, the name will be written as "input/eventX" (replace
 X with the appropriate number).

 2. Dump current mapping:

 sudo /lib/udev/keymap input/eventX > /tmp/orig-map.txt

 3. Find broken scan codes:

 sudo /lib/udev/keymap -i input/eventX

 Press all multimedia/function keys and check if the key name that gets printed
 out is plausible. If it is unknown or wrong, write down the scan code (looks
 like "0x1E") and the intended functionality of this key. Look in
 /usr/include/linux/input.h for an available KEY_XXXXX constant which most
 closely approximates this functionality and write it down as the new key code. 
 
 For example, you might press a key labeled "web browser" which currently
 produces "unknown". Note down this:

   0x1E www # Fn+F2 web browser

 Repeat that for all other keys. Write the resulting list into a file. Look at
 /lib/udev/keymaps/ for existing key map files and make sure that you use the
 same structure.

 If the key only ever works once and then your keyboard (or the entire desktop)
 gets stuck for a long time, then it is likely that the BIOS fails to send a
 corresponding "key release" event after the key press event. Please note down
 this case as well, as it can be worked around in
 /lib/udev/keymaps/95-keyboard-force-release.rules .

 4. Find out your system vendor and product:

 cat /sys/class/dmi/id/sys_vendor
 cat /sys/class/dmi/id/product_name

 5. Generate a device dump with "udevadm info --export-db > /tmp/udev-db.txt".

 6. Send the system vendor/product names, the key mapping from step 3,
 /tmp/orig-map.txt from step 2, and /tmp/udev-db.txt from step 5
 to the bug tracker, so that they can be included in the next release:

   https://bugs.launchpad.net/udev/+bugs

For local testing, copy your map file to /lib/udev/keymaps/ with an appropriate
name, and add an appropriate udev rule to /lib/udev/rules.d/95-keymap.rules:

  * If you selected an "AT keyboard", add the rule to the section after
  'LABEL="keyboard_vendorcheck"'.

  * If you selected a "module", add the rule to the top section where the
  "ThinkPad Extra Buttons" are.

== Author ==

keymap is written and maintained by Martin Pitt <martin.pitt@ubuntu.com>.
