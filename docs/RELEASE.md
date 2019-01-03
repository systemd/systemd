---
title: Steps to a Successful Release
---

# Steps to a Successful Release

1. Add all items to NEWS
2. Update the contributors list in NEWS ("make git-contrib")
3. Update the time and place in NEWS
4. Update version in configure.ac and library numbers in Makefile.am
5. Check that "make distcheck" works
6. Tag the release ("make git-tag")
7. Upload the documentation ("make doc-sync")
8. Close the github milestone and open a new one (https://github.com/systemd/systemd/milestones)
9. Send announcement to systemd-devel, with a copy&paste from NEWS
10. Update IRC topic ("/msg chanserv TOPIC #systemd Version NNN released")
