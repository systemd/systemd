# The Discoverable Partitions Specification

_TL;DR: Let's automatically discover, mount and enable the root partition, /home, /srv and the swap partitions based on GUID Partition Tables (GPT!)_ 

       +------------------------------------+-------------------------+---------------------------------------------------------+
       |Partition Type GUID                 | Name                    | Explanation                                             |
       +------------------------------------+-------------------------+---------------------------------------------------------+
       |44479540-f297-41b2-9af7d131d5f0458a | Root Partition (x86)    | On 32bit x86 systems the first x86 root partition on    |
       |                                    |                         | the disk the EFI ESP is located on is mounted to the    |
       |                                    |                         | root directory /.                                       |
       +------------------------------------+-------------------------+---------------------------------------------------------+
       |4f68bce3-e8cd-4db1-96e7fbcaf984b709 | Root Partition (x86-64) | On 64bit x86 systems the first x86-64 root partition on |
       |                                    |                         | the disk the EFI ESP is located on is mounted to the    |
       |                                    |                         | root directory /.                                       |
       +------------------------------------+-------------------------+---------------------------------------------------------+
       |933ac7e1-2eb4-4f13-b8440e14e2aef915 | Home Partition          | The first home partition on the disk the root partition |
       |                                    |                         | is located on is mounted to /home.                      |
       +------------------------------------+-------------------------+---------------------------------------------------------+
       |3b8f8425-20e0-4f3b-907f1a25a76f98e8 | Server Data Partition   | The first server data partition on the disk the root    |
       |                                    |                         | partition is located on is mounted to /srv.             |
       +------------------------------------+-------------------------+---------------------------------------------------------+
       |0657fd6d-a4ab-43c4-84e50933c84b4f4f | Swap                    | All swap partitions located on the disk the root        |
       |                                    |                         | partition is located on are enabled.                    |
       +------------------------------------+-------------------------+---------------------------------------------------------+
