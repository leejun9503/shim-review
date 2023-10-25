This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 on Linux, so asking
us to endorse anything else for signing is going to require some convincing on
your part.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
[NAVER Cloud Corp.](https://www.navercloudcorp.com/)

*******************************************************************************
### What product or service is this for?
*******************************************************************************
Navix 8

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
Navix is a linux operating system base on RHEL and compatible with other RHEL-like Linux.  
We developed Navix to use on our environment, but we are going to release Navix public in 2024.  

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
We build and provide our own kernel and bootloader that cannot be authenticated by other OS provider's shim.  
Therefore, we need our signed shim to fully integrate secure boot to our OS.  

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: JunYeong Lee
- Position: Linux Engineer
- Email address: jun-yeong.l@navercorp.com
- PGP key fingerprint: 61C0 B066 4E45 0C5A 1AA2 B76F 2B4D 506B 780C 8D62

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Hwaseop Keum
- Position: Linux Engineer
- Email address: dl_le@navercorp.com
- PGP key fingerprint: FA09 272D 4095 0167 B28C C751 590A 3486 7A19 5978

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Were these binaries created from the 15.7 shim release tar?
Please create your shim binaries starting with the 15.7 shim release tar file: https://github.com/rhboot/shim/releases/download/15.7/shim-15.7.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.7 and contains the appropriate gnu-efi source.

*******************************************************************************
Yes.

*******************************************************************************
### URL for a repo that contains the exact code which was built to get this binary:
*******************************************************************************

`shim-unsigned-x64-15.7-1.el8.src.rpm` includes the release tarball.
https://github.com/rhboot/shim/releases/download/15.7/shim-15.7.tar.bz2

*******************************************************************************
### What patches are being applied and why:
*******************************************************************************
[Enable the NX Compatibility flag by default](https://github.com/rhboot/shim/commit/7c7642530fab73facaf3eac233cfbce29e10b0ef)  
[Make sbat_var.S parse right with buggy gcc/binutils](https://github.com/rhboot/shim/pull/535/commits/4eaf28827e99e930aad742eadd79a716fe323bf3)  
[Microsoft](https://github.com/rhboot/shim-review/issues/307) requires to enable NX support, so we patched our shim 15.7 to enable NX compatibility flag.  
And we patched shim for binutils bug that fixes incorrect `.sbatlevel` section.

*******************************************************************************
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
*******************************************************************************
RHEL-like implementation.

*******************************************************************************
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of grub affected by any of the CVEs in the July 2020 grub2 CVE list, the March 2021 grub2 CVE list, the June 7th 2022 grub2 CVE list, or the November 15th 2022 list, have fixes for all these CVEs been applied?

* CVE-2020-14372
* CVE-2020-25632
* CVE-2020-25647
* CVE-2020-27749
* CVE-2020-27779
* CVE-2021-20225
* CVE-2021-20233
* CVE-2020-10713
* CVE-2020-14308
* CVE-2020-14309
* CVE-2020-14310
* CVE-2020-14311
* CVE-2020-15705
* CVE-2021-3418 (if you are shipping the shim_lock module)

* CVE-2021-3695
* CVE-2021-3696
* CVE-2021-3697
* CVE-2022-28733
* CVE-2022-28734
* CVE-2022-28735
* CVE-2022-28736
* CVE-2022-28737

* CVE-2022-2601
* CVE-2022-3775
*******************************************************************************
This is our first shim submission, so we only allow grub2 bootloader that does not affected by those CVEs.

*******************************************************************************
### If these fixes have been applied, have you set the global SBAT generation on your GRUB binary to 3?
*******************************************************************************
Yes. 

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
*******************************************************************************
This is our first shim submission, so we only allow grub2 bootloader that does not affected by those CVEs.

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
*******************************************************************************
Redhat's kernel already disables kgdb/kdb so we do not need to apply "lockdown: also lock down previous kgdb use" patch.  
Our kernel is based on RHEL and patches are identical until we release our custom kernel.

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
No. Kernel source is identical to RHEL.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We do not use vendor_db functionality.

*******************************************************************************
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
*******************************************************************************
This is our first shim submission.

*******************************************************************************
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
*******************************************************************************
`Dockerfile` is included to reproduce our build.

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
Please reference to `build.log`.

*******************************************************************************
### What changes were made since your SHIM was last signed?
*******************************************************************************
This is our first shim submission.

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************
```
dc5056c74e44aad36944d7f18c3b9c57900e104a727bf7b7f6aac52315352522  shimx64.efi
ab8407a1bb040c5f78459811415350daf4b4462e19349aa2c91f3cfe2c6cd8ac  shimia32.efi
```

*******************************************************************************
### How do you manage and protect the keys used in your SHIM?
*******************************************************************************
Our private key is stored on FIPS 140-2 Level 2 HSM that can be only accessible by 2 person listed above.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the SHIM?
*******************************************************************************
No.

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( grub2, fwupd, fwupdate, shim + all child shim binaries )?
### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
*******************************************************************************
Yes.

shim
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md  
shim,3,UEFI shim,shim,1,https://github.com/rhboot/shim  
shim.navix,1,Navix,shim,15.7,dl_le@navercorp.com  
```

grub2
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md  
grub,3,Free Software Foundation,grub,2.02,https//www.gnu.org/software/grub/  
grub.rh,2,Red Hat,grub2,2.02-148.el8,mailto:secalert@redhat.com  
grub.navix,1,Navix,grub2,2.02-148.el8,mailto:dl_le@navercorp.com  
```

fwupd
```
sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
fwupd-efi,1,Firmware update daemon,fwupd-efi,1.3,https://github.com/fwupd/fwupd-efi
fwupd-efi.navix,1,Navix,fwupd,1.7.8,dl_le@navercorp.com
```

*******************************************************************************
### Which modules are built into your signed grub image?
*******************************************************************************
```
all_video boot blscfg
cat configfile cryptodisk echo ext2
fat font gcry_rijndael gcry_rsa gcry_serpent
gcry_sha256 gcry_twofish gcry_whirlpool
gfxmenu gfxterm gzio halt http
increment iso9660 jpeg loadenv loopback linux
lvm luks mdraid09 mdraid1x minicmd net
normal part_apple part_msdos part_gpt
password_pbkdf2 png reboot regexp search
search_fs_uuid search_fs_file search_label
serial sleep syslinuxcfg test tftp video xfs
```

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB or other)?
*******************************************************************************
`grub2-2.02-148.el8` from RHEL

*******************************************************************************
### If your SHIM launches any other components, please provide further details on what is launched.
*******************************************************************************
It also launches fwupd.

*******************************************************************************
### If your GRUB2 launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
*******************************************************************************
GRUB2 can't launch unauthenticated code because SHIM also validates the code launched from grub.

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
*******************************************************************************
SHIM validates all loaded component(grub,kernel..) using our CA certificates.
grub2 bootloader also validates kernel through shim.
fwupd only loads UEFI firmware updates.

*******************************************************************************
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB)?
*******************************************************************************
No.

*******************************************************************************
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
*******************************************************************************
We are using downstream kernel from RHEL and all our kernel has certificate and suggested upstream commit applied.

*******************************************************************************
### Add any additional information you think we may need to validate this shim.
*******************************************************************************
N/A

