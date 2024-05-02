FROM rockylinux:9.2
RUN rm -rf /etc/yum.repos.d/*.repo
COPY rocky.repo /etc/yum.repos.d/

COPY shim-unsigned-x64-15.8-1.el9.src.rpm shimx64.efi /
RUN dnf install dnf-plugins-core rpm-build -y; \
    dnf builddep shim-unsigned-x64-15.8-1.el9.src.rpm -y
RUN echo -e '%_topdir /builddir/build/\n%_tmp %{_topdir}/tmp' > /root/.rpmmacros
RUN rpm -ivh shim-unsigned-x64-15.8-1.el9.src.rpm
RUN rpmbuild -bb /builddir/build/SPECS/shim-unsigned-x64.spec
RUN rpm2cpio /builddir/build/RPMS/x86_64/shim-unsigned-x64-15.8-1.el9.x86_64.rpm | cpio -idmu

RUN objcopy -O binary --only-section=.sbat \
    /usr/share/shim/15.8-1.el9/x64/shimx64.efi /built-sbat.x64; cat /built-sbat.x64
RUN objcopy -O binary --only-section=.sbat \
    /shimx64.efi /orig-sbat.x64; cat /orig-sbat.x64
RUN hexdump -Cv /usr/share/shim/15.8-1.el9/x64/shimx64.efi > /built-x64; \
    hexdump -Cv shimx64.efi > /orig-x64

RUN diff -u /orig-x64 /built-x64
RUN pesign -h -P -i /usr/share/shim/15.8-1.el9/x64/shimx64.efi && \
    pesign -h -P -i shimx64.efi
RUN sha256sum /usr/share/shim/15.8-1.el9/x64/shimx64.efi && \
    sha256sum shimx64.efi 
