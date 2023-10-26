FROM rockylinux:8.6
RUN rm -rf /etc/yum.repos.d/*.repo
COPY rocky-86.repo /etc/yum.repos.d/

COPY shim-unsigned-x64-15.7-1.el8.src.rpm shimia32.efi shimx64.efi /
RUN dnf install dnf-plugins-core rpm-build -y; \
    dnf builddep shim-unsigned-x64-15.7-1.el8.src.rpm -y
RUN echo -e '%_topdir /builddir/build/\n%_tmp %{_topdir}/tmp' > /root/.rpmmacros
RUN rpm -ivh shim-unsigned-x64-15.7-1.el8.src.rpm
RUN sed -i 's/linux32 -B/linux32/g' /builddir/build/SPECS/shim-unsigned-x64.spec
RUN rpmbuild -bb /builddir/build/SPECS/shim-unsigned-x64.spec
RUN rpm2cpio /builddir/build/RPMS/x86_64/shim-unsigned-x64-15.7-1.el8.x86_64.rpm | cpio -idmu
RUN rpm2cpio /builddir/build/RPMS/x86_64/shim-unsigned-ia32-15.7-1.el8.x86_64.rpm | cpio -idmu

RUN objcopy -O binary --only-section=.sbat \
    /usr/share/shim/15.7-1.el8/x64/shimx64.efi sbat.ia32; cat sbat.ia32
RUN objcopy -O binary --only-section=.sbat \
    /usr/share/shim/15.7-1.el8/ia32/shimia32.efi sbat.x64; cat sbat.x64
RUN hexdump -Cv /usr/share/shim/15.7-1.el8/x64/shimx64.efi > built-x64; \
    hexdump -Cv shimx64.efi > orig-x64
RUN hexdump -Cv /usr/share/shim/15.7-1.el8/ia32/shimia32.efi > built-ia32; \
    hexdump -Cv shimia32.efi > orig-ia32
RUN diff -u orig-x64 built-x64
RUN diff -u orig-ia32 built-ia32
RUN pesign -h -P -i /usr/share/shim/15.7-1.el8/x64/shimx64.efi && \
    pesign -h -P -i shimx64.efi && \
    pesign -h -P -i /usr/share/shim/15.7-1.el8/ia32/shimia32.efi && \
    pesign -h -P -i shimia32.efi
RUN sha256sum /usr/share/shim/15.7-1.el8/x64/shimx64.efi && \
    sha256sum shimx64.efi && \
    sha256sum /usr/share/shim/15.7-1.el8/ia32/shimia32.efi && \
    sha256sum shimia32.efi
