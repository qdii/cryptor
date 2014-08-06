#include <utility>
#include <functional>
#include <string>
#include <iostream>

#include "cryptor.h"

static const char * private_key_without_password =
R"(-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAriDoH3gBbJo+SojeL5j+4yQumXgnjhrt5+FChBxOfvTcyczz
p5qlUNqLzQQcQ/a+XR5qUhaA4l97DgNseFNyoYHIxrB5t+BQw27Q+UuUYYaIwJqZ
6r2PVCnQF9WPqqWdzBN6+13IlreH2XX4qy47kuLI3lcPlP5qhYaDogpZCl7lN7Oe
Qj2FAPZ1nkV+PL4RYfWZbBymUz0C105ytT7PWgLAZVvag8kHiNXRYv4Ksc9SJ3AE
ZriZ1tzpJ6/ZkI3vfJZqCeclELQ8zGxb8CbfSd4mHoHCVY7t1h+BNM4zUxSjN8d7
bctYJwnfBtztRFN2uTotDJs6njsoxfmh4/SzAQIDAQABAoIBAAGTWKZYPqMN7jxc
aq5BkyTZAfbviGQXyElN1308iFVLv+evjBDbLF3D7HnpbJwM0oIjMVEW1Qm3VXS2
AThBgQsHEpsBo8hPJkvuZ8OptGkBf6FGhNgD6RUY38Inc4pWv0vGbVly6sq6VGda
Uuqxm2Zj2O9yGDj/6FTW97/ymgWm/FfKczg/zGtjdog67W8LvvtmAj5ynSuimOP8
mOINPjewIbcl7rKvxcMNrOXKsRWwVxTNXdMNMsXd1Figw022KTqdiazQ/DPIXU6M
f8H+U/gS5QZRIAF8i0r3cvq6ai26dX0OFtsoizqG4qlRNwtQ+wyRsilZKiKnFuMY
bt1pRBUCgYEA1TlAT/Ui4TBdgGmm0Rlj7JKJENnpDKIFE8bP6Vy8SwBmp5MiRofE
TMne4BBKLcFcslCJrFvjl7+v4B9a2de7hJYqtevrXjM91vwFhc6z0m27vv6MKStQ
3uKX8+0RGHQ3j53kAvLxFSuAqYQ+gf9IAuyG0gpMABRvj0/8HY3T7tMCgYEA0Q/O
0og9UbXh8y3yI94ztczWdIQERyEhQiGNRUnHCqO2QbZQ9Nm190Jx/8yew03xpPVb
fyWWfKqO8Kjg5np0w37porI0UmfLZ5QMC+GFMq0jOUXidsvkyoWOe4D8LII0L98k
sjihHBlGNrfFjEgOUQaoreB+8F07m/iofRCROlsCgYAPUUGRfOa4jqTo6K4XL1/C
SvSVxVG8mpcKyKl+9i6ApNK7DxLTRkWPzqC4L/NkPhPOq4J4Y1GCQT79NsNsCtdp
uu/uibgq2DuFCi3LYwIAB+oI2nhvLLFukZCg8VLdEtw68PjETXeMMcfYZaun4xLl
QuCcjijPiKhK/0/5P4sOCQKBgHsi7XXRqxRapdg/ArUfpqN5IAOG0qI2oEk8S+I4
v1TD8pCn2u0s4mHdsBmzovt0CFVZ8udj80xAhWq4facjD20qbmBWyDyVSBgc+i9x
SKv9kJamU+oW1A55NeAGrAFnO2fK7elPM43CUTnfairjMhOFcYrghMP8liSbBFqN
jIyrAoGAVGZQVZgicmSppbBuZYJPOuegPVYhncq3XtBZCtEGGlMtQpKgz+GRhyvT
Ar/HC7xnS5Gjfyjj6eGHsBAjTsE4t38qD4nxQXzBmAQQ1/7/iq3WNu63OV2q4GRh
wChOO0pcJPOZfWtvKiy7hbN09e0nt5blX1yqe6LdO7mACWli/Ss=
-----END RSA PRIVATE KEY-----)";

static const char * public_key_without_password = 
R"(ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuIOgfeAFsmj5KiN4vmP7jJC6ZeCeOGu3n4UKEHE5+9NzJzPOnmqVQ2ovNBBxD9r5dHmpSFoDiX3sOA2x4U3KhgcjGsHm34FDDbtD5S5RhhojAmpnqvY9UKdAX1Y+qpZ3ME3r7XciWt4fZdfirLjuS4sjeVw+U/mqFhoOiClkKXuU3s55CPYUA9nWeRX48vhFh9ZlsHKZTPQLXTnK1Ps9aAsBlW9qDyQeI1dFi/gqxz1IncARmuJnW3Oknr9mQje98lmoJ5yUQtDzMbFvwJt9J3iYegcJVju3WH4E0zjNTFKM3x3tty1gnCd8G3O1EU3a5Oi0MmzqeOyjF+aHj9LMB qdii@nomada)";

#define LAUNCH( X ) launch( X, #X )

static
bool launch( std::function< bool() > fnc, std::string name )
{
    bool succeeded = true;
    std::cout << name << ": ";
    try
    {
        succeeded = fnc();
    }
    catch( ... )
    {
        succeeded = false;
    }
    if ( succeeded )
        std::cout << "OK\n";
    else
        std::cout << "FAILED\n";

    return succeeded;
}

static
bool test01()
{
    cryptor c( private_key_without_password, public_key_without_password );
}

int main()
{
    LAUNCH( test01 );
}
