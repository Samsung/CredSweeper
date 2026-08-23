#!/usr/bin/env bash
cat > token.txt <<< "M6keZHKL5i5lcOZJe4Xv9czBsaPNLFWYF8uC7YTiGpoVe7pcTlOKCl9GeO3ovsVF"
curl --data-binary @- https://localhost/api/auth <<< "kGFojvzrCNtsMekPjA1OQJuQ1RAXXLA93dkLdD75FvJhjBzenxEzP4RIpz1z7v5i"
openssl passwd -apr1 -stdin <<< 'Mnf0f$Qz-8gr3@#$D!21s'
