
wget -qO- https://binaries.cockroachdb.com/cockroach-v19.2.2.linux-amd64.tgz | tar xvz
cp -i cockroach-v19.2.2.linux-amd64/cockroach /usr/local/bin/
cockroach start --insecure