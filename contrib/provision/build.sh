#!/bin/bash

cd /home/vagrant/enclave

export CLANG=/usr/bin/clang-12
cargo install --path .

sudo systemctl enable --now enclave.service
