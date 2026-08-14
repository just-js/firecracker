#!/bin/sh
git diff v1.16.1..joos-fire -- . ':(exclude)gen-patch.sh' > ../joos/patches/firecracker-1.16.1.patch
